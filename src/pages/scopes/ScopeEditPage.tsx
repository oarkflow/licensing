import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Target } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/hooks/use-toast';
import type { CreateScopeRequest, FeatureScope } from '@/types/api';
import { mergeMetadata, parseMetadataText, stringifyMetadata } from '@/lib/featureMetadata';

type ScopeEditFormState = {
    name: string;
    slug: string;
    permission: 'allow' | 'deny' | 'limit';
    limit: string;
    description: string;
    restrictionType: string;
    restrictionLimit: string;
    restrictionWindow: string;
    advancedMetadata: string;
};

export function ScopeEditPage() {
    const { productId, featureId, scopeId } = useParams<{
        productId: string;
        featureId: string;
        scopeId: string;
    }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const { data: scopesResponse, isLoading } = useQuery({
        queryKey: ['scopes', productId, featureId],
        queryFn: () => api.listScopes(productId!, featureId!),
        enabled: !!productId && !!featureId,
    });

    const scope = scopesResponse?.data?.find((s: FeatureScope) => s.id === scopeId);

    const [formData, setFormData] = useState<ScopeEditFormState>({
        name: '',
        slug: '',
        permission: 'allow',
        limit: '',
        description: '',
        restrictionType: '',
        restrictionLimit: '',
        restrictionWindow: '',
        advancedMetadata: '',
    });

    useEffect(() => {
        if (scope) {
            setFormData({
                name: scope.name,
                slug: scope.slug,
                permission: (scope.permission as 'allow' | 'deny' | 'limit') || 'allow',
                limit:
                    scope.permission === 'limit' && typeof scope.limit === 'number'
                        ? String(scope.limit)
                        : '',
                description: scope.metadata?.description || '',
                restrictionType: scope.metadata?.restriction_type || '',
                restrictionLimit: scope.metadata?.restriction_limit || '',
                restrictionWindow: scope.metadata?.restriction_window_seconds || '',
                advancedMetadata: stringifyMetadata(
                    Object.fromEntries(
                        Object.entries(scope.metadata || {}).filter(([key]) =>
                            !['description', 'restriction_type', 'restriction_limit', 'restriction_window_seconds'].includes(key)
                        )
                    )
                ),
            });
        }
    }, [scope]);

    const updateMutation = useMutation({
        mutationFn: () => {
            const payload: Partial<CreateScopeRequest> = {
                name: formData.name.trim(),
                slug: formData.slug.trim(),
                permission: formData.permission,
            };
            if (formData.permission === 'limit' && formData.limit) {
                payload.limit = Number(formData.limit);
            }
            // Determine if metadata has changed (description or restriction fields)
            const trimmedDescription = formData.description.trim();
            const origDescription = scope?.metadata?.description || '';
            const origRestrictionType = scope?.metadata?.restriction_type || '';
            const origRestrictionLimit = scope?.metadata?.restriction_limit || '';
            const origRestrictionWindow = scope?.metadata?.restriction_window_seconds || '';

            let metadataChanged = false;
            if (trimmedDescription !== origDescription) metadataChanged = true;
            if (formData.restrictionType !== origRestrictionType) metadataChanged = true;
            if (String(formData.restrictionLimit) !== origRestrictionLimit) metadataChanged = true;
            if (String(formData.restrictionWindow) !== origRestrictionWindow) metadataChanged = true;

            if (metadataChanged) {
                const newMetadata: Record<string, string> = {};
                if (trimmedDescription) newMetadata.description = trimmedDescription;
                if (formData.restrictionType) newMetadata.restriction_type = formData.restrictionType;
                if (formData.restrictionLimit !== '' && formData.restrictionLimit !== undefined) newMetadata.restriction_limit = String(formData.restrictionLimit);
                if (formData.restrictionWindow !== '' && formData.restrictionWindow !== undefined) newMetadata.restriction_window_seconds = String(formData.restrictionWindow);
                const merged = mergeMetadata(
                    parseMetadataText(formData.advancedMetadata),
                    newMetadata,
                    ['description', 'restriction_type', 'restriction_limit', 'restriction_window_seconds']
                );
                // If user cleared all metadata-related fields, newMetadata will be empty which signals clearing metadata
                payload.metadata = merged;
            }
            return api.updateScope(productId!, featureId!, scopeId!, payload);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({
                queryKey: ['scopes', productId, featureId],
            });
            toast({ title: 'Scope updated successfully' });
            navigate(`/products/${productId}/features/${featureId}`);
        },
        onError: (error) => {
            toast({
                title: 'Failed to update scope',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        updateMutation.mutate();
    };

    if (isLoading) {
        return (
            <div className="space-y-6">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
            </div>
        );
    }

    if (!scope) {
        return (
            <div className="flex flex-col items-center justify-center py-12">
                <Target className="h-12 w-12 text-muted-foreground" />
                <h2 className="mt-4 text-lg font-semibold">Scope not found</h2>
                <Button
                    className="mt-4"
                    onClick={() => navigate(`/products/${productId}/features/${featureId}`)}
                >
                    Back to Feature
                </Button>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Edit Scope</h1>
                    <p className="text-muted-foreground">Update scope information</p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Target className="h-5 w-5" />
                        Scope Details
                    </CardTitle>
                    <CardDescription>Modify the scope settings</CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="name">Name *</Label>
                            <Input
                                id="name"
                                value={formData.name}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, name: e.target.value }))
                                }
                                placeholder="Read Access"
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="slug">Slug *</Label>
                            <Input
                                id="slug"
                                value={formData.slug}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, slug: e.target.value }))
                                }
                                placeholder="read"
                                className="font-mono"
                                required
                            />
                        </div>

                        <div className="grid gap-4 sm:grid-cols-2">
                            <div className="space-y-2">
                                <Label htmlFor="permission">Permission</Label>
                                <Select
                                    value={formData.permission}
                                    onValueChange={(value: 'allow' | 'deny' | 'limit') =>
                                        setFormData((prev) => ({ ...prev, permission: value }))
                                    }
                                >
                                    <SelectTrigger id="permission">
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="allow">Allow</SelectItem>
                                        <SelectItem value="deny">Deny</SelectItem>
                                        <SelectItem value="limit">Limit</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="limit">Limit</Label>
                                <Input
                                    id="limit"
                                    type="number"
                                    min="0"
                                    value={formData.limit}
                                    disabled={formData.permission !== 'limit'}
                                    onChange={(e) =>
                                        setFormData((prev) => ({ ...prev, limit: e.target.value }))
                                    }
                                    placeholder={
                                        formData.permission === 'limit'
                                            ? 'Maximum allowed operations'
                                            : 'Set permission to "limit"'
                                    }
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="description">Description</Label>
                            <Textarea
                                id="description"
                                value={formData.description}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, description: e.target.value }))
                                }
                                placeholder="What this scope allows..."
                                rows={3}
                            />
                        </div>

                        <div className="grid gap-4 sm:grid-cols-3">
                            <div className="space-y-2">
                                <Label htmlFor="restriction_type">Restriction Type</Label>
                                <Select
                                    value={formData.restrictionType}
                                    onValueChange={(value) =>
                                        setFormData((prev) => ({ ...prev, restrictionType: value }))
                                    }
                                >
                                    <SelectTrigger id="restriction_type">
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="">None</SelectItem>
                                        <SelectItem value="storage">Storage</SelectItem>
                                        <SelectItem value="user">User</SelectItem>
                                        <SelectItem value="device">Device</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="restriction_limit">Restriction Limit</Label>
                                <Input
                                    id="restriction_limit"
                                    type="number"
                                    min={0}
                                    value={formData.restrictionLimit}
                                    onChange={(e) =>
                                        setFormData((prev) => ({ ...prev, restrictionLimit: e.target.value }))
                                    }
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="restriction_window">Window (seconds)</Label>
                                <Input
                                    id="restriction_window"
                                    type="number"
                                    min={0}
                                    value={formData.restrictionWindow}
                                    onChange={(e) =>
                                        setFormData((prev) => ({ ...prev, restrictionWindow: e.target.value }))
                                    }
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="advanced_metadata">Advanced Metadata</Label>
                            <Textarea
                                id="advanced_metadata"
                                value={formData.advancedMetadata}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, advancedMetadata: e.target.value }))
                                }
                                placeholder={`flag:beta=true\nsetting:format=json\nlimit:rows=5000\nusage:exports:limit=25`}
                                rows={5}
                                className="font-mono text-xs"
                            />
                            <p className="text-xs text-muted-foreground">
                                Optional extra `key=value` lines for flags, settings, custom limits, and usage grants.
                            </p>
                        </div>

                        <div className="flex gap-4">
                            <Button
                                type="submit"
                                disabled={
                                    updateMutation.isPending || !formData.name || !formData.slug
                                }
                            >
                                {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
                            </Button>
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => navigate(-1)}
                            >
                                Cancel
                            </Button>
                        </div>
                    </form>
                </CardContent>
            </Card>
        </div>
    );
}
