import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
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
import { useToast } from '@/hooks/use-toast';
import type { CreateScopeRequest } from '@/types/api';
import { mergeMetadata, parseMetadataText } from '@/lib/featureMetadata';

type ScopeNewFormState = {
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

export function ScopeNewPage() {
    const { productId, featureId } = useParams<{
        productId: string;
        featureId: string;
    }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const [formData, setFormData] = useState<ScopeNewFormState>({
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

    const createMutation = useMutation({
        mutationFn: () => {
            const payload: Omit<CreateScopeRequest, 'feature_id'> = {
                name: formData.name.trim(),
                slug: formData.slug.trim(),
                permission: formData.permission,
            };
            if (formData.permission === 'limit' && formData.limit) {
                payload.limit = Number(formData.limit);
            }
            const trimmedDescription = formData.description.trim();
            const metadata: Record<string, string> = {};
            if (trimmedDescription) {
                metadata.description = trimmedDescription;
            }
            if (formData.restrictionType) {
                metadata.restriction_type = formData.restrictionType;
            }
            if (formData.restrictionLimit !== '' && formData.restrictionLimit !== undefined) {
                metadata.restriction_limit = String(formData.restrictionLimit);
            }
            if (formData.restrictionWindow !== '' && formData.restrictionWindow !== undefined) {
                metadata.restriction_window_seconds = String(formData.restrictionWindow);
            }
            const mergedMetadata = mergeMetadata(
                parseMetadataText(formData.advancedMetadata),
                metadata,
                ['description', 'restriction_type', 'restriction_limit', 'restriction_window_seconds']
            );
            if (Object.keys(mergedMetadata).length > 0) {
                payload.metadata = mergedMetadata;
            }
            return api.createScope(productId!, featureId!, payload);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({
                queryKey: ['scopes', productId, featureId],
            });
            toast({ title: 'Scope created successfully' });
            navigate(`/products/${productId}/features/${featureId}`);
        },
        onError: (error) => {
            toast({
                title: 'Failed to create scope',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        createMutation.mutate();
    };

    const generateSlug = () => {
        const slug = formData.name
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '')
            .replace(/--+/g, '-');
        setFormData((prev) => ({ ...prev, slug }));
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">New Scope</h1>
                    <p className="text-muted-foreground">Create a new feature scope</p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Target className="h-5 w-5" />
                        Scope Details
                    </CardTitle>
                    <CardDescription>Configure the scope settings</CardDescription>
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
                                onBlur={() => !formData.slug && generateSlug()}
                                placeholder="Read Access"
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="slug">Slug *</Label>
                            <div className="flex gap-2">
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
                                <Button type="button" variant="outline" onClick={generateSlug}>
                                    Generate
                                </Button>
                            </div>
                            <p className="text-xs text-muted-foreground">
                                Unique identifier used for overrides
                            </p>
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
                                    value={formData.limit || ''}
                                    disabled={formData.permission !== 'limit'}
                                    onChange={(e) => {
                                        const value = e.target.value;
                                        setFormData((prev) => ({
                                            ...prev,
                                            limit: value,
                                        }));
                                    }}
                                    onBlur={(e) => {
                                        const value = e.target.value;
                                        if (formData.permission === 'limit' && (value === '' || isNaN(parseInt(value, 10)))) {
                                            setFormData((prev) => ({
                                                ...prev,
                                                limit: '0',
                                            }));
                                        }
                                    }}
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
                                    createMutation.isPending || !formData.name || !formData.slug
                                }
                            >
                                {createMutation.isPending ? 'Creating...' : 'Create Scope'}
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
