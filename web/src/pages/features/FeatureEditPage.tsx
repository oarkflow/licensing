import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Puzzle } from 'lucide-react';
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
import type { CreateFeatureRequest } from '@/types/api';

export function FeatureEditPage() {
    const { productId, featureId } = useParams<{
        productId: string;
        featureId: string;
    }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const { data: featureResponse, isLoading } = useQuery({
        queryKey: ['feature', productId, featureId],
        queryFn: () => api.getFeature(productId!, featureId!),
        enabled: !!productId && !!featureId,
    });

    const [formData, setFormData] = useState<Partial<CreateFeatureRequest>>({
        name: '',
        slug: '',
        description: '',
        category: '',
        type: 'boolean',
    });

    useEffect(() => {
        if (featureResponse?.data) {
            setFormData({
                name: featureResponse.data.name,
                slug: featureResponse.data.slug,
                description: featureResponse.data.description || '',
                category: featureResponse.data.category || '',
                type: featureResponse.data.type || 'boolean',
            });
        }
    }, [featureResponse?.data]);

    const updateMutation = useMutation({
        mutationFn: (data: Partial<CreateFeatureRequest>) =>
            api.updateFeature(productId!, featureId!, data),
        onSuccess: () => {
            queryClient.invalidateQueries({
                queryKey: ['feature', productId, featureId],
            });
            queryClient.invalidateQueries({ queryKey: ['features', productId] });
            toast({ title: 'Feature updated successfully' });
            navigate(`/products/${productId}/features/${featureId}`);
        },
        onError: (error) => {
            toast({
                title: 'Failed to update feature',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        updateMutation.mutate(formData);
    };

    if (isLoading) {
        return (
            <div className="space-y-6">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
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
                    <h1 className="text-3xl font-bold tracking-tight">Edit Feature</h1>
                    <p className="text-muted-foreground">Update feature information</p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Puzzle className="h-5 w-5" />
                        Feature Details
                    </CardTitle>
                    <CardDescription>Modify the feature settings</CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="name">Name *</Label>
                            <Input
                                id="name"
                                value={formData.name || ''}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, name: e.target.value }))
                                }
                                placeholder="Advanced Analytics"
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="slug">Slug *</Label>
                            <Input
                                id="slug"
                                value={formData.slug || ''}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, slug: e.target.value }))
                                }
                                placeholder="advanced-analytics"
                                className="font-mono"
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="category">Category</Label>
                            <Input
                                id="category"
                                value={formData.category || ''}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, category: e.target.value }))
                                }
                                placeholder="e.g., billing, sync, integrations"
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="type">Type *</Label>
                            <Select
                                value={formData.type}
                                onValueChange={(value: 'boolean' | 'metered' | 'scoped') =>
                                    setFormData((prev) => ({ ...prev, type: value }))
                                }
                            >
                                <SelectTrigger id="type">
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="boolean">Boolean (On/Off)</SelectItem>
                                    <SelectItem value="metered">Metered (Usage-based)</SelectItem>
                                    <SelectItem value="scoped">
                                        Scoped (With sub-permissions)
                                    </SelectItem>
                                </SelectContent>
                            </Select>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="description">Description</Label>
                            <Textarea
                                id="description"
                                value={formData.description || ''}
                                onChange={(e) =>
                                    setFormData((prev) => ({
                                        ...prev,
                                        description: e.target.value,
                                    }))
                                }
                                placeholder="What this feature enables..."
                                rows={3}
                            />
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
