import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
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
import { useToast } from '@/hooks/use-toast';
import type { CreateFeatureRequest } from '@/types/api';

export function FeatureNewPage() {
    const { productId } = useParams<{ productId: string }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const [formData, setFormData] = useState<Omit<CreateFeatureRequest, 'productId'>>({
        name: '',
        slug: '',
        description: '',
        category: '',
        type: 'boolean',
    });

    const createMutation = useMutation({
        mutationFn: (data: Omit<CreateFeatureRequest, 'productId'>) =>
            api.createFeature(productId!, data),
        onSuccess: (response) => {
            queryClient.invalidateQueries({ queryKey: ['features', productId] });
            toast({ title: 'Feature created successfully' });
            if (response.data?.id) {
                navigate(`/products/${productId}/features/${response.data.id}`);
            } else {
                navigate(`/products/${productId}`);
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to create feature',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        createMutation.mutate(formData);
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
                    <h1 className="text-3xl font-bold tracking-tight">New Feature</h1>
                    <p className="text-muted-foreground">Create a new product feature</p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Puzzle className="h-5 w-5" />
                        Feature Details
                    </CardTitle>
                    <CardDescription>Configure the feature settings</CardDescription>
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
                                placeholder="Advanced Analytics"
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
                                    placeholder="advanced-analytics"
                                    className="font-mono"
                                    required
                                />
                                <Button type="button" variant="outline" onClick={generateSlug}>
                                    Generate
                                </Button>
                            </div>
                            <p className="text-xs text-muted-foreground">
                                URL-friendly identifier shared with clients (CLI/GUI/API)
                            </p>
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
                                    <SelectItem value="boolean">
                                        Boolean (On/Off)
                                    </SelectItem>
                                    <SelectItem value="metered">
                                        Metered (Usage-based)
                                    </SelectItem>
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
                                    createMutation.isPending || !formData.name || !formData.slug
                                }
                            >
                                {createMutation.isPending ? 'Creating...' : 'Create Feature'}
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
