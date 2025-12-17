import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Package } from 'lucide-react';
import api from '@/services/api';
import { normalizeSlug } from '@/lib/utils';
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
import { useToast } from '@/hooks/use-toast';
import type { CreateProductRequest } from '@/types/api';

export function ProductNewPage() {
    const navigate = useNavigate();
    const { toast } = useToast();

    const [formData, setFormData] = useState<CreateProductRequest>({
        name: '',
        slug: '',
        description: '',
    });
    // track whether user edited slug manually; if false, slug will auto-update from name
    const [slugTouched, setSlugTouched] = useState(false);

    const createMutation = useMutation({
        mutationFn: (data: CreateProductRequest) => api.createProduct(data),
        onSuccess: (response) => {
            toast({ title: 'Product created successfully' });
            if (response.data?.id) {
                navigate(`/products/${response.data.id}`);
            } else {
                navigate('/products');
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to create product',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        // ensure slug exists (generate from name if not present)
        setFormData((prev) => ({
            ...prev,
            slug: prev.slug || normalizeSlug(prev.name),
        }));
        createMutation.mutate({ ...formData, slug: formData.slug || normalizeSlug(formData.name) });
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">New Product</h1>
                    <p className="text-muted-foreground">
                        Create a new software product
                    </p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Package className="h-5 w-5" />
                        Product Details
                    </CardTitle>
                    <CardDescription>
                        Enter the basic product information
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="name">Name *</Label>
                            <Input
                                id="name"
                                value={formData.name}
                                onChange={(e) => {
                                    const newName = e.target.value;
                                    setFormData((prev) => ({ ...prev, name: newName }));
                                    // Auto-update slug while user hasn't manually edited it
                                    setFormData((prev) => ({
                                        ...prev,
                                        slug: slugTouched ? prev.slug : normalizeSlug(newName),
                                    }));
                                }}
                                placeholder="My Awesome App"
                                required
                            />
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
                                placeholder="A brief description of your product..."
                                rows={4}
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="slug">Slug *</Label>
                            <Input
                                id="slug"
                                value={formData.slug}
                                onChange={(e) => {
                                    const normalized = normalizeSlug(e.target.value);
                                    setSlugTouched(true);
                                    setFormData((prev) => ({ ...prev, slug: normalized }));
                                }}
                                placeholder="product-slug"
                                required
                            />
                            <p className="text-sm text-muted-foreground">URL-friendly identifier (lowercase, dashes). Auto-generated from name unless edited.</p>
                        </div>

                        <div className="flex gap-4">
                            <Button
                                type="submit"
                                disabled={createMutation.isPending || !formData.name || !formData.slug}
                            >
                                {createMutation.isPending ? 'Creating...' : 'Create Product'}
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
