import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Plus, Package, ArrowRight } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import {
    Card,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';

export function ProductsPage() {
    const { data: response, isLoading } = useQuery({
        queryKey: ['products'],
        queryFn: () => api.listProducts(),
    });

    const products = response?.data || [];

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Products</h1>
                    <p className="text-muted-foreground">
                        Manage your software products and their licensing plans
                    </p>
                </div>
                <Button asChild>
                    <Link to="/products/new">
                        <Plus className="mr-2 h-4 w-4" />
                        New Product
                    </Link>
                </Button>
            </div>

            {isLoading ? (
                <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
                    {[...Array(6)].map((_, i) => (
                        <Skeleton key={i} className="h-48 w-full" />
                    ))}
                </div>
            ) : products.length === 0 ? (
                <div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-12">
                    <Package className="h-12 w-12 text-muted-foreground" />
                    <h3 className="mt-4 text-lg font-semibold">No products found</h3>
                    <p className="mt-2 text-sm text-muted-foreground">
                        Get started by creating your first product
                    </p>
                    <Button asChild className="mt-4">
                        <Link to="/products/new">
                            <Plus className="mr-2 h-4 w-4" />
                            New Product
                        </Link>
                    </Button>
                </div>
            ) : (
                <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
                    {products.map((product) => (
                        <Card key={product.id} className="flex flex-col">
                            <CardHeader>
                                <div className="flex items-start justify-between">
                                    <div className="flex items-center gap-2">
                                        <Package className="h-5 w-5 text-primary" />
                                        <CardTitle className="text-lg">{product.name}</CardTitle>
                                    </div>
                                    <Badge variant="default">Active</Badge>
                                </div>
                                <CardDescription className="line-clamp-2">
                                    {product.description || 'No description provided'}
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="flex-1">
                                <div className="grid grid-cols-2 gap-4 text-sm">
                                    <div>
                                        <div className="text-muted-foreground">Slug</div>
                                        <div className="font-medium font-mono">{product.slug}</div>
                                    </div>
                                    <div>
                                        <div className="text-muted-foreground">Created</div>
                                        <div className="font-medium">
                                            {product.created_at ? new Date(product.created_at).toLocaleDateString() : '—'}
                                        </div>
                                    </div>
                                </div>
                            </CardContent>
                            <CardFooter>
                                <Button asChild variant="outline" className="w-full">
                                    <Link to={`/products/${product.id}`}>
                                        View Product
                                        <ArrowRight className="ml-2 h-4 w-4" />
                                    </Link>
                                </Button>
                            </CardFooter>
                        </Card>
                    ))}
                </div>
            )}
        </div>
    );
}
