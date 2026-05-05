import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
    ArrowLeft,
    Package,
    Edit,
    Trash2,
    Plus,
    Layers,
    Puzzle,
    ArrowRight,
} from 'lucide-react';
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
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
    AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import type { Plan, Feature, PlanFeature } from '@/types/api';
import { formatCurrencyFromCents } from '@/lib/utils';

// Component to fetch and display plan features count
function PlanFeaturesCount({ productId, planId }: { productId: string; planId: string }) {
    const { data: response } = useQuery({
        queryKey: ['plan-features', productId, planId],
        queryFn: () => api.getPlanFeatures(productId, planId),
    });
    const count = response?.data?.length || 0;
    return <>{count} features included</>;
}

export function ProductDetailPage() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const { data: productResponse, isLoading: productLoading } = useQuery({
        queryKey: ['product', id],
        queryFn: () => api.getProduct(id!),
        enabled: !!id,
    });

    const { data: plansResponse, isLoading: plansLoading } = useQuery({
        queryKey: ['plans', id],
        queryFn: () => api.listPlans(id!),
        enabled: !!id,
    });

    const { data: featuresResponse, isLoading: featuresLoading } = useQuery({
        queryKey: ['features', id],
        queryFn: () => api.listFeatures(id!),
        enabled: !!id,
    });

    const deleteMutation = useMutation({
        mutationFn: () => api.deleteProduct(id!),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['products'] });
            toast({ title: 'Product deleted successfully' });
            navigate('/products');
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete product',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    if (productLoading) {
        return (
            <div className="space-y-6">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
            </div>
        );
    }

    const product = productResponse?.data;

    if (!product) {
        return (
            <div className="flex flex-col items-center justify-center py-12">
                <Package className="h-12 w-12 text-muted-foreground" />
                <h2 className="mt-4 text-lg font-semibold">Product not found</h2>
                <Button asChild className="mt-4">
                    <Link to="/products">Back to Products</Link>
                </Button>
            </div>
        );
    }

    const plans: Plan[] = plansResponse?.data || [];
    const features: Feature[] = featuresResponse?.data || [];

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div className="flex-1">
                    <h1 className="text-3xl font-bold tracking-tight">{product.name}</h1>
                    <p className="text-muted-foreground">
                        {product.description || 'No description'}
                    </p>
                </div>
                <div className="flex gap-2">
                    <Button asChild variant="outline">
                        <Link to={`/products/${id}/edit`}>
                            <Edit className="mr-2 h-4 w-4" />
                            Edit
                        </Link>
                    </Button>
                    <AlertDialog>
                        <AlertDialogTrigger asChild>
                            <Button variant="destructive">
                                <Trash2 className="mr-2 h-4 w-4" />
                                Delete
                            </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                            <AlertDialogHeader>
                                <AlertDialogTitle>Delete Product</AlertDialogTitle>
                                <AlertDialogDescription>
                                    This will permanently delete the product and all associated
                                    plans and features. This action cannot be undone.
                                </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                <AlertDialogAction
                                    onClick={() => deleteMutation.mutate()}
                                    className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                >
                                    Delete
                                </AlertDialogAction>
                            </AlertDialogFooter>
                        </AlertDialogContent>
                    </AlertDialog>
                </div>
            </div>

            <Tabs defaultValue="plans" className="space-y-4">
                <TabsList>
                    <TabsTrigger value="plans" className="gap-2">
                        <Layers className="h-4 w-4" />
                        Plans ({plans.length})
                    </TabsTrigger>
                    <TabsTrigger value="features" className="gap-2">
                        <Puzzle className="h-4 w-4" />
                        Features ({features.length})
                    </TabsTrigger>
                </TabsList>

                <TabsContent value="plans" className="space-y-4">
                    <div className="flex items-center justify-between">
                        <h2 className="text-xl font-semibold">Licensing Plans</h2>
                        <Button asChild>
                            <Link to={`/products/${id}/plans/new`}>
                                <Plus className="mr-2 h-4 w-4" />
                                New Plan
                            </Link>
                        </Button>
                    </div>

                    {plansLoading ? (
                        <div className="space-y-2">
                            {[...Array(3)].map((_, i) => (
                                <Skeleton key={i} className="h-24 w-full" />
                            ))}
                        </div>
                    ) : plans.length === 0 ? (
                        <Card>
                            <CardContent className="flex flex-col items-center justify-center py-8">
                                <Layers className="h-12 w-12 text-muted-foreground" />
                                <p className="mt-2 text-sm text-muted-foreground">
                                    No plans created yet
                                </p>
                                <Button asChild className="mt-4">
                                    <Link to={`/products/${id}/plans/new`}>Create Plan</Link>
                                </Button>
                            </CardContent>
                        </Card>
                    ) : (
                        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                            {plans.map((plan) => {
                                const priceCents = plan.price_per_device ?? plan.price ?? 0;
                                const priceBadge = priceCents > 0
                                    ? `${formatCurrencyFromCents(priceCents, plan.currency || 'USD')}/device`
                                    : null;

                                return (
                                    <Card key={plan.id}>
                                        <CardHeader>
                                            <div className="flex items-start justify-between">
                                                <CardTitle className="text-lg">{plan.name}</CardTitle>
                                                {priceBadge && (
                                                    <Badge variant="outline">{priceBadge}</Badge>
                                                )}
                                            </div>
                                            <CardDescription>
                                                {plan.description || 'No description'}
                                            </CardDescription>
                                        </CardHeader>
                                        <CardContent>
                                            <div className="text-sm text-muted-foreground">
                                                <PlanFeaturesCount productId={id!} planId={plan.id} />
                                            </div>
                                        </CardContent>
                                        <CardFooter>
                                            <Button asChild variant="outline" className="w-full">
                                                <Link to={`/products/${id}/plans/${plan.id}`}>
                                                    View Plan
                                                    <ArrowRight className="ml-2 h-4 w-4" />
                                                </Link>
                                            </Button>
                                        </CardFooter>
                                    </Card>
                                );
                            })}
                        </div>
                    )}
                </TabsContent>

                <TabsContent value="features" className="space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                        <h2 className="text-xl font-semibold">Product Features</h2>
                        <div className="flex flex-wrap gap-2">
                            <Button asChild variant="outline">
                                <Link to={`/products/${id}/features/manage`}>
                                    Manage Features & Scopes
                                </Link>
                            </Button>
                            <Button asChild>
                                <Link to={`/products/${id}/features/new`}>
                                    <Plus className="mr-2 h-4 w-4" />
                                    New Feature
                                </Link>
                            </Button>
                        </div>
                    </div>

                    {featuresLoading ? (
                        <div className="space-y-2">
                            {[...Array(3)].map((_, i) => (
                                <Skeleton key={i} className="h-12 w-full" />
                            ))}
                        </div>
                    ) : features.length === 0 ? (
                        <Card>
                            <CardContent className="flex flex-col items-center justify-center py-8">
                                <Puzzle className="h-12 w-12 text-muted-foreground" />
                                <p className="mt-2 text-sm text-muted-foreground">
                                    No features created yet
                                </p>
                                <Button asChild className="mt-4">
                                    <Link to={`/products/${id}/features/new`}>Create Feature</Link>
                                </Button>
                            </CardContent>
                        </Card>
                    ) : (
                        <div className="rounded-md border">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Name</TableHead>
                                        <TableHead>Slug</TableHead>
                                        <TableHead>Category</TableHead>
                                        <TableHead className="w-[100px]">Actions</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {features.map((feature) => (
                                        <TableRow key={feature.id}>
                                            <TableCell className="font-medium">
                                                {feature.name}
                                            </TableCell>
                                            <TableCell className="font-mono text-sm">
                                                {feature.slug}
                                            </TableCell>
                                            <TableCell>
                                                {feature.category ? (
                                                    <Badge variant="outline">{feature.category}</Badge>
                                                ) : (
                                                    <span className="text-muted-foreground">—</span>
                                                )}
                                            </TableCell>
                                            <TableCell>
                                                <Button asChild variant="ghost" size="sm">
                                                    <Link to={`/products/${id}/features/${feature.id}`}>
                                                        View
                                                    </Link>
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>
                    )}
                </TabsContent>
            </Tabs>
        </div>
    );
}
