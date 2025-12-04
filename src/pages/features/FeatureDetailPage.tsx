import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
    ArrowLeft,
    Puzzle,
    Edit,
    Trash2,
    Plus,
    Target,
} from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import {
    Card,
    CardContent,
    CardDescription,
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
import { Label } from '@/components/ui/label';
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
import { useToast } from '@/hooks/use-toast';
import type { FeatureScope } from '@/types/api';

export function FeatureDetailPage() {
    const { productId, featureId } = useParams<{
        productId: string;
        featureId: string;
    }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const { data: featureResponse, isLoading: featureLoading } = useQuery({
        queryKey: ['feature', productId, featureId],
        queryFn: () => api.getFeature(productId!, featureId!),
        enabled: !!productId && !!featureId,
    });

    const { data: scopesResponse, isLoading: scopesLoading } = useQuery({
        queryKey: ['scopes', productId, featureId],
        queryFn: () => api.listScopes(productId!, featureId!),
        enabled: !!productId && !!featureId,
    });

    const deleteMutation = useMutation({
        mutationFn: () => api.deleteFeature(productId!, featureId!),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['features', productId] });
            toast({ title: 'Feature deleted successfully' });
            navigate(`/products/${productId}`);
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete feature',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const deleteScopeMutation = useMutation({
        mutationFn: (scopeId: string) =>
            api.deleteScope(productId!, featureId!, scopeId),
        onSuccess: () => {
            queryClient.invalidateQueries({
                queryKey: ['scopes', productId, featureId],
            });
            toast({ title: 'Scope deleted successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete scope',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    if (featureLoading) {
        return (
            <div className="space-y-6">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
            </div>
        );
    }

    const feature = featureResponse?.data;
    const scopes: FeatureScope[] = scopesResponse?.data || [];

    if (!feature) {
        return (
            <div className="flex flex-col items-center justify-center py-12">
                <Puzzle className="h-12 w-12 text-muted-foreground" />
                <h2 className="mt-4 text-lg font-semibold">Feature not found</h2>
                <Button asChild className="mt-4">
                    <Link to={`/products/${productId}`}>Back to Product</Link>
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
                <div className="flex-1">
                    <h1 className="text-3xl font-bold tracking-tight">{feature.name}</h1>
                    <p className="text-muted-foreground">
                        {feature.description || 'No description'}
                    </p>
                </div>
                <div className="flex gap-2">
                    <Button asChild variant="outline">
                        <Link to={`/products/${productId}/features/${featureId}/edit`}>
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
                                <AlertDialogTitle>Delete Feature</AlertDialogTitle>
                                <AlertDialogDescription>
                                    This will permanently delete the feature and all its scopes.
                                    Plans using this feature will no longer include it.
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

            <Card>
                <CardHeader>
                    <CardTitle>Feature Information</CardTitle>
                    <CardDescription>Basic feature details</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="grid gap-4 sm:grid-cols-4">
                        <div>
                            <Label className="text-muted-foreground">Slug</Label>
                            <p className="font-mono font-medium">{feature.slug}</p>
                        </div>
                        <div>
                            <Label className="text-muted-foreground">Category</Label>
                            <div className="mt-1">
                                <Badge variant="outline">{feature.category || 'uncategorized'}</Badge>
                            </div>
                        </div>
                        <div>
                            <Label className="text-muted-foreground">Created</Label>
                            <p className="font-medium">
                                {new Date(feature.created_at).toLocaleDateString()}
                            </p>
                        </div>
                        <div>
                            <Label className="text-muted-foreground">Updated</Label>
                            <p className="font-medium">
                                {new Date(feature.updated_at).toLocaleDateString()}
                            </p>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {feature.type === 'scoped' && (
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between">
                        <div>
                            <CardTitle>Scopes</CardTitle>
                            <CardDescription>
                                Sub-permissions for this feature
                            </CardDescription>
                        </div>
                        <Button asChild>
                            <Link
                                to={`/products/${productId}/features/${featureId}/scopes/new`}
                            >
                                <Plus className="mr-2 h-4 w-4" />
                                New Scope
                            </Link>
                        </Button>
                    </CardHeader>
                    <CardContent>
                        {scopesLoading ? (
                            <div className="space-y-2">
                                {[...Array(3)].map((_, i) => (
                                    <Skeleton key={i} className="h-12 w-full" />
                                ))}
                            </div>
                        ) : scopes.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-8 text-center">
                                <Target className="h-12 w-12 text-muted-foreground" />
                                <p className="mt-2 text-sm text-muted-foreground">
                                    No scopes created yet
                                </p>
                                <Button asChild className="mt-4">
                                    <Link
                                        to={`/products/${productId}/features/${featureId}/scopes/new`}
                                    >
                                        Create Scope
                                    </Link>
                                </Button>
                            </div>
                        ) : (
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Name</TableHead>
                                        <TableHead>Slug</TableHead>
                                        <TableHead>Permission</TableHead>
                                        <TableHead>Limit</TableHead>
                                        <TableHead>Description</TableHead>
                                        <TableHead className="w-[150px]">Actions</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {scopes.map((scope) => (
                                        <TableRow key={scope.id}>
                                            <TableCell className="font-medium">{scope.name}</TableCell>
                                            <TableCell className="font-mono text-sm">
                                                {scope.slug}
                                            </TableCell>
                                            <TableCell>
                                                <Badge variant="outline" className="uppercase tracking-tight">
                                                    {scope.permission}
                                                </Badge>
                                            </TableCell>
                                            <TableCell className="text-sm">
                                                {scope.permission === 'limit' && typeof scope.limit === 'number'
                                                    ? scope.limit
                                                    : '—'}
                                            </TableCell>
                                            <TableCell className="text-muted-foreground">
                                                {scope.metadata?.description || '—'}
                                            </TableCell>
                                            <TableCell>
                                                <div className="flex gap-2">
                                                    <Button asChild variant="ghost" size="sm">
                                                        <Link
                                                            to={`/products/${productId}/features/${featureId}/scopes/${scope.id}/edit`}
                                                        >
                                                            Edit
                                                        </Link>
                                                    </Button>
                                                    <AlertDialog>
                                                        <AlertDialogTrigger asChild>
                                                            <Button variant="ghost" size="icon">
                                                                <Trash2 className="h-4 w-4" />
                                                            </Button>
                                                        </AlertDialogTrigger>
                                                        <AlertDialogContent>
                                                            <AlertDialogHeader>
                                                                <AlertDialogTitle>Delete Scope</AlertDialogTitle>
                                                                <AlertDialogDescription>
                                                                    This will permanently delete the scope.
                                                                </AlertDialogDescription>
                                                            </AlertDialogHeader>
                                                            <AlertDialogFooter>
                                                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                                                <AlertDialogAction
                                                                    onClick={() =>
                                                                        deleteScopeMutation.mutate(scope.id)
                                                                    }
                                                                >
                                                                    Delete
                                                                </AlertDialogAction>
                                                            </AlertDialogFooter>
                                                        </AlertDialogContent>
                                                    </AlertDialog>
                                                </div>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        )}
                    </CardContent>
                </Card>
            )}
        </div>
    );
}
