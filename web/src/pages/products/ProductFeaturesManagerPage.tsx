import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
    AlertTriangle,
    ArrowLeft,
    Edit,
    Filter,
    Layers,
    Loader2,
    Plus,
    Puzzle,
    Settings2,
    Target,
    Trash2,
} from 'lucide-react';
import api from '@/services/api';
import type { Feature, FeatureScope, CreateFeatureRequest, CreateScopeRequest } from '@/types/api';
import { Button } from '@/components/ui/button';
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from '@/components/ui/dialog';
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
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

const suggestedCategories = ['cli', 'gui', 'api'];

const slugify = (value: string) =>
    value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .replace(/--+/g, '-');

type FeatureFormState = Omit<CreateFeatureRequest, 'product_id'>;
interface ScopeFormState {
    name: string;
    slug: string;
    permission: 'allow' | 'deny' | 'limit';
    limit?: number | string;
    description?: string;
    restrictionType?: string;
    restrictionLimit?: number | string;
    restrictionWindow?: number | string;
}

const defaultFeatureForm: FeatureFormState = {
    name: '',
    slug: '',
    description: '',
    category: '',
    type: 'boolean',
};

const defaultScopeForm: ScopeFormState = {
    name: '',
    slug: '',
    permission: 'allow',
    limit: '',
    description: '',
    restrictionType: 'none',
    restrictionLimit: '',
    restrictionWindow: '',
};

export function ProductFeaturesManagerPage() {
    const { productId } = useParams<{ productId: string }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const [categoryFilter, setCategoryFilter] = useState('all');
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedFeatureId, setSelectedFeatureId] = useState<string | null>(null);
    const [featureDialogOpen, setFeatureDialogOpen] = useState(false);
    const [scopeDialogOpen, setScopeDialogOpen] = useState(false);
    const [scopeSearchTerm, setScopeSearchTerm] = useState('');
    const [scopePermissionFilter, setScopePermissionFilter] = useState<'all' | 'allow' | 'deny' | 'limit'>('all');
    const [featureForm, setFeatureForm] = useState<FeatureFormState>(defaultFeatureForm);
    const [scopeForm, setScopeForm] = useState<ScopeFormState>(defaultScopeForm);
    const [editingScopeId, setEditingScopeId] = useState<string | null>(null);
    const [showAddScopeForm, setShowAddScopeForm] = useState(false);

    const { data: productResponse, isLoading: productLoading } = useQuery({
        queryKey: ['product', productId],
        queryFn: () => api.getProduct(productId!),
        enabled: !!productId,
    });

    const { data: featuresResponse, isLoading: featuresLoading } = useQuery({
        queryKey: ['features', productId],
        queryFn: () => api.listFeatures(productId!),
        enabled: !!productId,
    });

    const { data: scopesResponse, isLoading: scopesLoading } = useQuery({
        queryKey: ['scopes', productId, selectedFeatureId],
        queryFn: () => api.listScopes(productId!, selectedFeatureId!),
        enabled: !!productId && !!selectedFeatureId,
    });

    const product = productResponse?.data;
    const features: Feature[] = featuresResponse?.data || [];
    const scopes: FeatureScope[] = scopesResponse?.data || [];

    const normalizedSearch = searchTerm.trim().toLowerCase();

    const categoryOptions = useMemo(() => {
        const set = new Set<string>(['all', ...suggestedCategories]);
        const hasUncategorized = features.some((feature) => !feature.category);
        if (hasUncategorized) {
            set.add('uncategorized');
        }
        features.forEach((feature) => {
            if (feature.category) {
                set.add(feature.category.trim().toLowerCase());
            }
        });
        return Array.from(set);
    }, [features]);

    const filteredFeatures = useMemo(() => {
        return features.filter((feature) => {
            const normalizedCategory = feature.category
                ? feature.category.trim().toLowerCase()
                : 'uncategorized';
            const matchesCategory =
                categoryFilter === 'all' || normalizedCategory === categoryFilter;
            const matchesSearch =
                !normalizedSearch ||
                feature.name.toLowerCase().includes(normalizedSearch) ||
                feature.slug.toLowerCase().includes(normalizedSearch) ||
                (feature.description?.toLowerCase().includes(normalizedSearch) ?? false);
            return matchesCategory && matchesSearch;
        });
    }, [features, categoryFilter, normalizedSearch]);

    useEffect(() => {
        if (!filteredFeatures.length) {
            setSelectedFeatureId(null);
            return;
        }
        if (!selectedFeatureId || !filteredFeatures.some((feature) => feature.id === selectedFeatureId)) {
            setSelectedFeatureId(filteredFeatures[0].id);
        }
    }, [filteredFeatures, selectedFeatureId]);

    useEffect(() => {
        if (!featureDialogOpen) {
            setFeatureForm(defaultFeatureForm);
        }
    }, [featureDialogOpen]);

    useEffect(() => {
        if (!scopeDialogOpen) {
            setScopeForm(defaultScopeForm);
        }
    }, [scopeDialogOpen]);

    useEffect(() => {
        // Reset scope form when toggling add scope form
        if (!showAddScopeForm) {
            setScopeForm(defaultScopeForm);
        }
    }, [showAddScopeForm]);

    useEffect(() => {
        // Reset scope filters when changing features
        setScopeSearchTerm('');
        setScopePermissionFilter('all');
        setShowAddScopeForm(false);
        setEditingScopeId(null);
    }, [selectedFeatureId]);

    const selectedFeature = features.find((feature) => feature.id === selectedFeatureId) || null;

    const filteredScopes = useMemo(() => {
        const normalizedScopeSearch = scopeSearchTerm.trim().toLowerCase();
        return scopes.filter((scope) => {
            const matchesSearch =
                !normalizedScopeSearch ||
                scope.name.toLowerCase().includes(normalizedScopeSearch) ||
                scope.slug.toLowerCase().includes(normalizedScopeSearch) ||
                (scope.metadata?.description?.toLowerCase().includes(normalizedScopeSearch) ?? false);
            const matchesPermission =
                scopePermissionFilter === 'all' || scope.permission === scopePermissionFilter;
            return matchesSearch && matchesPermission;
        });
    }, [scopes, scopeSearchTerm, scopePermissionFilter]);

    const createFeatureMutation = useMutation({
        mutationFn: (payload: FeatureFormState) =>
            api.createFeature(productId!, {
                name: payload.name.trim(),
                slug: payload.slug.trim(),
                description: payload.description?.trim(),
                category: payload.category?.trim(),
                type: payload.type || 'boolean',
            } as any),
        onSuccess: (response) => {
            if (!response.success) {
                toast({
                    title: 'Failed to create feature',
                    description: response.error || 'Unknown error',
                    variant: 'destructive',
                });
                return;
            }
            queryClient.invalidateQueries({ queryKey: ['features', productId] });
            toast({ title: 'Feature created successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to create feature',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const createScopeMutation = useMutation({
        mutationFn: (payload: ScopeFormState) => {
            const scopePayload: any = {
                name: payload.name.trim(),
                slug: payload.slug.trim(),
                permission: payload.permission,
            };
            if (payload.permission === 'limit' && payload.limit !== undefined && payload.limit !== '') {
                scopePayload.limit = Number(payload.limit);
            }
            const description = (payload.description || '').trim();
            const metadata: Record<string, string> = {};
            if (description) metadata.description = description;
            if (payload.restrictionType && payload.restrictionType !== 'none') metadata.restriction_type = payload.restrictionType;
            if (payload.restrictionLimit !== undefined && payload.restrictionLimit !== '') metadata.restriction_limit = String(payload.restrictionLimit);
            if (payload.restrictionWindow !== undefined && payload.restrictionWindow !== '') metadata.restriction_window_seconds = String(payload.restrictionWindow);
            if (Object.keys(metadata).length > 0) scopePayload.metadata = metadata;
            return api.createScope(productId!, selectedFeatureId!, scopePayload);
        },
        onSuccess: (response) => {
            if (!response.success) {
                toast({
                    title: 'Failed to create scope',
                    description: response.error || 'Unknown error',
                    variant: 'destructive',
                });
                return;
            }
            queryClient.invalidateQueries({ queryKey: ['scopes', productId, selectedFeatureId] });
            toast({ title: 'Scope created successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to create scope',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const deleteFeatureMutation = useMutation({
        mutationFn: (featureId: string) => api.deleteFeature(productId!, featureId),
        onSuccess: (response, featureId) => {
            if (!response.success) {
                toast({
                    title: 'Failed to delete feature',
                    description: response.error || 'Unknown error',
                    variant: 'destructive',
                });
                return;
            }
            if (selectedFeatureId === featureId) {
                setSelectedFeatureId(null);
            }
            queryClient.invalidateQueries({ queryKey: ['features', productId] });
            toast({ title: 'Feature deleted' });
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
        mutationFn: (scopeId: string) => api.deleteScope(productId!, selectedFeatureId!, scopeId),
        onSuccess: (response) => {
            if (!response.success) {
                toast({
                    title: 'Failed to delete scope',
                    description: response.error || 'Unknown error',
                    variant: 'destructive',
                });
                return;
            }
            queryClient.invalidateQueries({ queryKey: ['scopes', productId, selectedFeatureId] });
            toast({ title: 'Scope deleted' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete scope',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const updateScopeMutation = useMutation({
        mutationFn: (payload: { scopeId: string; data: ScopeFormState }) => {
            const scopePayload: any = {
                name: payload.data.name.trim(),
                slug: payload.data.slug.trim(),
                permission: payload.data.permission,
            };
            if (payload.data.permission === 'limit' && payload.data.limit !== undefined && payload.data.limit !== '') {
                scopePayload.limit = Number(payload.data.limit);
            }
            const description = (payload.data.description || '').trim();
            const metadata: Record<string, string> = {};
            if (description) metadata.description = description;
            if (payload.data.restrictionType && payload.data.restrictionType !== 'none') metadata.restriction_type = payload.data.restrictionType;
            if (payload.data.restrictionLimit !== undefined && payload.data.restrictionLimit !== '') metadata.restriction_limit = String(payload.data.restrictionLimit);
            if (payload.data.restrictionWindow !== undefined && payload.data.restrictionWindow !== '') metadata.restriction_window_seconds = String(payload.data.restrictionWindow);
            if (Object.keys(metadata).length > 0) scopePayload.metadata = metadata;
            return api.updateScope(productId!, selectedFeatureId!, payload.scopeId, scopePayload);
        },
        onSuccess: (response) => {
            if (!response.success) {
                toast({
                    title: 'Failed to update scope',
                    description: response.error || 'Unknown error',
                    variant: 'destructive',
                });
                return;
            }
            queryClient.invalidateQueries({ queryKey: ['scopes', productId, selectedFeatureId] });
            toast({ title: 'Scope updated successfully' });
            setEditingScopeId(null);
        },
        onError: (error) => {
            toast({
                title: 'Failed to update scope',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleCreateFeature = async (event: React.FormEvent) => {
        event.preventDefault();
        if (!productId) return;
        const response = await createFeatureMutation.mutateAsync(featureForm);
        if (response.success && response.data?.id) {
            setFeatureDialogOpen(false);
            setCategoryFilter('all');
            setSelectedFeatureId(response.data.id);
        }
    };

    const handleCreateScope = async (event: React.FormEvent) => {
        event.preventDefault();
        if (!productId || !selectedFeatureId) return;
        const response = await createScopeMutation.mutateAsync(scopeForm);
        if (response.success) {
            setScopeDialogOpen(false);
            setShowAddScopeForm(false);
        }
    };

    const handleUpdateScope = async (event: React.FormEvent, scopeId: string) => {
        event.preventDefault();
        if (!productId || !selectedFeatureId) return;
        const response = await updateScopeMutation.mutateAsync({ scopeId, data: scopeForm });
        if (response.success) {
            setEditingScopeId(null);
        }
    };

    const handleDeleteFeature = (featureId: string) => {
        deleteFeatureMutation.mutate(featureId);
    };

    const handleDeleteScope = (scopeId: string) => {
        deleteScopeMutation.mutate(scopeId);
    };

    const categoryLabel = (value: string) => {
        if (value === 'all') return 'All';
        if (value === 'uncategorized') return 'Uncategorized';
        return value.toUpperCase();
    };

    if (productLoading) {
        return (
            <div className="space-y-4">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
            </div>
        );
    }

    if (!product) {
        return (
            <div className="flex flex-col items-center justify-center space-y-4 py-12">
                <AlertTriangle className="h-10 w-10 text-muted-foreground" />
                <p className="text-muted-foreground">Product not found</p>
                <Button variant="outline" onClick={() => navigate('/products')}>
                    Back to Products
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
                    <h1 className="text-3xl font-bold tracking-tight">Manage Features & Scopes</h1>
                    <p className="text-muted-foreground">Define CLI/GUI/API access for {product.name}</p>
                </div>
                <div className="flex gap-2">
                    <Button variant="outline" asChild>
                        <Link to={`/products/${productId}`}>
                            <Layers className="mr-2 h-4 w-4" />
                            Product Overview
                        </Link>
                    </Button>
                    <Dialog open={featureDialogOpen} onOpenChange={setFeatureDialogOpen}>
                        <DialogTrigger asChild>
                            <Button>
                                <Plus className="mr-2 h-4 w-4" />
                                New Feature
                            </Button>
                        </DialogTrigger>
                        <DialogContent>
                            <DialogHeader>
                                <DialogTitle>Create Feature</DialogTitle>
                                <DialogDescription>
                                    Add a new feature to this product.
                                </DialogDescription>
                            </DialogHeader>
                            <form onSubmit={handleCreateFeature} className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="feature-name">Name *</Label>
                                    <Input
                                        id="feature-name"
                                        value={featureForm.name}
                                        onChange={(e) =>
                                            setFeatureForm((prev) => ({ ...prev, name: e.target.value }))
                                        }
                                        onBlur={() =>
                                            !featureForm.slug &&
                                            setFeatureForm((prev) => ({ ...prev, slug: slugify(prev.name) }))
                                        }
                                        placeholder="Command line interface"
                                        required
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="feature-slug">Slug *</Label>
                                    <div className="flex gap-2">
                                        <Input
                                            id="feature-slug"
                                            value={featureForm.slug}
                                            onChange={(e) =>
                                                setFeatureForm((prev) => ({ ...prev, slug: e.target.value }))
                                            }
                                            placeholder="cli"
                                            className="font-mono"
                                            required
                                        />
                                        <Button
                                            type="button"
                                            variant="outline"
                                            onClick={() =>
                                                setFeatureForm((prev) => ({ ...prev, slug: slugify(prev.name) }))
                                            }
                                        >
                                            Auto
                                        </Button>
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="feature-category">Category</Label>
                                    <Input
                                        id="feature-category"
                                        value={featureForm.category ?? ''}
                                        onChange={(e) =>
                                            setFeatureForm((prev) => ({ ...prev, category: e.target.value }))
                                        }
                                        placeholder="e.g., billing, sync, integrations"
                                    />
                                    <div className="flex flex-wrap gap-2">
                                        {suggestedCategories.map((category) => (
                                            <Button
                                                key={category}
                                                type="button"
                                                size="sm"
                                                variant={
                                                    featureForm.category?.toLowerCase() === category
                                                        ? 'default'
                                                        : 'outline'
                                                }
                                                onClick={() =>
                                                    setFeatureForm((prev) => ({ ...prev, category }))
                                                }
                                            >
                                                {category.toUpperCase()}
                                            </Button>
                                        ))}
                                    </div>
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="feature-type">Type *</Label>
                                    <Select
                                        value={featureForm.type}
                                        onValueChange={(value: 'boolean' | 'metered' | 'scoped') =>
                                            setFeatureForm((prev) => ({ ...prev, type: value }))
                                        }
                                    >
                                        <SelectTrigger id="feature-type">
                                            <SelectValue />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="boolean">Boolean (On/Off)</SelectItem>
                                            <SelectItem value="metered">Metered (Usage-based)</SelectItem>
                                            <SelectItem value="scoped">Scoped (With sub-permissions)</SelectItem>
                                        </SelectContent>
                                    </Select>
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="feature-description">Description</Label>
                                    <Textarea
                                        id="feature-description"
                                        value={featureForm.description ?? ''}
                                        onChange={(e) =>
                                            setFeatureForm((prev) => ({ ...prev, description: e.target.value }))
                                        }
                                        placeholder="Short summary for teammates"
                                        rows={3}
                                    />
                                </div>
                                <DialogFooter>
                                    <Button
                                        type="submit"
                                        disabled={
                                            createFeatureMutation.isPending ||
                                            !featureForm.name.trim() ||
                                            !featureForm.slug.trim()
                                        }
                                    >
                                        {createFeatureMutation.isPending ? (
                                            <>
                                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                                Creating...
                                            </>
                                        ) : (
                                            'Create Feature'
                                        )}
                                    </Button>
                                </DialogFooter>
                            </form>
                        </DialogContent>
                    </Dialog>
                </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-[320px_1fr] h-[calc(100vh-200px)]">
                <div className="overflow-y-auto">
                    <div className="sticky top-0 z-10">
                        <Card className="h-fit">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Settings2 className="h-4 w-4" /> Feature Catalog
                                </CardTitle>
                                <CardDescription>Filter by CLI, GUI, API, or custom scopes</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="feature-search" className="text-xs uppercase text-muted-foreground">
                                        Search
                                    </Label>
                                    <div className="flex items-center gap-2">
                                        <Filter className="h-4 w-4 text-muted-foreground" />
                                        <Input
                                            id="feature-search"
                                            placeholder="Find feature..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                        />
                                    </div>
                                </div>
                                <div className="flex flex-wrap gap-2">
                                    {categoryOptions.map((category) => (
                                        <Button
                                            key={category}
                                            size="sm"
                                            variant={categoryFilter === category ? 'default' : 'outline'}
                                            onClick={() => setCategoryFilter(category)}
                                        >
                                            {categoryLabel(category)}
                                        </Button>
                                    ))}
                                </div>
                                <Separator />
                                {featuresLoading ? (
                                    <div className="space-y-2">
                                        {[...Array(4)].map((_, index) => (
                                            <Skeleton key={index} className="h-12 w-full" />
                                        ))}
                                    </div>
                                ) : filteredFeatures.length === 0 ? (
                                    <div className="text-center text-sm text-muted-foreground">
                                        No features match your filters
                                    </div>
                                ) : (
                                    <div className="space-y-2">
                                        {filteredFeatures.map((feature) => (
                                            <button
                                                key={feature.id}
                                                className={cn(
                                                    'w-full rounded-md border px-4 py-3 text-left transition hover:bg-muted',
                                                    selectedFeatureId === feature.id
                                                        ? 'border-primary bg-primary/5'
                                                        : 'border-muted'
                                                )}
                                                onClick={() => setSelectedFeatureId(feature.id)}
                                            >
                                                <div className="flex items-center justify-between">
                                                    <div>
                                                        <p className="font-medium">{feature.name}</p>
                                                        <p className="font-mono text-xs text-muted-foreground">
                                                            {feature.slug}
                                                        </p>
                                                    </div>
                                                    <Badge variant="outline">
                                                        {(feature.category || 'uncategorized').toUpperCase()}
                                                    </Badge>
                                                </div>
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </CardContent>
                        </Card>
                    </div>
                </div>

                <div className="overflow-y-auto">
                    <Card>
                        <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                                <CardTitle className="flex items-center gap-2">
                                    <Puzzle className="h-5 w-5" />
                                    {selectedFeature ? selectedFeature.name : 'Select a feature'}
                                </CardTitle>
                                <CardDescription>
                                    {selectedFeature
                                        ? selectedFeature.description || 'No description provided'
                                        : 'Choose a feature to manage scopes'}
                                </CardDescription>
                            </div>
                            {selectedFeature && (
                                <div className="flex flex-wrap gap-2">
                                    <Button asChild variant="outline" size="sm">
                                        <Link to={`/products/${productId}/features/${selectedFeature.id}`}>
                                            View Details
                                        </Link>
                                    </Button>
                                    <Button asChild variant="outline" size="sm">
                                        <Link to={`/products/${productId}/features/${selectedFeature.id}/edit`}>
                                            <Edit className="mr-2 h-4 w-4" />
                                            Edit
                                        </Link>
                                    </Button>
                                    <AlertDialog>
                                        <AlertDialogTrigger asChild>
                                            <Button variant="destructive" size="sm">
                                                <Trash2 className="mr-2 h-4 w-4" />
                                                Delete
                                            </Button>
                                        </AlertDialogTrigger>
                                        <AlertDialogContent>
                                            <AlertDialogHeader>
                                                <AlertDialogTitle>Delete feature?</AlertDialogTitle>
                                                <AlertDialogDescription>
                                                    This removes the feature and all scopes across plans.
                                                </AlertDialogDescription>
                                            </AlertDialogHeader>
                                            <AlertDialogFooter>
                                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                                <AlertDialogAction
                                                    onClick={() => handleDeleteFeature(selectedFeature.id)}
                                                    className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                                >
                                                    Delete feature
                                                </AlertDialogAction>
                                            </AlertDialogFooter>
                                        </AlertDialogContent>
                                    </AlertDialog>
                                </div>
                            )}
                        </CardHeader>
                        <CardContent className="space-y-6">
                            {selectedFeature ? (
                                <>
                                    <div className="grid gap-4 md:grid-cols-3">
                                        <div>
                                            <Label className="text-xs uppercase text-muted-foreground">Slug</Label>
                                            <p className="font-mono text-sm">{selectedFeature.slug}</p>
                                        </div>
                                        <div>
                                            <Label className="text-xs uppercase text-muted-foreground">Category</Label>
                                            <Badge variant="outline" className="mt-1">
                                                {(selectedFeature.category || 'uncategorized').toUpperCase()}
                                            </Badge>
                                        </div>
                                        <div>
                                            <Label className="text-xs uppercase text-muted-foreground">Updated</Label>
                                            <p className="text-sm text-muted-foreground">
                                                {new Date(selectedFeature.updated_at).toLocaleString()}
                                            </p>
                                        </div>
                                    </div>
                                    <Separator />
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <h3 className="text-lg font-semibold">Scopes</h3>
                                            <p className="text-sm text-muted-foreground">
                                                Define CLI/GUI/API permissions for this feature
                                            </p>
                                        </div>
                                        {!showAddScopeForm && (
                                            <Button onClick={() => setShowAddScopeForm(true)} disabled={!selectedFeature}>
                                                <Plus className="mr-2 h-4 w-4" />
                                                New Scope
                                            </Button>
                                        )}
                                    </div>
                                    <div className="space-y-4">
                                        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                                            <div className="flex flex-1 items-center gap-2">
                                                <Filter className="h-4 w-4 text-muted-foreground" />
                                                <Input
                                                    placeholder="Search scopes..."
                                                    value={scopeSearchTerm}
                                                    onChange={(e) => setScopeSearchTerm(e.target.value)}
                                                    className="flex-1"
                                                />
                                            </div>
                                            <Select value={scopePermissionFilter} onValueChange={(value: any) => setScopePermissionFilter(value)}>
                                                <SelectTrigger className="w-40">
                                                    <SelectValue />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    <SelectItem value="all">All Permissions</SelectItem>
                                                    <SelectItem value="allow">Allow</SelectItem>
                                                    <SelectItem value="deny">Deny</SelectItem>
                                                    <SelectItem value="limit">Limit</SelectItem>
                                                </SelectContent>
                                            </Select>
                                        </div>
                                    </div>
                                    {showAddScopeForm ? (
                                        <div className="rounded-md border bg-slate-50/50 dark:bg-slate-900/20 p-3">
                                            <form onSubmit={handleCreateScope} className="space-y-2">
                                                {/* Row 1: All Fields */}
                                                <div className="grid grid-cols-[1fr_1fr_auto_auto] gap-2 items-end">
                                                    <div className="space-y-1">
                                                        <Label htmlFor="form-scope-name" className="text-xs">Name *</Label>
                                                        <Input
                                                            id="form-scope-name"
                                                            value={scopeForm.name}
                                                            onChange={(e) =>
                                                                setScopeForm((prev) => ({ ...prev, name: e.target.value }))
                                                            }
                                                            onBlur={() =>
                                                                !scopeForm.slug &&
                                                                setScopeForm((prev) => ({ ...prev, slug: slugify(prev.name) }))
                                                            }
                                                            placeholder="activate"
                                                            className="h-8 text-sm"
                                                            required
                                                        />
                                                    </div>
                                                    <div className="space-y-1">
                                                        <Label htmlFor="form-scope-slug" className="text-xs">Slug *</Label>
                                                        <div className="flex gap-1">
                                                            <Input
                                                                id="form-scope-slug"
                                                                value={scopeForm.slug}
                                                                onChange={(e) =>
                                                                    setScopeForm((prev) => ({ ...prev, slug: e.target.value }))
                                                                }
                                                                placeholder="activate"
                                                                className="font-mono h-8 text-sm"
                                                                required
                                                            />
                                                            <Button
                                                                type="button"
                                                                variant="ghost"
                                                                onClick={() =>
                                                                    setScopeForm((prev) => ({ ...prev, slug: slugify(prev.name) }))
                                                                }
                                                                size="sm"
                                                                className="px-2 h-8"
                                                            >
                                                                Auto
                                                            </Button>
                                                        </div>
                                                    </div>
                                                    <div className="space-y-1">
                                                        <Label htmlFor="form-scope-permission" className="text-xs">Permission *</Label>
                                                        <Select
                                                            value={scopeForm.permission}
                                                            onValueChange={(value: 'allow' | 'deny' | 'limit') =>
                                                                setScopeForm((prev) => ({ ...prev, permission: value }))
                                                            }
                                                        >
                                                            <SelectTrigger id="form-scope-permission" className="h-8 text-xs w-24">
                                                                <SelectValue />
                                                            </SelectTrigger>
                                                            <SelectContent>
                                                                <SelectItem value="allow">Allow</SelectItem>
                                                                <SelectItem value="deny">Deny</SelectItem>
                                                                <SelectItem value="limit">Limit</SelectItem>
                                                            </SelectContent>
                                                        </Select>
                                                    </div>
                                                    <div className="space-y-1">
                                                        <Label htmlFor="form-scope-limit" className="text-xs">Limit</Label>
                                                        <Input
                                                            id="form-scope-limit"
                                                            type="number"
                                                            min="0"
                                                            disabled={scopeForm.permission !== 'limit'}
                                                            value={scopeForm.limit ?? ''}
                                                            onChange={(e) =>
                                                                setScopeForm((prev) => ({ ...prev, limit: e.target.value }))
                                                            }
                                                            placeholder={scopeForm.permission === 'limit' ? 'Max' : 'N/A'}
                                                            className="h-8 text-sm w-20"
                                                        />
                                                    </div>
                                                </div>
                                                {/* Row 2: Description and Actions */}
                                                <div className="flex flex-wrap gap-2 items-start">
                                                    <div className="flex-1 space-y-1">
                                                        <Label htmlFor="form-scope-description" className="text-xs">Description</Label>
                                                        <Textarea
                                                            id="form-scope-description"
                                                            value={scopeForm.description ?? ''}
                                                            onChange={(e) =>
                                                                setScopeForm((prev) => ({ ...prev, description: e.target.value }))
                                                            }
                                                            rows={1}
                                                            placeholder="What does this scope do?"
                                                            className="resize-none text-xs"
                                                        />
                                                    </div>
                                                    <div className="space-y-1">
                                                        <Label htmlFor="form-restriction-type" className="text-xs">Restriction Type</Label>
                                                        <Select
                                                            value={scopeForm.restrictionType}
                                                            onValueChange={(value: any) => setScopeForm((prev) => ({ ...prev, restrictionType: value }))}
                                                        >
                                                            <SelectTrigger id="form-restriction-type" className="h-8 text-xs">
                                                                <SelectValue />
                                                            </SelectTrigger>
                                                            <SelectContent>
                                                                <SelectItem value="none">None</SelectItem>
                                                                <SelectItem value="storage">Storage</SelectItem>
                                                                <SelectItem value="user">User</SelectItem>
                                                                <SelectItem value="device">Device</SelectItem>
                                                            </SelectContent>
                                                        </Select>
                                                    </div>
                                                    <div className="space-y-1">
                                                        <Label htmlFor="form-restriction-limit" className="text-xs">Restriction Limit</Label>
                                                        <Input
                                                            id="form-restriction-limit"
                                                            type="number"
                                                            min={0}
                                                            value={scopeForm.restrictionLimit ?? ''}
                                                            onChange={(e) => setScopeForm((prev) => ({ ...prev, restrictionLimit: e.target.value }))}
                                                            className="h-8 text-sm w-24"
                                                        />
                                                    </div>
                                                    <div className="space-y-1">
                                                        <Label htmlFor="form-restriction-window" className="text-xs">Window (seconds)</Label>
                                                        <Input
                                                            id="form-restriction-window"
                                                            type="number"
                                                            min={0}
                                                            value={scopeForm.restrictionWindow ?? ''}
                                                            onChange={(e) => setScopeForm((prev) => ({ ...prev, restrictionWindow: e.target.value }))}
                                                            className="h-8 text-sm w-32"
                                                        />
                                                    </div>
                                                    <div className="flex gap-2">
                                                        <Button
                                                            type="button"
                                                            variant="ghost"
                                                            size="sm"
                                                            onClick={() => {
                                                                setShowAddScopeForm(false);
                                                                setScopeForm(defaultScopeForm);
                                                            }}
                                                        >
                                                            Cancel
                                                        </Button>
                                                        <Button
                                                            type="submit"
                                                            size="sm"
                                                            disabled={
                                                                createScopeMutation.isPending ||
                                                                !scopeForm.name.trim() ||
                                                                !scopeForm.slug.trim()
                                                            }
                                                        >
                                                            {createScopeMutation.isPending ? (
                                                                <>
                                                                    <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                                                                    Creating...
                                                                </>
                                                            ) : (
                                                                'Create'
                                                            )}
                                                        </Button>
                                                    </div>
                                                </div>
                                            </form>
                                        </div>
                                    ) : null}
                                    <div className="overflow-y-auto h-[calc(100vh-600px)]">
                                        {scopesLoading ? (
                                            <div className="space-y-2">
                                                {[...Array(3)].map((_, index) => (
                                                    <Skeleton key={index} className="h-12 w-full" />
                                                ))}
                                            </div>
                                        ) : scopes.length === 0 && !showAddScopeForm ? (
                                            <div className="flex flex-col items-center justify-center rounded-md border border-dashed py-12 text-center">
                                                <Target className="h-10 w-10 text-muted-foreground" />
                                                <p className="mt-2 text-sm text-muted-foreground">
                                                    No scopes yet for this feature.
                                                </p>
                                                <Button className="mt-4" onClick={() => setShowAddScopeForm(true)}>
                                                    <Plus className="mr-2 h-4 w-4" /> Add Scope
                                                </Button>
                                            </div>
                                        ) : filteredScopes.length === 0 ? (
                                            <div className="flex flex-col items-center justify-center rounded-md border border-dashed py-12 text-center">
                                                <Target className="h-10 w-10 text-muted-foreground" />
                                                <p className="mt-2 text-sm text-muted-foreground">
                                                    No scopes match your filters.
                                                </p>
                                            </div>
                                        ) : (
                                            <div className="space-y-3">
                                                {filteredScopes.map((scope) => (
                                                    <div key={scope.id} className="rounded-md border p-3 hover:bg-slate-50/30 dark:hover:bg-slate-900/30 transition">
                                                        {editingScopeId === scope.id ? (
                                                            <form onSubmit={(e) => handleUpdateScope(e, scope.id)} className="space-y-2">
                                                                {/* Row 1: Fields */}
                                                                <div className="grid grid-cols-[1fr_1fr_auto_auto] gap-2 items-end">
                                                                    <div className="space-y-1">
                                                                        <Label htmlFor={`edit-scope-name-${scope.id}`} className="text-xs">Name *</Label>
                                                                        <Input
                                                                            id={`edit-scope-name-${scope.id}`}
                                                                            value={scopeForm.name}
                                                                            onChange={(e) =>
                                                                                setScopeForm((prev) => ({ ...prev, name: e.target.value }))
                                                                            }
                                                                            onBlur={() =>
                                                                                !scopeForm.slug &&
                                                                                setScopeForm((prev) => ({ ...prev, slug: slugify(prev.name) }))
                                                                            }
                                                                            className="h-8 text-sm"
                                                                            required
                                                                        />
                                                                    </div>
                                                                    <div className="space-y-1">
                                                                        <Label htmlFor={`edit-scope-slug-${scope.id}`} className="text-xs">Slug *</Label>
                                                                        <div className="flex gap-1">
                                                                            <Input
                                                                                id={`edit-scope-slug-${scope.id}`}
                                                                                value={scopeForm.slug}
                                                                                onChange={(e) =>
                                                                                    setScopeForm((prev) => ({ ...prev, slug: e.target.value }))
                                                                                }
                                                                                className="font-mono h-8 text-sm"
                                                                                required
                                                                            />
                                                                            <Button
                                                                                type="button"
                                                                                variant="ghost"
                                                                                onClick={() =>
                                                                                    setScopeForm((prev) => ({ ...prev, slug: slugify(prev.name) }))
                                                                                }
                                                                                size="sm"
                                                                                className="px-2 h-8"
                                                                            >
                                                                                Auto
                                                                            </Button>
                                                                        </div>
                                                                    </div>
                                                                    <div className="space-y-1">
                                                                        <Label htmlFor={`edit-scope-permission-${scope.id}`} className="text-xs">Permission *</Label>
                                                                        <Select
                                                                            value={scopeForm.permission}
                                                                            onValueChange={(value: 'allow' | 'deny' | 'limit') =>
                                                                                setScopeForm((prev) => ({ ...prev, permission: value }))
                                                                            }
                                                                        >
                                                                            <SelectTrigger id={`edit-scope-permission-${scope.id}`} className="h-8 text-xs w-24">
                                                                                <SelectValue />
                                                                            </SelectTrigger>
                                                                            <SelectContent>
                                                                                <SelectItem value="allow">Allow</SelectItem>
                                                                                <SelectItem value="deny">Deny</SelectItem>
                                                                                <SelectItem value="limit">Limit</SelectItem>
                                                                            </SelectContent>
                                                                        </Select>
                                                                    </div>
                                                                    <div className="space-y-1">
                                                                        <Label htmlFor={`edit-scope-limit-${scope.id}`} className="text-xs">Limit</Label>
                                                                        <Input
                                                                            id={`edit-scope-limit-${scope.id}`}
                                                                            type="number"
                                                                            min="0"
                                                                            disabled={scopeForm.permission !== 'limit'}
                                                                            value={scopeForm.limit ?? ''}
                                                                            onChange={(e) =>
                                                                                setScopeForm((prev) => ({ ...prev, limit: e.target.value }))
                                                                            }
                                                                            placeholder={scopeForm.permission === 'limit' ? 'Max' : 'N/A'}
                                                                            className="h-8 text-sm w-20"
                                                                        />
                                                                    </div>
                                                                </div>
                                                                {/* Row 2: Description and Actions */}
                                                                <div className="flex gap-2 items-end">
                                                                    <div className="flex-1 space-y-1">
                                                                        <Label htmlFor={`edit-scope-description-${scope.id}`} className="text-xs">Description</Label>
                                                                        <Textarea
                                                                            id={`edit-scope-description-${scope.id}`}
                                                                            value={scopeForm.description ?? ''}
                                                                            onChange={(e) =>
                                                                                setScopeForm((prev) => ({ ...prev, description: e.target.value }))
                                                                            }
                                                                            rows={1}
                                                                            placeholder="What does this scope do?"
                                                                            className="resize-none text-xs"
                                                                        />
                                                                    </div>
                                                                    <div className="grid gap-4 sm:grid-cols-3">
                                                                        <div className="space-y-1">
                                                                            <Label htmlFor={`edit-restriction-type-${scope.id}`} className="text-xs">Restriction Type</Label>
                                                                            <Select
                                                                                value={scopeForm.restrictionType}
                                                                                onValueChange={(value: any) => setScopeForm((prev) => ({ ...prev, restrictionType: value }))}
                                                                            >
                                                                                <SelectTrigger id={`edit-restriction-type-${scope.id}`} className="h-8 text-xs">
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
                                                                        <div className="space-y-1">
                                                                            <Label htmlFor={`edit-restriction-limit-${scope.id}`} className="text-xs">Restriction Limit</Label>
                                                                            <Input
                                                                                id={`edit-restriction-limit-${scope.id}`}
                                                                                type="number"
                                                                                min={0}
                                                                                value={scopeForm.restrictionLimit ?? ''}
                                                                                onChange={(e) => setScopeForm((prev) => ({ ...prev, restrictionLimit: e.target.value }))}
                                                                                className="h-8 text-sm w-24"
                                                                            />
                                                                        </div>
                                                                        <div className="space-y-1">
                                                                            <Label htmlFor={`edit-restriction-window-${scope.id}`} className="text-xs">Window (seconds)</Label>
                                                                            <Input
                                                                                id={`edit-restriction-window-${scope.id}`}
                                                                                type="number"
                                                                                min={0}
                                                                                value={scopeForm.restrictionWindow ?? ''}
                                                                                onChange={(e) => setScopeForm((prev) => ({ ...prev, restrictionWindow: e.target.value }))}
                                                                                className="h-8 text-sm w-32"
                                                                            />
                                                                        </div>
                                                                    </div>
                                                                    <div className="flex gap-2">
                                                                        <Button
                                                                            type="button"
                                                                            variant="ghost"
                                                                            size="sm"
                                                                            onClick={() => setEditingScopeId(null)}
                                                                        >
                                                                            Cancel
                                                                        </Button>
                                                                        <Button
                                                                            type="submit"
                                                                            size="sm"
                                                                            disabled={
                                                                                updateScopeMutation.isPending ||
                                                                                !scopeForm.name.trim() ||
                                                                                !scopeForm.slug.trim()
                                                                            }
                                                                        >
                                                                            {updateScopeMutation.isPending ? (
                                                                                <>
                                                                                    <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                                                                                    Saving...
                                                                                </>
                                                                            ) : (
                                                                                'Save'
                                                                            )}
                                                                        </Button>
                                                                    </div>
                                                                </div>
                                                            </form>
                                                        ) : (
                                                            <div className="space-y-3">
                                                                <div className="flex items-start justify-between">
                                                                    <div>
                                                                        <p className="font-medium">{scope.name}</p>
                                                                        <p className="font-mono text-xs text-muted-foreground">{scope.slug}</p>
                                                                    </div>
                                                                    <div className="flex gap-2">
                                                                        <Button
                                                                            variant="outline"
                                                                            size="sm"
                                                                            onClick={() => {
                                                                                setScopeForm({
                                                                                    name: scope.name,
                                                                                    slug: scope.slug,
                                                                                    permission: scope.permission as 'allow' | 'deny' | 'limit',
                                                                                    limit: scope.limit ?? '',
                                                                                    description: scope.metadata?.description ?? '',
                                                                                    restrictionType: scope.metadata?.restriction_type ?? '',
                                                                                    restrictionLimit: scope.metadata?.restriction_limit ?? '',
                                                                                    restrictionWindow: scope.metadata?.restriction_window_seconds ?? '',
                                                                                });
                                                                                setEditingScopeId(scope.id);
                                                                            }}
                                                                        >
                                                                            <Edit className="h-4 w-4" />
                                                                        </Button>
                                                                        <AlertDialog>
                                                                            <AlertDialogTrigger asChild>
                                                                                <Button variant="destructive" size="sm">
                                                                                    <Trash2 className="h-4 w-4" />
                                                                                </Button>
                                                                            </AlertDialogTrigger>
                                                                            <AlertDialogContent>
                                                                                <AlertDialogHeader>
                                                                                    <AlertDialogTitle>Delete scope?</AlertDialogTitle>
                                                                                    <AlertDialogDescription>
                                                                                        This action cannot be undone.
                                                                                    </AlertDialogDescription>
                                                                                </AlertDialogHeader>
                                                                                <AlertDialogFooter>
                                                                                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                                                                                    <AlertDialogAction onClick={() => handleDeleteScope(scope.id)}>
                                                                                        Delete
                                                                                    </AlertDialogAction>
                                                                                </AlertDialogFooter>
                                                                            </AlertDialogContent>
                                                                        </AlertDialog>
                                                                    </div>
                                                                </div>
                                                                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                                                                    <div>
                                                                        <p className="text-xs uppercase text-muted-foreground">Permission</p>
                                                                        <Badge
                                                                            variant={
                                                                                scope.permission === 'allow'
                                                                                    ? 'secondary'
                                                                                    : scope.permission === 'deny'
                                                                                        ? 'destructive'
                                                                                        : 'outline'
                                                                            }
                                                                            className="mt-1 uppercase"
                                                                        >
                                                                            {scope.permission}
                                                                        </Badge>
                                                                    </div>
                                                                    {scope.permission === 'limit' && typeof scope.limit === 'number' && (
                                                                        <div>
                                                                            <p className="text-xs uppercase text-muted-foreground">Limit</p>
                                                                            <p className="mt-1 font-medium">{scope.limit}</p>
                                                                        </div>
                                                                    )}
                                                                    {scope.metadata?.description && (
                                                                        <div className="sm:col-span-2">
                                                                            <p className="text-xs uppercase text-muted-foreground">Description</p>
                                                                            <p className="mt-1 text-sm">{scope.metadata.description}</p>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </>
                            ) : (
                                <div className="flex h-full items-center justify-center text-center">
                                    <p className="text-sm text-muted-foreground">
                                        Select a feature from the left panel to manage its scopes.
                                    </p>
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}
