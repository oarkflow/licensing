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
interface ScopeFormState extends Omit<CreateScopeRequest, 'feature_id'> {
    description?: string;
    limit?: number | string;
}

const defaultFeatureForm: FeatureFormState = {
    name: '',
    slug: '',
    description: '',
    category: 'cli',
};

const defaultScopeForm: ScopeFormState = {
    name: '',
    slug: '',
    permission: 'allow',
    limit: '',
    description: '',
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
    const [featureForm, setFeatureForm] = useState<FeatureFormState>(defaultFeatureForm);
    const [scopeForm, setScopeForm] = useState<ScopeFormState>(defaultScopeForm);

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

    const selectedFeature = features.find((feature) => feature.id === selectedFeatureId) || null;

    const createFeatureMutation = useMutation({
        mutationFn: (payload: FeatureFormState) =>
            api.createFeature(productId!, {
                name: payload.name.trim(),
                slug: payload.slug.trim(),
                description: payload.description?.trim(),
                category: payload.category?.trim(),
            }),
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
            const scopePayload: Omit<CreateScopeRequest, 'feature_id'> = {
                name: payload.name.trim(),
                slug: payload.slug.trim(),
                permission: payload.permission,
            };
            if (payload.permission === 'limit' && payload.limit !== undefined && payload.limit !== '') {
                scopePayload.limit = Number(payload.limit);
            }
            const description = (payload.description || '').trim();
            if (description) {
                scopePayload.metadata = { description };
            }
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
                                    Add a new CLI, GUI, or API capability to this product.
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
                                        placeholder="cli / gui / api"
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

            <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
                <Card>
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

                <Card className="min-h-[480px]">
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
                                    <Dialog open={scopeDialogOpen} onOpenChange={setScopeDialogOpen}>
                                        <DialogTrigger asChild>
                                            <Button disabled={!selectedFeature}>
                                                <Plus className="mr-2 h-4 w-4" />
                                                Add Scope
                                            </Button>
                                        </DialogTrigger>
                                        <DialogContent>
                                            <DialogHeader>
                                                <DialogTitle>New Scope</DialogTitle>
                                                <DialogDescription>
                                                    Create a granular permission inside this feature.
                                                </DialogDescription>
                                            </DialogHeader>
                                            <form onSubmit={handleCreateScope} className="space-y-4">
                                                <div className="space-y-2">
                                                    <Label htmlFor="scope-name">Name *</Label>
                                                    <Input
                                                        id="scope-name"
                                                        value={scopeForm.name}
                                                        onChange={(e) =>
                                                            setScopeForm((prev) => ({ ...prev, name: e.target.value }))
                                                        }
                                                        onBlur={() =>
                                                            !scopeForm.slug &&
                                                            setScopeForm((prev) => ({ ...prev, slug: slugify(prev.name) }))
                                                        }
                                                        placeholder="activate"
                                                        required
                                                    />
                                                </div>
                                                <div className="space-y-2">
                                                    <Label htmlFor="scope-slug">Slug *</Label>
                                                    <div className="flex gap-2">
                                                        <Input
                                                            id="scope-slug"
                                                            value={scopeForm.slug}
                                                            onChange={(e) =>
                                                                setScopeForm((prev) => ({ ...prev, slug: e.target.value }))
                                                            }
                                                            placeholder="activate"
                                                            className="font-mono"
                                                            required
                                                        />
                                                        <Button
                                                            type="button"
                                                            variant="outline"
                                                            onClick={() =>
                                                                setScopeForm((prev) => ({ ...prev, slug: slugify(prev.name) }))
                                                            }
                                                        >
                                                            Auto
                                                        </Button>
                                                    </div>
                                                </div>
                                                <div className="grid gap-4 md:grid-cols-2">
                                                    <div className="space-y-2">
                                                        <Label>Permission</Label>
                                                        <Select
                                                            value={scopeForm.permission}
                                                            onValueChange={(value: 'allow' | 'deny' | 'limit') =>
                                                                setScopeForm((prev) => ({ ...prev, permission: value }))
                                                            }
                                                        >
                                                            <SelectTrigger>
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
                                                        <Label htmlFor="scope-limit">Limit</Label>
                                                        <Input
                                                            id="scope-limit"
                                                            type="number"
                                                            min="0"
                                                            disabled={scopeForm.permission !== 'limit'}
                                                            value={scopeForm.limit ?? ''}
                                                            onChange={(e) =>
                                                                setScopeForm((prev) => ({ ...prev, limit: e.target.value }))
                                                            }
                                                            placeholder={
                                                                scopeForm.permission === 'limit'
                                                                    ? 'Max operations'
                                                                    : 'Enable "limit" permission'
                                                            }
                                                        />
                                                    </div>
                                                </div>
                                                <div className="space-y-2">
                                                    <Label htmlFor="scope-description">Description</Label>
                                                    <Textarea
                                                        id="scope-description"
                                                        value={scopeForm.description ?? ''}
                                                        onChange={(e) =>
                                                            setScopeForm((prev) => ({ ...prev, description: e.target.value }))
                                                        }
                                                        rows={3}
                                                        placeholder="Explain what this scope controls"
                                                    />
                                                </div>
                                                <DialogFooter>
                                                    <Button
                                                        type="submit"
                                                        disabled={
                                                            createScopeMutation.isPending ||
                                                            !scopeForm.name.trim() ||
                                                            !scopeForm.slug.trim()
                                                        }
                                                    >
                                                        {createScopeMutation.isPending ? (
                                                            <>
                                                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                                                Creating...
                                                            </>
                                                        ) : (
                                                            'Create Scope'
                                                        )}
                                                    </Button>
                                                </DialogFooter>
                                            </form>
                                        </DialogContent>
                                    </Dialog>
                                </div>
                                {scopesLoading ? (
                                    <div className="space-y-2">
                                        {[...Array(3)].map((_, index) => (
                                            <Skeleton key={index} className="h-12 w-full" />
                                        ))}
                                    </div>
                                ) : scopes.length === 0 ? (
                                    <div className="flex flex-col items-center justify-center rounded-md border border-dashed py-12 text-center">
                                        <Target className="h-10 w-10 text-muted-foreground" />
                                        <p className="mt-2 text-sm text-muted-foreground">
                                            No scopes yet for this feature.
                                        </p>
                                        <Button className="mt-4" onClick={() => setScopeDialogOpen(true)}>
                                            <Plus className="mr-2 h-4 w-4" /> Add Scope
                                        </Button>
                                    </div>
                                ) : (
                                    <div className="rounded-md border">
                                        <Table>
                                            <TableHeader>
                                                <TableRow>
                                                    <TableHead>Name</TableHead>
                                                    <TableHead>Slug</TableHead>
                                                    <TableHead>Permission</TableHead>
                                                    <TableHead>Limit</TableHead>
                                                    <TableHead>Description</TableHead>
                                                    <TableHead className="w-[120px]">Actions</TableHead>
                                                </TableRow>
                                            </TableHeader>
                                            <TableBody>
                                                {scopes.map((scope) => (
                                                    <TableRow key={scope.id}>
                                                        <TableCell className="font-medium">{scope.name}</TableCell>
                                                        <TableCell className="font-mono text-sm">{scope.slug}</TableCell>
                                                        <TableCell>
                                                            <Badge
                                                                variant={
                                                                    scope.permission === 'allow'
                                                                        ? 'secondary'
                                                                        : scope.permission === 'deny'
                                                                            ? 'destructive'
                                                                            : 'outline'
                                                                }
                                                                className="uppercase"
                                                            >
                                                                {scope.permission}
                                                            </Badge>
                                                        </TableCell>
                                                        <TableCell>
                                                            {scope.permission === 'limit' && typeof scope.limit === 'number'
                                                                ? scope.limit
                                                                : '—'}
                                                        </TableCell>
                                                        <TableCell className="text-sm text-muted-foreground">
                                                            {scope.metadata?.description || '—'}
                                                        </TableCell>
                                                        <TableCell>
                                                            <div className="flex gap-2">
                                                                <Button asChild variant="ghost" size="sm">
                                                                    <Link
                                                                        to={`/products/${productId}/features/${selectedFeature.id}/scopes/${scope.id}/edit`}
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
                                                        </TableCell>
                                                    </TableRow>
                                                ))}
                                            </TableBody>
                                        </Table>
                                    </div>
                                )}
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
    );
}
