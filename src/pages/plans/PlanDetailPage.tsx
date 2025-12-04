import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
    ArrowLeft,
    Layers,
    Trash2,
    Plus,
    Puzzle,
    ChevronDown,
    ChevronRight,
    Save,
    Edit,
    X,
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
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import {
    Collapsible,
    CollapsibleContent,
    CollapsibleTrigger,
} from '@/components/ui/collapsible';
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
import type { PlanFeature, FeatureScope, CreatePlanRequest } from '@/types/api';
import { formatCurrencyFromCents } from '@/lib/utils';

// Scope Card Component with Toggle
function ScopeCard({
    scope,
    isAllowed,
    onToggle,
}: {
    scope: FeatureScope;
    isAllowed: boolean;
    onToggle: (allowed: boolean) => void;
}) {
    return (
        <Card className={`transition-all hover:shadow-md ${isAllowed ? 'border-accent/50' : 'border-destructive/50'}`}>
            <CardContent className="p-4">
                <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                        <h4 className="font-medium text-sm truncate text-card-foreground">{scope.name}</h4>
                        <p className="text-xs text-muted-foreground font-mono truncate">{scope.slug}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                        <Badge variant={isAllowed ? 'default' : 'destructive'} className="text-xs">
                            {isAllowed ? 'Allow' : 'Deny'}
                        </Badge>
                        <Switch
                            checked={isAllowed}
                            onCheckedChange={onToggle}
                        />
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}

// Editable Plan Feature Row Component
function PlanFeatureRow({
    pf,
    productId,
    planId,
    onRemove,
}: {
    pf: PlanFeature;
    productId: string;
    planId: string;
    onRemove: () => void;
}) {
    const [isOpen, setIsOpen] = useState(true);
    const [enabled, setEnabled] = useState(pf.enabled);
    const [scopeOverrides, setScopeOverrides] = useState<Record<string, { permission: string; limit?: number }>>(
        pf.scope_overrides || {}
    );
    const [isDirty, setIsDirty] = useState(false);
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const updateMutation = useMutation({
        mutationFn: () => api.updatePlanFeature(productId, planId, pf.feature_id, {
            enabled,
            scope_overrides: scopeOverrides,
        }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['plan-features', productId, planId] });
            toast({ title: 'Feature updated successfully' });
            setIsDirty(false);
        },
        onError: (error) => {
            toast({
                title: 'Failed to update feature',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleEnabledChange = (value: boolean) => {
        setEnabled(value);
        setIsDirty(true);
    };

    const handleScopeToggle = (scopeSlug: string, allowed: boolean) => {
        setScopeOverrides(prev => ({
            ...prev,
            [scopeSlug]: {
                ...prev[scopeSlug],
                permission: allowed ? 'allow' : 'deny',
            }
        }));
        setIsDirty(true);
    };

    const getScopePermission = (scope: FeatureScope): boolean => {
        const override = scopeOverrides[scope.slug];
        if (override) {
            return override.permission === 'allow';
        }
        return scope.permission === 'allow';
    };

    return (
        <div className="border rounded-lg">
            <Collapsible open={isOpen} onOpenChange={setIsOpen}>
                <div className="flex items-center justify-between p-4">
                    <CollapsibleTrigger asChild>
                        <Button variant="ghost" size="sm" className="gap-2">
                            {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                            <span className="font-medium">{pf.feature?.name || pf.feature_id}</span>
                            {pf.feature?.category && (
                                <Badge variant="outline" className="ml-2">{pf.feature.category}</Badge>
                            )}
                        </Button>
                    </CollapsibleTrigger>
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2">
                            <Label htmlFor={`enabled-${pf.feature_id}`} className="text-sm">Enabled</Label>
                            <Switch
                                id={`enabled-${pf.feature_id}`}
                                checked={enabled}
                                onCheckedChange={handleEnabledChange}
                            />
                        </div>
                        {isDirty && (
                            <Button
                                size="sm"
                                onClick={() => updateMutation.mutate()}
                                disabled={updateMutation.isPending}
                            >
                                <Save className="h-4 w-4 mr-1" />
                                Save
                            </Button>
                        )}
                        <AlertDialog>
                            <AlertDialogTrigger asChild>
                                <Button variant="ghost" size="icon">
                                    <Trash2 className="h-4 w-4" />
                                </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                                <AlertDialogHeader>
                                    <AlertDialogTitle>Remove Feature</AlertDialogTitle>
                                    <AlertDialogDescription>
                                        Remove this feature from the plan?
                                    </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                                    <AlertDialogAction onClick={onRemove}>
                                        Remove
                                    </AlertDialogAction>
                                </AlertDialogFooter>
                            </AlertDialogContent>
                        </AlertDialog>
                    </div>
                </div>
                <CollapsibleContent>
                    <div className="px-4 pb-4 space-y-4">
                        <div className="text-sm text-muted-foreground">
                            <span className="font-mono">{pf.feature?.slug}</span>
                            {pf.feature?.description && (
                                <p className="mt-1">{pf.feature.description}</p>
                            )}
                        </div>

                        {pf.scopes && pf.scopes.length > 0 && (
                            <div className="space-y-3">
                                <Label className="text-sm font-medium">Scope Permissions</Label>
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                                    {pf.scopes.map((scope) => (
                                        <ScopeCard
                                            key={scope.id}
                                            scope={scope}
                                            isAllowed={getScopePermission(scope)}
                                            onToggle={(allowed) => handleScopeToggle(scope.slug, allowed)}
                                        />
                                    ))}
                                </div>
                            </div>
                        )}

                        {(!pf.scopes || pf.scopes.length === 0) && (
                            <p className="text-sm text-muted-foreground italic">No scopes defined for this feature</p>
                        )}
                    </div>
                </CollapsibleContent>
            </Collapsible>
        </div>
    );
}

export function PlanDetailPage() {
    const { productId, planId } = useParams<{
        productId: string;
        planId: string;
    }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const { data: planResponse, isLoading: planLoading } = useQuery({
        queryKey: ['plan', productId, planId],
        queryFn: () => api.getPlan(productId!, planId!),
        enabled: !!productId && !!planId,
        staleTime: 30000, // Cache for 30 seconds
    });

    const { data: featuresResponse } = useQuery({
        queryKey: ['plan-features', productId, planId],
        queryFn: () => api.getPlanFeatures(productId!, planId!),
        enabled: !!productId && !!planId,
        staleTime: 30000,
    });

    const { data: licensesResponse } = useQuery({
        queryKey: ['licenses'],
        queryFn: () => api.listLicenses(),
        staleTime: 60000, // Cache for 1 minute
    });

    // Edit form state
    const [isEditMode, setIsEditMode] = useState(false);
    const [formData, setFormData] = useState<Partial<CreatePlanRequest>>({
        name: '',
        slug: '',
        description: '',
        price_per_device: undefined,
        min_devices: 1,
        currency: 'USD',
        billing_cycle: 'yearly',
    });
    const [isFormDirty, setIsFormDirty] = useState(false);

    // Initialize form when plan data loads
    useEffect(() => {
        if (planResponse?.data) {
            setFormData({
                name: planResponse.data.name,
                slug: planResponse.data.slug,
                description: planResponse.data.description || '',
                price_per_device: planResponse.data.price_per_device ? planResponse.data.price_per_device / 100 : undefined,
                min_devices: planResponse.data.min_devices || 1,
                currency: planResponse.data.currency || 'USD',
                billing_cycle: planResponse.data.billing_cycle || 'yearly',
            });
            setIsFormDirty(false);
        }
    }, [planResponse?.data]);

    const updatePlanMutation = useMutation({
        mutationFn: (data: Partial<CreatePlanRequest>) =>
            api.updatePlan(productId!, planId!, data),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['plan', productId, planId] });
            queryClient.invalidateQueries({ queryKey: ['plans', productId] });
            toast({ title: 'Plan updated successfully' });
            setIsFormDirty(false);
            setIsEditMode(false);
        },
        onError: (error) => {
            toast({
                title: 'Failed to update plan',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const deleteMutation = useMutation({
        mutationFn: () => api.deletePlan(productId!, planId!),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['plans', productId] });
            toast({ title: 'Plan deleted successfully' });
            navigate(`/products/${productId}`);
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete plan',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const removeFeatureMutation = useMutation({
        mutationFn: (featureId: string) =>
            api.removeFeatureFromPlan(productId!, planId!, featureId),
        onSuccess: () => {
            queryClient.invalidateQueries({
                queryKey: ['plan-features', productId, planId],
            });
            toast({ title: 'Feature removed from plan' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to remove feature',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleFormChange = (field: keyof CreatePlanRequest, value: unknown) => {
        setFormData(prev => ({ ...prev, [field]: value }));
        setIsFormDirty(true);
    };

    const handleSavePlan = () => {
        const pricePerDevice = formData.price_per_device || 0;
        const minDevices = formData.min_devices || 1;
        const price = Math.round(pricePerDevice * minDevices * 100);

        updatePlanMutation.mutate({
            ...formData,
            price,
            price_per_device: Math.round(pricePerDevice * 100),
            min_devices: minDevices,
        });
    };

    if (planLoading) {
        return (
            <div className="space-y-6">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
            </div>
        );
    }

    const plan = planResponse?.data;
    const planFeatures = featuresResponse?.data || [];
    const allLicenses = licensesResponse?.data || [];
    const planLicenses = allLicenses.filter(l => l.plan_id === planId);

    if (!plan) {
        return (
            <div className="flex flex-col items-center justify-center py-12">
                <Layers className="h-12 w-12 text-muted-foreground" />
                <h2 className="mt-4 text-lg font-semibold">Plan not found</h2>
                <Button asChild className="mt-4">
                    <Link to={`/products/${productId}`}>Back to Product</Link>
                </Button>
            </div>
        );
    }

    const priceCents = (plan.price_per_device ?? plan.price ?? 0);
    const currencyCode = plan.currency || 'USD';
    const hasPaidPrice = priceCents > 0;
    const formattedPrice = hasPaidPrice ? formatCurrencyFromCents(priceCents, currencyCode) : 'Free';

    // Calculate displayed total price for form
    const pricePerDevice = formData.price_per_device || 0;
    const minDevices = formData.min_devices || 1;
    const totalPrice = pricePerDevice * minDevices;

    const highlightStats = [
        {
            label: 'Price per Device',
            value: hasPaidPrice ? formattedPrice : 'Free',
            helper: plan.billing_cycle ? `per ${plan.billing_cycle}` : undefined,
        },
        {
            label: 'Minimum Devices',
            value: plan.min_devices || 1,
            helper: 'Required seats',
        },
        {
            label: 'Licenses',
            value: planLicenses.length,
            helper: 'Active licenses',
        },
        {
            label: 'Features',
            value: planFeatures.length,
            helper: 'Assigned features',
        },
        {
            label: 'Currency',
            value: plan.currency || 'USD',
            helper: 'Billing currency',
        },
        {
            label: 'Plan Slug',
            value: plan.slug,
            helper: 'API reference',
        },
    ];

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div className="flex-1">
                    <h1 className="text-3xl font-bold tracking-tight">{plan.name}</h1>
                    <p className="text-muted-foreground">
                        {plan.description || 'No description'}
                    </p>
                </div>
                <div className="flex gap-2">
                    <AlertDialog>
                        <AlertDialogTrigger asChild>
                            <Button variant="destructive">
                                <Trash2 className="mr-2 h-4 w-4" />
                                Delete
                            </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                            <AlertDialogHeader>
                                <AlertDialogTitle>Delete Plan</AlertDialogTitle>
                                <AlertDialogDescription>
                                    This will permanently delete the plan. Existing licenses using
                                    this plan will not be affected.
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

            {/* Plan Details - Preview or Edit Mode */}
            <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                    <div>
                        <CardTitle className="flex items-center gap-2">
                            <Layers className="h-5 w-5" />
                            Plan Details
                        </CardTitle>
                        <CardDescription>
                            {isEditMode ? 'Edit plan settings' : 'Plan configuration overview'}
                        </CardDescription>
                    </div>
                    <div className="flex gap-2">
                        {isEditMode ? (
                            <>
                                <Button
                                    variant="outline"
                                    onClick={() => {
                                        setIsEditMode(false);
                                        setIsFormDirty(false);
                                        // Reset form data
                                        if (planResponse?.data) {
                                            setFormData({
                                                name: planResponse.data.name,
                                                slug: planResponse.data.slug,
                                                description: planResponse.data.description || '',
                                                price_per_device: planResponse.data.price_per_device ? planResponse.data.price_per_device / 100 : undefined,
                                                min_devices: planResponse.data.min_devices || 1,
                                                currency: planResponse.data.currency || 'USD',
                                                billing_cycle: planResponse.data.billing_cycle || 'yearly',
                                            });
                                        }
                                    }}
                                >
                                    <X className="mr-2 h-4 w-4" />
                                    Cancel
                                </Button>
                                <Button
                                    onClick={handleSavePlan}
                                    disabled={updatePlanMutation.isPending || !formData.name || !isFormDirty}
                                >
                                    <Save className="mr-2 h-4 w-4" />
                                    {updatePlanMutation.isPending ? 'Saving...' : 'Save Changes'}
                                </Button>
                            </>
                        ) : (
                            <Button variant="outline" onClick={() => setIsEditMode(true)}>
                                <Edit className="mr-2 h-4 w-4" />
                                Edit Plan
                            </Button>
                        )}
                    </div>
                </CardHeader>
                <CardContent>
                    {isEditMode ? (
                        /* Edit Form */
                        <div className="grid gap-6 md:grid-cols-2">
                            <div className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="name">Name *</Label>
                                    <Input
                                        id="name"
                                        value={formData.name || ''}
                                        onChange={(e) => handleFormChange('name', e.target.value)}
                                        placeholder="Professional Plan"
                                    />
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="slug">Slug</Label>
                                    <Input
                                        id="slug"
                                        value={formData.slug || ''}
                                        onChange={(e) => handleFormChange('slug', e.target.value)}
                                        placeholder="professional"
                                    />
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="description">Description</Label>
                                    <Textarea
                                        id="description"
                                        value={formData.description || ''}
                                        onChange={(e) => handleFormChange('description', e.target.value)}
                                        placeholder="Description of what this plan includes..."
                                        rows={3}
                                    />
                                </div>
                            </div>

                            <div className="space-y-4">
                                <div className="grid gap-4 sm:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="price_per_device">Price per Device</Label>
                                        <Input
                                            id="price_per_device"
                                            type="number"
                                            step="0.01"
                                            min="0"
                                            value={formData.price_per_device || ''}
                                            onChange={(e) => handleFormChange('price_per_device', parseFloat(e.target.value) || undefined)}
                                            placeholder="49.00"
                                        />
                                    </div>

                                    <div className="space-y-2">
                                        <Label htmlFor="min_devices">Min Devices</Label>
                                        <Input
                                            id="min_devices"
                                            type="number"
                                            min="1"
                                            value={formData.min_devices || 1}
                                            onChange={(e) => handleFormChange('min_devices', parseInt(e.target.value) || 1)}
                                            placeholder="1"
                                        />
                                    </div>
                                </div>

                                <div className="grid gap-4 sm:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="currency">Currency</Label>
                                        <Select
                                            value={formData.currency || 'USD'}
                                            onValueChange={(value) => handleFormChange('currency', value)}
                                        >
                                            <SelectTrigger id="currency">
                                                <SelectValue placeholder="Select currency" />
                                            </SelectTrigger>
                                            <SelectContent>
                                                <SelectItem value="USD">USD ($)</SelectItem>
                                                <SelectItem value="EUR">EUR (€)</SelectItem>
                                                <SelectItem value="GBP">GBP (£)</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </div>

                                    <div className="space-y-2">
                                        <Label htmlFor="billing_cycle">Billing Cycle</Label>
                                        <Select
                                            value={formData.billing_cycle || 'yearly'}
                                            onValueChange={(value) => handleFormChange('billing_cycle', value)}
                                        >
                                            <SelectTrigger id="billing_cycle">
                                                <SelectValue placeholder="Select billing cycle" />
                                            </SelectTrigger>
                                            <SelectContent>
                                                <SelectItem value="monthly">Monthly</SelectItem>
                                                <SelectItem value="yearly">Yearly</SelectItem>
                                                <SelectItem value="lifetime">Lifetime</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </div>
                                </div>

                                {totalPrice > 0 && (
                                    <div className="rounded-lg border bg-muted/50 p-3">
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm font-medium">Minimum Cost</span>
                                            <span className="font-bold">
                                                ${totalPrice.toFixed(2)} / {formData.billing_cycle}
                                            </span>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    ) : (
                        /* Preview Layout */
                        <div className="space-y-6">
                            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                                {highlightStats.map((stat) => (
                                    <div key={stat.label} className="rounded-xl border bg-muted/30 p-4">
                                        <p className="text-xs uppercase tracking-wide text-muted-foreground">{stat.label}</p>
                                        <p className="mt-1 text-2xl font-semibold">{stat.value}</p>
                                        {stat.helper && (
                                            <p className="text-xs text-muted-foreground mt-1">{stat.helper}</p>
                                        )}
                                    </div>
                                ))}
                            </div>

                            <div className="grid gap-4 lg:grid-cols-3">
                                <Card className="lg:col-span-2">
                                    <CardHeader className="pb-2">
                                        <CardTitle>Plan Overview</CardTitle>
                                        <CardDescription>High-level information for this plan</CardDescription>
                                    </CardHeader>
                                    <CardContent className="space-y-4">
                                        <div>
                                            <Label className="text-xs text-muted-foreground">Description</Label>
                                            <p className="mt-1 text-sm leading-relaxed">
                                                {plan.description?.trim() || 'No description provided for this plan.'}
                                            </p>
                                        </div>
                                        <dl className="grid gap-4 sm:grid-cols-2">
                                            <div>
                                                <dt className="text-xs text-muted-foreground uppercase tracking-wide">Plan Name</dt>
                                                <dd className="mt-1 font-medium">{plan.name}</dd>
                                            </div>
                                            <div>
                                                <dt className="text-xs text-muted-foreground uppercase tracking-wide">Plan Slug</dt>
                                                <dd className="mt-1 font-mono text-sm">{plan.slug}</dd>
                                            </div>
                                            <div>
                                                <dt className="text-xs text-muted-foreground uppercase tracking-wide">Billing Cycle</dt>
                                                <dd className="mt-1 font-medium capitalize">{plan.billing_cycle || 'N/A'}</dd>
                                            </div>
                                            <div>
                                                <dt className="text-xs text-muted-foreground uppercase tracking-wide">Currency</dt>
                                                <dd className="mt-1 font-medium">{plan.currency || 'USD'}</dd>
                                            </div>
                                        </dl>
                                    </CardContent>
                                </Card>

                                <Card>
                                    <CardHeader className="pb-2">
                                        <CardTitle>Lifecycle & Access</CardTitle>
                                        <CardDescription>Status benchmarks for this plan</CardDescription>
                                    </CardHeader>
                                    <CardContent className="space-y-4">
                                        <div>
                                            <Label className="text-xs text-muted-foreground">Status</Label>
                                            <div className="mt-1">
                                                <Badge variant={plan.is_active ? 'default' : 'secondary'}>
                                                    {plan.is_active ? 'Active' : 'Inactive'}
                                                </Badge>
                                            </div>
                                        </div>
                                        <div>
                                            <Label className="text-xs text-muted-foreground">Trial Offering</Label>
                                            <p className="mt-1 text-sm font-medium">
                                                {plan.is_trial ? `${plan.trial_days} days` : 'No trial available'}
                                            </p>
                                        </div>
                                        <div>
                                            <Label className="text-xs text-muted-foreground">Created</Label>
                                            <p className="mt-1 text-sm">
                                                {new Date(plan.created_at).toLocaleDateString()}
                                            </p>
                                        </div>
                                        <div>
                                            <Label className="text-xs text-muted-foreground">Last Updated</Label>
                                            <p className="mt-1 text-sm">
                                                {new Date(plan.updated_at).toLocaleDateString()}
                                            </p>
                                        </div>
                                    </CardContent>
                                </Card>
                            </div>
                        </div>
                    )}
                </CardContent>
            </Card>

            <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                    <div>
                        <CardTitle>Plan Features</CardTitle>
                        <CardDescription>
                            Features included in this plan - click to expand and configure scopes
                        </CardDescription>
                    </div>
                    <Button asChild>
                        <Link to={`/products/${productId}/plans/${planId}/features/add`}>
                            <Plus className="mr-2 h-4 w-4" />
                            Add Feature
                        </Link>
                    </Button>
                </CardHeader>
                <CardContent>
                    {planFeatures.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-8 text-center">
                            <Puzzle className="h-12 w-12 text-muted-foreground" />
                            <p className="mt-2 text-sm text-muted-foreground">
                                No features added to this plan
                            </p>
                            <Button asChild className="mt-4">
                                <Link to={`/products/${productId}/plans/${planId}/features/add`}>
                                    Add Feature
                                </Link>
                            </Button>
                        </div>
                    ) : (
                        <div className="space-y-2">
                            {planFeatures.map((pf) => (
                                <PlanFeatureRow
                                    key={pf.feature_id}
                                    pf={pf}
                                    productId={productId!}
                                    planId={planId!}
                                    onRemove={() => removeFeatureMutation.mutate(pf.feature_id)}
                                />
                            ))}
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}
