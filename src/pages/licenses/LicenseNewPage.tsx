import { useMemo, useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { useNavigate, Link, useSearchParams } from 'react-router-dom';
import { ArrowLeft, Key, Users, Loader2, AlertCircle, ShieldCheck, DollarSign } from 'lucide-react';
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
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import type { Client, Product, Plan, CreateLicenseRequest } from '@/types/api';

export function LicenseNewPage() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const { toast } = useToast();

    const [formData, setFormData] = useState<CreateLicenseRequest>({
        client_id: searchParams.get('clientId') || '',
        product_id: searchParams.get('productId') || '',
        plan_id: '',
        plan_slug: '',
        duration_days: 365,
        max_devices: 1,
    });

    const { data: clientsResponse } = useQuery({
        queryKey: ['clients'],
        queryFn: () => api.listClients(),
    });

    const { data: productsResponse } = useQuery({
        queryKey: ['products'],
        queryFn: () => api.listProducts(),
    });

    const selectedProductId = formData.product_id || '';

    const { data: plansResponse, isFetching: plansLoading, isError: plansError } = useQuery({
        queryKey: ['plans', selectedProductId],
        queryFn: () => api.listPlans(selectedProductId),
        enabled: !!selectedProductId,
        staleTime: 1000 * 60,
    });

    const clients: Client[] = clientsResponse?.data || [];
    const products: Product[] = productsResponse?.data || [];
    const plans: Plan[] = plansResponse?.data || [];

    // Get the selected plan
    const selectedPlan = useMemo(() => {
        return plans.find(p => p.id === formData.plan_id);
    }, [plans, formData.plan_id]);

    // Calculate price based on selected plan and device count
    const priceInfo = useMemo(() => {
        if (!selectedPlan) return null;

        const pricePerDevice = (selectedPlan.price_per_device || 0) / 100; // Convert from cents
        const minDevices = selectedPlan.min_devices || 1;
        const deviceCount = Math.max(formData.max_devices || 1, minDevices);
        const totalPrice = pricePerDevice * deviceCount;
        const currency = selectedPlan.currency || 'USD';
        const billingCycle = selectedPlan.billing_cycle || 'yearly';

        return {
            pricePerDevice,
            minDevices,
            deviceCount,
            totalPrice,
            currency,
            billingCycle,
            isUnderMinimum: (formData.max_devices || 1) < minDevices,
        };
    }, [selectedPlan, formData.max_devices]);

    // Update max_devices to minimum when plan changes
    useEffect(() => {
        if (selectedPlan && selectedPlan.min_devices > (formData.max_devices || 1)) {
            setFormData((prev) => ({
                ...prev,
                max_devices: selectedPlan.min_devices,
            }));
        }
    }, [selectedPlan]);

    const createMutation = useMutation({
        mutationFn: (data: CreateLicenseRequest) => api.createLicense(data),
        onSuccess: (response) => {
            toast({ title: 'License created successfully' });
            if (response.data?.id) {
                navigate(`/licenses/${response.data.id}`);
            } else {
                navigate('/licenses');
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to create license',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();

        // Enforce minimum devices
        if (priceInfo && priceInfo.isUnderMinimum) {
            toast({
                title: 'Invalid device count',
                description: `This plan requires at least ${priceInfo.minDevices} devices`,
                variant: 'destructive',
            });
            return;
        }

        createMutation.mutate(formData);
    };

    const handlePlanChange = (planId: string) => {
        const plan = plans.find((p) => p.id === planId);
        setFormData((prev) => ({
            ...prev,
            plan_id: planId,
            plan_slug: plan?.slug || '',
            // Set max_devices to plan's minimum if current value is less
            max_devices: plan ? Math.max(prev.max_devices || 1, plan.min_devices || 1) : prev.max_devices,
        }));
    };

    const selectedClient = useMemo(
        () => clients.find((client) => client.id === formData.client_id),
        [clients, formData.client_id]
    );

    const handleProductChange = (productId: string) => {
        setFormData((prev) => ({
            ...prev,
            product_id: productId,
            plan_id: '',
            plan_slug: '',
        }));
    };

    const formatCurrency = (amount: number, currency: string) => {
        const symbols: Record<string, string> = { USD: '$', EUR: '€', GBP: '£' };
        return `${symbols[currency] || '$'}${amount.toFixed(2)}`;
    };

    const formatBillingCycle = (cycle: string) => {
        const labels: Record<string, string> = {
            monthly: 'month',
            yearly: 'year',
            lifetime: 'one-time',
        };
        return labels[cycle] || cycle;
    };

    const disableSubmit =
        createMutation.isPending ||
        !formData.client_id ||
        !formData.product_id ||
        !formData.plan_id ||
        (priceInfo?.isUnderMinimum ?? false);

    return (
        <div className="space-y-8">
            <div className="flex flex-wrap items-center gap-4">
                <Button
                    variant="ghost"
                    size="icon"
                    className="rounded-2xl border border-white/10 bg-white/5 text-white hover:bg-white/10"
                    onClick={() => navigate(-1)}
                >
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div className="space-y-3">
                    <Badge variant="secondary" className="rounded-full border border-white/10 bg-white/5 px-4 py-1 text-xs uppercase tracking-[0.4em] text-muted-foreground">
                        License Minting
                    </Badge>
                    <div>
                        <h1 className="text-4xl font-semibold tracking-tight">Issue New License</h1>
                        <p className="text-muted-foreground">
                            Bind a client to a product plan with fine-grained control.
                        </p>
                    </div>
                </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
                <Card className="glass-panel rounded-[32px] border-white/10">
                    <CardHeader className="space-y-1">
                        <CardTitle className="flex items-center gap-2 text-2xl">
                            <Key className="h-6 w-6 text-primary" />
                            License Blueprint
                        </CardTitle>
                        <CardDescription>Define who receives access and which matrix they inherit.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleSubmit} className="space-y-8">
                            <div className="grid gap-6 md:grid-cols-2">
                                <div className="space-y-3">
                                    <Label htmlFor="client" className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Client *</Label>
                                    <Select
                                        value={formData.client_id}
                                        onValueChange={(value) =>
                                            setFormData((prev) => ({ ...prev, client_id: value }))
                                        }
                                    >
                                        <SelectTrigger id="client" className="h-12 rounded-2xl border-white/10 bg-white/5">
                                            <SelectValue placeholder="Select a client" />
                                        </SelectTrigger>
                                        <SelectContent className="rounded-2xl border-white/10 bg-card/90 backdrop-blur">
                                            {clients.map((client) => (
                                                <SelectItem key={client.id} value={client.id}>
                                                    {client.email}
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>
                                    <p className="text-xs text-muted-foreground">
                                        Missing someone?{' '}
                                        <Link to="/clients/new" className="text-primary hover:underline">
                                            Add a client
                                        </Link>
                                    </p>
                                </div>

                                <div className="space-y-3">
                                    <Label htmlFor="product" className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Product *</Label>
                                    <Select value={selectedProductId} onValueChange={handleProductChange}>
                                        <SelectTrigger id="product" className="h-12 rounded-2xl border-white/10 bg-white/5">
                                            <SelectValue placeholder="Select a product" />
                                        </SelectTrigger>
                                        <SelectContent className="rounded-2xl border-white/10 bg-card/90 backdrop-blur">
                                            {products.map((product) => (
                                                <SelectItem key={product.id} value={product.id}>
                                                    {product.name}
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>
                                </div>
                            </div>

                            {selectedProductId && (
                                <div className="space-y-3">
                                    <Label htmlFor="plan" className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Plan *</Label>
                                    {plansLoading ? (
                                        <Skeleton className="h-12 w-full rounded-2xl" />
                                    ) : plansError ? (
                                        <div className="flex items-center gap-3 rounded-2xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
                                            <AlertCircle className="h-4 w-4" />
                                            Unable to load plans for this product. Please retry.
                                        </div>
                                    ) : plans.length === 0 ? (
                                        <div className="rounded-2xl border border-dashed border-white/20 p-4 text-sm text-muted-foreground">
                                            No plans configured for this product yet.{' '}
                                            <Link to={`/products/${selectedProductId}`} className="text-primary hover:underline">
                                                Configure plans
                                            </Link>
                                        </div>
                                    ) : (
                                        <>
                                            <Select value={formData.plan_id} onValueChange={handlePlanChange}>
                                                <SelectTrigger id="plan" className="h-12 rounded-2xl border-white/10 bg-white/5">
                                                    <SelectValue placeholder="Select a plan" />
                                                </SelectTrigger>
                                                <SelectContent className="rounded-2xl border-white/10 bg-card/90 backdrop-blur">
                                                    {plans.map((plan) => (
                                                        <SelectItem key={plan.id} value={plan.id}>
                                                            <div className="flex flex-col gap-0.5">
                                                                <span className="font-medium">{plan.name}</span>
                                                                <span className="text-xs text-muted-foreground">
                                                                    {plan.price_per_device > 0
                                                                        ? `${formatCurrency(plan.price_per_device / 100, plan.currency || 'USD')}/device/${formatBillingCycle(plan.billing_cycle)}`
                                                                        : plan.slug
                                                                    }
                                                                    {` · min ${plan.min_devices || 1} device${(plan.min_devices || 1) > 1 ? 's' : ''}`}
                                                                </span>
                                                            </div>
                                                        </SelectItem>
                                                    ))}
                                                </SelectContent>
                                            </Select>
                                            {selectedPlan && (
                                                <div className="mt-3 rounded-2xl border border-white/10 bg-white/5 p-4 space-y-2">
                                                    <div className="flex items-center justify-between text-sm">
                                                        <span className="text-muted-foreground">Plan</span>
                                                        <span className="font-medium">{selectedPlan.name}</span>
                                                    </div>
                                                    <div className="flex items-center justify-between text-sm">
                                                        <span className="text-muted-foreground">Min Devices Required</span>
                                                        <span className="font-medium">{selectedPlan.min_devices || 1}</span>
                                                    </div>
                                                    {selectedPlan.price_per_device > 0 && (
                                                        <div className="flex items-center justify-between text-sm">
                                                            <span className="text-muted-foreground">Price per Device</span>
                                                            <span className="font-medium">
                                                                {formatCurrency(selectedPlan.price_per_device / 100, selectedPlan.currency || 'USD')}/{formatBillingCycle(selectedPlan.billing_cycle)}
                                                            </span>
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </>
                                    )}
                                </div>
                            )}

                            <div className="grid gap-6 md:grid-cols-2">
                                <div className="space-y-3">
                                    <Label htmlFor="max_devices" className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Number of Devices *</Label>
                                    <Input
                                        id="max_devices"
                                        type="number"
                                        min={priceInfo?.minDevices || 1}
                                        value={formData.max_devices || ''}
                                        onChange={(e) =>
                                            setFormData((prev) => ({
                                                ...prev,
                                                max_devices: parseInt(e.target.value, 10) || 1,
                                            }))
                                        }
                                        className={`h-12 rounded-2xl border-white/10 bg-white/5 ${priceInfo?.isUnderMinimum ? 'border-destructive' : ''}`}
                                    />
                                    {selectedPlan && (
                                        <p className={`text-xs ${priceInfo?.isUnderMinimum ? 'text-destructive font-medium' : 'text-muted-foreground'}`}>
                                            {priceInfo?.isUnderMinimum
                                                ? `⚠️ This plan requires at least ${priceInfo.minDevices} device${priceInfo.minDevices > 1 ? 's' : ''}`
                                                : `Minimum: ${priceInfo?.minDevices || 1} device${(priceInfo?.minDevices || 1) > 1 ? 's' : ''}`
                                            }
                                        </p>
                                    )}
                                </div>
                                <div className="space-y-3">
                                    <Label htmlFor="duration_days" className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Duration (Days)</Label>
                                    <Input
                                        id="duration_days"
                                        type="number"
                                        min="1"
                                        value={formData.duration_days || ''}
                                        onChange={(e) =>
                                            setFormData((prev) => ({
                                                ...prev,
                                                duration_days: parseInt(e.target.value, 10) || 365,
                                            }))
                                        }
                                        className="h-12 rounded-2xl border-white/10 bg-white/5"
                                    />
                                    <p className="text-xs text-muted-foreground">Determines when the entitlement automatically lapses.</p>
                                </div>
                            </div>

                            {priceInfo && priceInfo.isUnderMinimum && (
                                <Alert variant="destructive" className="rounded-2xl">
                                    <AlertCircle className="h-4 w-4" />
                                    <AlertDescription>
                                        This plan requires at least {priceInfo.minDevices} devices.
                                        Please increase the device count.
                                    </AlertDescription>
                                </Alert>
                            )}

                            <Separator className="border-white/10" />

                            <div className="flex flex-wrap gap-3">
                                <Button
                                    type="submit"
                                    disabled={disableSubmit}
                                    className="rounded-2xl bg-primary px-6 text-primary-foreground shadow-lg shadow-primary/30"
                                >
                                    {createMutation.isPending ? (
                                        <>
                                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                            Minting...
                                        </>
                                    ) : (
                                        'Create License'
                                    )}
                                </Button>
                                <Button
                                    type="button"
                                    variant="outline"
                                    className="rounded-2xl border-white/20 text-white hover:bg-white/10"
                                    onClick={() => navigate(-1)}
                                >
                                    Cancel
                                </Button>
                            </div>
                        </form>
                    </CardContent>
                </Card>

                <div className="space-y-6">
                    <Card className="glass-panel rounded-[32px] border-white/10">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-lg">
                                <Users className="h-5 w-5 text-secondary" />
                                Recipient Snapshot
                            </CardTitle>
                            <CardDescription>Quick glance at the chosen client</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-3 text-sm">
                            {selectedClient ? (
                                <>
                                    <p className="text-muted-foreground">{selectedClient.email}</p>
                                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                                        <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Client ID</p>
                                        <p className="font-mono text-sm text-primary">{selectedClient.id}</p>
                                    </div>
                                    <p className="text-xs text-muted-foreground">
                                        Joined {selectedClient.created_at ? new Date(selectedClient.created_at).toLocaleDateString() : '—'}
                                    </p>
                                </>
                            ) : (
                                <div className="rounded-2xl border border-dashed border-white/20 p-4 text-muted-foreground">
                                    Select a client to preview their identity.
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {priceInfo && priceInfo.totalPrice > 0 && !priceInfo.isUnderMinimum && (
                        <Card className="glass-panel rounded-[32px] border-white/10 border-primary/30 bg-primary/5">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2 text-lg">
                                    <DollarSign className="h-5 w-5 text-primary" />
                                    License Cost
                                </CardTitle>
                                <CardDescription>Calculated based on plan pricing</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-muted-foreground">Total</span>
                                    <span className="text-2xl font-bold text-primary">
                                        {formatCurrency(priceInfo.totalPrice, priceInfo.currency)}
                                        <span className="text-sm font-normal text-muted-foreground">
                                            /{formatBillingCycle(priceInfo.billingCycle)}
                                        </span>
                                    </span>
                                </div>
                                <Separator className="border-white/10" />
                                <div className="space-y-2 text-sm">
                                    <div className="flex justify-between">
                                        <span className="text-muted-foreground">Price per device</span>
                                        <span>{formatCurrency(priceInfo.pricePerDevice, priceInfo.currency)}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-muted-foreground">Devices</span>
                                        <span>{priceInfo.deviceCount}</span>
                                    </div>
                                    {priceInfo.minDevices > 1 && (
                                        <div className="flex justify-between text-xs">
                                            <span className="text-muted-foreground">Minimum required</span>
                                            <span>{priceInfo.minDevices} devices</span>
                                        </div>
                                    )}
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    <Card className="glass-panel rounded-[32px] border-white/10">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-lg">
                                <ShieldCheck className="h-5 w-5 text-emerald-300" />
                                Integrity Checks
                            </CardTitle>
                            <CardDescription>Pre-flight validation summary</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-3 text-sm">
                            <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-white/5 px-4 py-2">
                                <span className="text-muted-foreground">Client linked</span>
                                <Badge variant={formData.client_id ? 'secondary' : 'outline'} className={formData.client_id ? 'bg-emerald-400/20 text-emerald-200' : ''}>
                                    {formData.client_id ? 'Ready' : 'Missing'}
                                </Badge>
                            </div>
                            <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-white/5 px-4 py-2">
                                <span className="text-muted-foreground">Product + Plan</span>
                                <Badge variant={formData.plan_id ? 'secondary' : 'outline'} className={formData.plan_id ? 'bg-emerald-400/20 text-emerald-200' : ''}>
                                    {formData.plan_id ? 'Aligned' : 'Pending'}
                                </Badge>
                            </div>
                            <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-white/5 px-4 py-2">
                                <span className="text-muted-foreground">Device count</span>
                                <Badge
                                    variant={priceInfo?.isUnderMinimum ? 'destructive' : 'secondary'}
                                    className={!priceInfo?.isUnderMinimum ? 'bg-emerald-400/20 text-emerald-200' : ''}
                                >
                                    {formData.max_devices} {priceInfo?.isUnderMinimum && `(min ${priceInfo.minDevices})`}
                                </Badge>
                            </div>
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}
