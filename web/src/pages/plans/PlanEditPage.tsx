import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Layers } from 'lucide-react';
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
import { Switch } from '@/components/ui/switch';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/hooks/use-toast';
import type { CreatePlanRequest } from '@/types/api';

export function PlanEditPage() {
    const { productId, planId } = useParams<{
        productId: string;
        planId: string;
    }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const { data: planResponse, isLoading } = useQuery({
        queryKey: ['plan', productId, planId],
        queryFn: () => api.getPlan(productId!, planId!),
        enabled: !!productId && !!planId,
    });

    const [formData, setFormData] = useState<Partial<CreatePlanRequest>>({
        name: '',
        slug: '',
        description: '',
        price: undefined,
        price_unit: 'none',
        custom_price_unit: undefined as string | undefined,
        currency: 'USD',
        billing_cycle: 'yearly',
        is_trial: false,
        trial_days: 30,
    });

    const { data: featuresResponse } = useQuery({
        queryKey: ['features', productId],
        queryFn: () => api.listFeatures(productId!),
        enabled: !!productId,
        staleTime: 1000 * 60,
    });

    useEffect(() => {
        if (planResponse?.data) {
            // If price_unit encodes a feature (feature:<id>), treat it as a feature selection
            let priceUnit = planResponse.data.price_unit || 'none';
            let customUnit: string | undefined = undefined;
            if (priceUnit && priceUnit.startsWith('feature:')) {
                customUnit = priceUnit.split(':')[1];
                priceUnit = 'feature';
            }

            setFormData({
                name: planResponse.data.name,
                slug: planResponse.data.slug,
                description: planResponse.data.description || '',
                // Convert from cents to dollars for display
                price: planResponse.data.price ? planResponse.data.price / 100 : undefined,
                price_unit: priceUnit,
                custom_price_unit: customUnit,
                currency: planResponse.data.currency || 'USD',
                billing_cycle: planResponse.data.billing_cycle || 'yearly',
                is_trial: planResponse.data.is_trial || false,
                trial_days: planResponse.data.trial_days || 30,
            });
        }
    }, [planResponse?.data]);

    const updateMutation = useMutation({
        mutationFn: (data: Partial<CreatePlanRequest>) =>
            api.updatePlan(productId!, planId!, data),
        onSuccess: () => {
            queryClient.invalidateQueries({
                queryKey: ['plan', productId, planId],
            });
            queryClient.invalidateQueries({ queryKey: ['plans', productId] });
            toast({ title: 'Plan updated successfully' });
            navigate(`/products/${productId}/plans/${planId}`);
        },
        onError: (error) => {
            toast({
                title: 'Failed to update plan',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();

        if (formData.is_trial) {
            // For trial plans, only send trial-related fields
            updateMutation.mutate({
                name: formData.name,
                slug: formData.slug,
                description: formData.description,
                is_trial: true,
                trial_days: formData.trial_days || 30,
                is_active: formData.is_active,
            });
        } else {
            const priceDollars = formData.price || 0;
            const price = Math.round(priceDollars * 100);
            let priceUnit = formData.price_unit || 'none';
            if (priceUnit === 'feature' && formData.custom_price_unit) {
                priceUnit = `feature:${formData.custom_price_unit}`;
            } else if (priceUnit === 'other' && formData.custom_price_unit) {
                priceUnit = formData.custom_price_unit;
            }

            updateMutation.mutate({
                ...formData,
                price,
                price_unit: priceUnit,
                trial_days: undefined, // Clear trial_days for non-trial plans
            });
        }
    };

    if (isLoading) {
        return (
            <div className="space-y-6">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
            </div>
        );
    }

    // Calculate displayed total price (only for non-trial plans)
    const priceDollars = formData.price || 0;
    const priceUnit = formData.price_unit === 'other' ? formData.custom_price_unit || 'other' : formData.price_unit;

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Edit Plan</h1>
                    <p className="text-muted-foreground">Update plan information</p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Layers className="h-5 w-5" />
                        Plan Details
                    </CardTitle>
                    <CardDescription>Modify the plan settings</CardDescription>
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
                                placeholder="Professional Plan"
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="slug">Slug</Label>
                            <Input
                                id="slug"
                                value={formData.slug || ''}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, slug: e.target.value }))
                                }
                                placeholder="professional"
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
                                placeholder="Description of what this plan includes..."
                                rows={3}
                            />
                        </div>

                        <div className="flex items-center justify-between">
                            <div className="space-y-0.5">
                                <Label htmlFor="is_trial">Trial Plan</Label>
                                <p className="text-xs text-muted-foreground">
                                    Enable trial mode for this plan (no payment required)
                                </p>
                            </div>
                            <Switch
                                id="is_trial"
                                checked={!!formData.is_trial}
                                onCheckedChange={(checked) =>
                                    setFormData((prev) => ({ ...prev, is_trial: checked }))
                                }
                            />
                        </div>

                        {formData.is_trial && (
                            <div className="space-y-2">
                                <Label htmlFor="trial_days">Trial Duration (days) *</Label>
                                <Input
                                    id="trial_days"
                                    type="number"
                                    min="1"
                                    max="365"
                                    value={formData.trial_days || ''}
                                    onChange={(e) => {
                                        const value = e.target.value;
                                        setFormData((prev) => ({
                                            ...prev,
                                            trial_days: value === '' ? undefined : parseInt(value, 10),
                                        }));
                                    }}
                                    onBlur={(e) => {
                                        const value = e.target.value;
                                        if (value === '' || isNaN(parseInt(value, 10))) {
                                            setFormData((prev) => ({
                                                ...prev,
                                                trial_days: 30,
                                            }));
                                        }
                                    }}
                                    placeholder="30"
                                    required={formData.is_trial}
                                />
                                <p className="text-xs text-muted-foreground">
                                    Number of days the trial license will be valid
                                </p>
                            </div>
                        )}

                        {!formData.is_trial && (
                            <>
                                <div className="grid gap-4 sm:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="price">Price</Label>
                                        <Input
                                            id="price"
                                            type="number"
                                            step="0.01"
                                            min="0"
                                            value={formData.price || ''}
                                            onChange={(e) =>
                                                setFormData((prev) => ({
                                                    ...prev,
                                                    price: parseFloat(e.target.value) || undefined,
                                                }))
                                            }
                                            placeholder="49.00"
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            Amount in dollars for the plan
                                        </p>
                                    </div>

                                    <div className="space-y-2">
                                        <Label htmlFor="price_unit">Per</Label>
                                        <Select
                                            value={formData.price_unit || 'none'}
                                            onValueChange={(value) =>
                                                setFormData((prev) => ({ ...prev, price_unit: value }))
                                            }
                                        >
                                            <SelectTrigger id="price_unit">
                                                <SelectValue placeholder="Select unit" />
                                            </SelectTrigger>
                                            <SelectContent>
                                                <SelectItem value="none">None</SelectItem>
                                                <SelectItem value="feature">Feature</SelectItem>
                                                <SelectItem value="user">User</SelectItem>
                                                <SelectItem value="device">Device</SelectItem>
                                                <SelectItem value="storage">Storage</SelectItem>
                                                <SelectItem value="other">Other</SelectItem>
                                            </SelectContent>
                                        </Select>
                                        {formData.price_unit === 'feature' && (
                                            <Select
                                                value={formData.custom_price_unit || ''}
                                                onValueChange={(value) => setFormData((prev) => ({ ...prev, custom_price_unit: value }))}
                                            >
                                                <SelectTrigger id="price_feature">
                                                    <SelectValue placeholder="Select feature" />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    {(featuresResponse?.data || []).reduce((acc: any[], f) => {
                                                        if (!acc.find((x) => x.id === f.id)) acc.push(f);
                                                        return acc;
                                                    }, []).map((f) => (
                                                        <SelectItem key={f.id} value={f.id}>{f.name}</SelectItem>
                                                    ))}
                                                </SelectContent>
                                            </Select>
                                        )}
                                        {formData.price_unit === 'other' && (
                                            <Input
                                                id="custom_price_unit"
                                                value={formData.custom_price_unit || ''}
                                                onChange={(e) => setFormData((prev) => ({ ...prev, custom_price_unit: e.target.value }))}
                                                placeholder="e.g. seats"
                                            />
                                        )}
                                    </div>
                                </div>
                            </>
                        )}

                        {!formData.is_trial && (
                            <div className="grid gap-4 sm:grid-cols-2">
                                <div className="space-y-2">
                                    <Label htmlFor="currency">Currency</Label>
                                    <Select
                                        value={formData.currency || 'USD'}
                                        onValueChange={(value) =>
                                            setFormData((prev) => ({ ...prev, currency: value }))
                                        }
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
                                        onValueChange={(value) =>
                                            setFormData((prev) => ({ ...prev, billing_cycle: value }))
                                        }
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
                        )}





                        <div className="flex gap-4">
                            <Button
                                type="submit"
                                disabled={updateMutation.isPending || !formData.name}
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
