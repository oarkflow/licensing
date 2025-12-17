import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
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
import { useToast } from '@/hooks/use-toast';
import type { CreatePlanRequest } from '@/types/api';

export function PlanNewPage() {
    const { productId } = useParams<{ productId: string }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const [formData, setFormData] = useState<Omit<CreatePlanRequest, 'product_id'>>({
        name: '',
        slug: '',
        description: '',
        price: undefined,
        price_unit: 'none',
        // when price_unit === 'other', put custom value here
        custom_price_unit: undefined as string | undefined,
        currency: 'USD',
        billing_cycle: 'yearly',
        is_trial: false,
        trial_days: 30,
        is_active: true,
    });

    const { data: featuresResponse } = useQuery({
        queryKey: ['features', productId],
        queryFn: () => api.listFeatures(productId!),
        enabled: !!productId,
        staleTime: 1000 * 60,
    });

    const createMutation = useMutation({
        mutationFn: (data: Omit<CreatePlanRequest, 'product_id'>) =>
            api.createPlan(productId!, data),
        onSuccess: (response) => {
            queryClient.invalidateQueries({ queryKey: ['plans', productId] });
            toast({ title: 'Plan created successfully' });
            if (response.data?.id) {
                navigate(`/products/${productId}/plans/${response.data.id}`);
            } else {
                navigate(`/products/${productId}`);
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to create plan',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        // Generate slug from name if not provided
        const slug = formData.slug || formData.name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');

        if (formData.is_trial) {
            // For trial plans, only send trial-related fields
            createMutation.mutate({
                product_id: productId!,
                name: formData.name,
                slug,
                description: formData.description,
                is_trial: true,
                trial_days: formData.trial_days || 30,
                is_active: formData.is_active,
            });
        } else {
            // Use explicit price input (dollars) and price unit
            const priceDollars = formData.price || 0;
            const price = Math.round(priceDollars * 100);
            let priceUnit = formData.price_unit || 'none';
            if (priceUnit === 'feature' && formData.custom_price_unit) {
                priceUnit = `feature:${formData.custom_price_unit}`;
            } else if (priceUnit === 'other' && formData.custom_price_unit) {
                priceUnit = formData.custom_price_unit;
            }

            createMutation.mutate({
                product_id: productId!,
                name: formData.name,
                slug,
                description: formData.description,
                price,
                price_unit: priceUnit,
                currency: formData.currency,
                billing_cycle: formData.billing_cycle,
                is_active: formData.is_active,
                trial_days: undefined, // Clear trial_days for non-trial plans
            });
        }
    };

    // Displayed price for non-trial plans
    const priceDollars = formData.price || 0;
    const priceUnit = formData.price_unit === 'other' ? formData.custom_price_unit || 'other' : formData.price_unit;

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">New Plan</h1>
                    <p className="text-muted-foreground">Create a new licensing plan</p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Layers className="h-5 w-5" />
                        Plan Details
                    </CardTitle>
                    <CardDescription>Configure the plan settings</CardDescription>
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
                                placeholder="professional (auto-generated from name if empty)"
                            />
                            <p className="text-xs text-muted-foreground">
                                Used in API and URLs. Leave empty to auto-generate from name.
                            </p>
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
                                checked={formData.is_trial || false}
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
                                                    // Deduplicate by name
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



                        {!formData.is_trial && (formData.price && formData.price > 0) && (
                            <div className="rounded-lg border bg-muted/50 p-4">
                                <div className="flex items-center justify-between">
                                    <span className="text-sm font-medium">Price</span>
                                    <span className="text-lg font-bold">
                                        ${priceDollars.toFixed(2)} {priceUnit !== 'none' ? `/ ${priceUnit}` : ''}
                                    </span>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">
                                    {formData.currency || 'USD'} · {formData.billing_cycle}
                                </p>
                            </div>
                        )}

                        <div className="flex gap-4">
                            <Button
                                type="submit"
                                disabled={createMutation.isPending || !formData.name}
                            >
                                {createMutation.isPending ? 'Creating...' : 'Create Plan'}
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
