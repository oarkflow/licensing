import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
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
        price_per_device: undefined,
        min_devices: 1,
        currency: 'USD',
        billing_cycle: 'yearly',
        is_trial: false,
        trial_days: 30,
        is_active: true,
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
                name: formData.name,
                slug,
                description: formData.description,
                is_trial: true,
                trial_days: formData.trial_days || 30,
                is_active: formData.is_active,
            });
        } else {
            // Calculate total price from price_per_device * min_devices
            const pricePerDevice = formData.price_per_device || 0;
            const minDevices = formData.min_devices || 1;
            const price = Math.round(pricePerDevice * minDevices * 100); // Convert to cents

            createMutation.mutate({
                ...formData,
                slug,
                price,
                price_per_device: Math.round(pricePerDevice * 100), // Convert to cents
                min_devices: minDevices,
                trial_days: undefined, // Clear trial_days for non-trial plans
            });
        }
    };

    // Calculate displayed total price (only for non-trial plans)
    const pricePerDevice = formData.price_per_device || 0;
    const minDevices = formData.min_devices || 1;
    const totalPrice = formData.is_trial ? 0 : pricePerDevice * minDevices;

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
                            <>
                                <div className="grid gap-4 sm:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="price_per_device">Price per Device (per year)</Label>
                                        <Input
                                            id="price_per_device"
                                            type="number"
                                            step="0.01"
                                            min="0"
                                            value={formData.price_per_device || ''}
                                            onChange={(e) =>
                                                setFormData((prev) => ({
                                                    ...prev,
                                                    price_per_device: parseFloat(e.target.value) || undefined,
                                                }))
                                            }
                                            placeholder="49.00"
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            Price charged per device per billing cycle
                                        </p>
                                    </div>

                                    <div className="space-y-2">
                                        <Label htmlFor="min_devices">Minimum Devices *</Label>
                                        <Input
                                            id="min_devices"
                                            type="number"
                                            min="1"
                                            value={formData.min_devices || ''}
                                            onChange={(e) => {
                                                const value = e.target.value;
                                                setFormData((prev) => ({
                                                    ...prev,
                                                    min_devices: value === '' ? undefined : parseInt(value, 10),
                                                }));
                                            }}
                                            onBlur={(e) => {
                                                const value = e.target.value;
                                                if (value === '' || isNaN(parseInt(value, 10))) {
                                                    setFormData((prev) => ({
                                                        ...prev,
                                                        min_devices: 1,
                                                    }));
                                                }
                                            }}
                                            placeholder="1"
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            Minimum number of devices required for this plan
                                        </p>
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

                        {totalPrice > 0 && (
                            <div className="rounded-lg border bg-muted/50 p-4">
                                <div className="flex items-center justify-between">
                                    <span className="text-sm font-medium">Minimum Annual Cost</span>
                                    <span className="text-lg font-bold">
                                        ${totalPrice.toFixed(2)} / year
                                    </span>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">
                                    ${pricePerDevice.toFixed(2)}/device × {minDevices} minimum devices
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
