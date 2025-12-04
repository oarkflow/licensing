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
        price_per_device: undefined,
        min_devices: 1,
        currency: 'USD',
        billing_cycle: 'yearly',
    });

    useEffect(() => {
        if (planResponse?.data) {
            setFormData({
                name: planResponse.data.name,
                slug: planResponse.data.slug,
                description: planResponse.data.description || '',
                // Convert from cents to dollars for display
                price_per_device: planResponse.data.price_per_device ? planResponse.data.price_per_device / 100 : undefined,
                min_devices: planResponse.data.min_devices || 1,
                currency: planResponse.data.currency || 'USD',
                billing_cycle: planResponse.data.billing_cycle || 'yearly',
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
        // Calculate total price from price_per_device * min_devices
        const pricePerDevice = formData.price_per_device || 0;
        const minDevices = formData.min_devices || 1;
        const price = Math.round(pricePerDevice * minDevices * 100); // Convert to cents

        updateMutation.mutate({
            ...formData,
            price,
            price_per_device: Math.round(pricePerDevice * 100), // Convert to cents
            min_devices: minDevices,
        });
    };

    if (isLoading) {
        return (
            <div className="space-y-6">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
            </div>
        );
    }

    // Calculate displayed total price
    const pricePerDevice = formData.price_per_device || 0;
    const minDevices = formData.min_devices || 1;
    const totalPrice = pricePerDevice * minDevices;

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
                                    value={formData.min_devices || 1}
                                    onChange={(e) =>
                                        setFormData((prev) => ({
                                            ...prev,
                                            min_devices: parseInt(e.target.value) || 1,
                                        }))
                                    }
                                    placeholder="1"
                                />
                                <p className="text-xs text-muted-foreground">
                                    Minimum number of devices required for this plan
                                </p>
                            </div>
                        </div>

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
