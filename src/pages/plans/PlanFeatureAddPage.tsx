import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Plus } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/hooks/use-toast';
import type { Feature, FeatureScope } from '@/types/api';

export function PlanFeatureAddPage() {
    const { productId, planId } = useParams<{
        productId: string;
        planId: string;
    }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const [selectedFeatureId, setSelectedFeatureId] = useState<string>('');
    const [enabled, setEnabled] = useState(true);

    const { data: featuresResponse } = useQuery({
        queryKey: ['features', productId],
        queryFn: () => api.listFeatures(productId!),
        enabled: !!productId,
    });

    const { data: scopesResponse } = useQuery({
        queryKey: ['scopes', productId, selectedFeatureId],
        queryFn: () => api.listScopes(productId!, selectedFeatureId),
        enabled: !!productId && !!selectedFeatureId,
    });

    const features: Feature[] = featuresResponse?.data || [];
    const scopes: FeatureScope[] = scopesResponse?.data || [];
    const selectedFeature = features.find((f) => f.id === selectedFeatureId);

    const addMutation = useMutation({
        mutationFn: () =>
            api.addFeatureToPlan(productId!, planId!, selectedFeatureId, {
                enabled,
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({
                queryKey: ['plan-features', productId, planId],
            });
            toast({ title: 'Feature added to plan' });
            navigate(`/products/${productId}/plans/${planId}`);
        },
        onError: (error) => {
            toast({
                title: 'Failed to add feature',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        addMutation.mutate();
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Add Feature</h1>
                    <p className="text-muted-foreground">
                        Add a feature to this plan
                    </p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Plus className="h-5 w-5" />
                        Select Feature
                    </CardTitle>
                    <CardDescription>
                        Choose a feature to add to the plan
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="feature">Feature *</Label>
                            <Select
                                value={selectedFeatureId}
                                onValueChange={(value) => {
                                    setSelectedFeatureId(value);
                                }}
                            >
                                <SelectTrigger id="feature">
                                    <SelectValue placeholder="Select a feature" />
                                </SelectTrigger>
                                <SelectContent>
                                    {features.map((feature) => (
                                        <SelectItem key={feature.id} value={feature.id}>
                                            {feature.name} ({feature.slug})
                                        </SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>

                        <div className="flex items-center justify-between rounded-md border p-4">
                            <div>
                                <Label className="text-sm font-medium">Feature Enabled</Label>
                                <p className="text-xs text-muted-foreground">
                                    Disable to add the feature but keep it inactive for this plan.
                                </p>
                            </div>
                            <Switch checked={enabled} onCheckedChange={(value) => setEnabled(value)} />
                        </div>

                        {selectedFeature && scopes.length > 0 && (
                            <div className="space-y-3">
                                <Label>Default Scopes</Label>
                                <div className="rounded-md border divide-y">
                                    {scopes.map((scope) => (
                                        <div key={scope.id} className="flex items-center justify-between px-4 py-3">
                                            <div>
                                                <div className="font-medium text-sm">{scope.name}</div>
                                                <div className="text-xs text-muted-foreground font-mono">
                                                    {scope.slug}
                                                </div>
                                            </div>
                                            <span className="text-xs uppercase tracking-wide text-muted-foreground">
                                                {scope.permission}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                                <p className="text-xs text-muted-foreground">
                                    Scope overrides can be configured after the feature is added.
                                </p>
                            </div>
                        )}

                        <div className="flex gap-4">
                            <Button
                                type="submit"
                                disabled={addMutation.isPending || !selectedFeatureId}
                            >
                                {addMutation.isPending ? 'Adding...' : 'Add Feature'}
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
