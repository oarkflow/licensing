import { useState } from 'react';
import type { FormEvent } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { KeyRound, ShieldAlert, Sparkles, TimerReset } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';
import { CRMGuard } from '@/components/crm/CRMAuthGate';
import useCRM from '@/hooks/useCRM';
import crmService from '@/services/crm';
import type { CRMEntitlementResponse, CRMFeatureOverride, CRMProductAccess } from '@/types/crm';

export function CRMEntitlementsPage() {
    const { session } = useCRM();
    const { toast } = useToast();
    const [overridesText, setOverridesText] = useState('');
    const [result, setResult] = useState<CRMEntitlementResponse | null>(null);

    const tenantId = session?.tenant.id;

    const { data: products } = useQuery({
        queryKey: ['crm-tenant-products', tenantId],
        queryFn: () => (tenantId ? crmService.listTenantProducts(tenantId) : Promise.resolve([] as CRMProductAccess[])),
        enabled: Boolean(tenantId),
    });

    const mutation = useMutation({
        mutationFn: crmService.assignEntitlement.bind(crmService),
        onSuccess: (response) => {
            setResult(response);
            toast({
                title: 'Entitlement recorded',
                description: `Binding ${response.binding_id} saved with status ${response.status}.`,
            });
        },
        onError: (error: unknown) => {
            toast({
                title: 'Assignment failed',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    if (!session) {
        return (
            <CRMGuard
                title="Authenticate to manage entitlements"
                description="CRM write scopes are required to bind products."
            >
                {null}
            </CRMGuard>
        );
    }

    const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const formData = new FormData(event.currentTarget);
        let overrides: Record<string, CRMFeatureOverride> | undefined;
        if (overridesText.trim()) {
            try {
                overrides = JSON.parse(overridesText) as Record<string, CRMFeatureOverride>;
            } catch (error) {
                toast({
                    title: 'Invalid overrides payload',
                    description: error instanceof Error ? error.message : 'Ensure valid JSON',
                    variant: 'destructive',
                });
                return;
            }
        }
        const tenantValue = String(formData.get('tenant_id') || tenantId || '');
        const productValue = String(formData.get('product_id') || '').trim();
        if (!tenantValue) {
            toast({
                title: 'Tenant required',
                description: 'Provide a tenant id to scope the binding.',
                variant: 'destructive',
            });
            return;
        }
        if (!productValue) {
            toast({
                title: 'Product required',
                description: 'Provide the product id you want to entitle.',
                variant: 'destructive',
            });
            return;
        }
        mutation.mutate({
            tenant_id: tenantValue,
            contact_id: String(formData.get('contact_id') || ''),
            client_id: String(formData.get('client_id') || ''),
            product_id: productValue,
            plan_id: String(formData.get('plan_id') || ''),
            plan_slug: String(formData.get('plan_slug') || ''),
            effective_at: String(formData.get('effective_at') || ''),
            expires_at: String(formData.get('expires_at') || ''),
            feature_overrides: overrides,
        });
    };

    return (
        <CRMGuard
            title="Authenticate to manage entitlements"
            description="CRM write scopes are required to bind products."
        >
            <div className="space-y-8">
                <div className="space-y-3">
                    <Badge variant="secondary" className="rounded-full border bg-muted px-4 py-1 text-xs uppercase tracking-[0.4em]">
                        CRM
                    </Badge>
                    <div>
                        <h1 className="text-4xl font-semibold">Entitlement orchestrator</h1>
                        <p className="text-muted-foreground">
                            Attach products and plans to tenants, contacts, or devices with scoped overrides.
                        </p>
                    </div>
                </div>

                <Card className="rounded-3xl border bg-card/70">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <KeyRound className="h-5 w-5 text-primary" />
                            Assignment payload
                        </CardTitle>
                        <CardDescription>Define the product binding and optional override payload.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form className="grid gap-6 lg:grid-cols-2" onSubmit={handleSubmit}>
                            <div className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="tenant_id">Tenant ID</Label>
                                    <Input id="tenant_id" name="tenant_id" defaultValue={tenantId} required />
                                </div>
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="contact_id">Contact ID</Label>
                                        <Input id="contact_id" name="contact_id" placeholder="Optional" />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="client_id">Client ID</Label>
                                        <Input id="client_id" name="client_id" placeholder="Optional" />
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="product_id">Product ID</Label>
                                    <Input id="product_id" name="product_id" placeholder="prod_123" required />
                                </div>
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="plan_id">Plan ID</Label>
                                        <Input id="plan_id" name="plan_id" placeholder="plan_123" />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="plan_slug">Plan slug</Label>
                                        <Input id="plan_slug" name="plan_slug" placeholder="enterprise" />
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="effective_at">Effective at</Label>
                                        <Input id="effective_at" name="effective_at" type="datetime-local" />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="expires_at">Expires at</Label>
                                        <Input id="expires_at" name="expires_at" type="datetime-local" />
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <Label>Feature overrides (JSON)</Label>
                                    <Textarea
                                        rows={6}
                                        value={overridesText}
                                        onChange={(event) => setOverridesText(event.target.value)}
                                        placeholder='{"feature_slug": {"enabled": true}}'
                                    />
                                </div>
                                <Button
                                    type="submit"
                                    className="w-full rounded-2xl"
                                    disabled={mutation.isPending}
                                >
                                    {mutation.isPending ? 'Recording…' : 'Assign entitlement'}
                                </Button>
                            </div>
                        </form>
                    </CardContent>
                </Card>

                <div className="grid gap-6 lg:grid-cols-2">
                    <Card className="rounded-3xl border bg-card/60">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <ShieldAlert className="h-5 w-5 text-primary" />
                                Active bindings snapshot
                            </CardTitle>
                            <CardDescription>References from the current tenant graph.</CardDescription>
                        </CardHeader>
                        <CardContent>
                            {products && products.length > 0 ? (
                                <div className="rounded-3xl border">
                                    <Table>
                                        <TableHeader>
                                            <TableRow>
                                                <TableHead>Product</TableHead>
                                                <TableHead>Plan</TableHead>
                                                <TableHead>Status</TableHead>
                                            </TableRow>
                                        </TableHeader>
                                        <TableBody>
                                            {products.slice(0, 6).map((product) => (
                                                <TableRow key={`${product.product_id}-${product.plan_id}`}>
                                                    <TableCell>{product.product_slug || product.product_id}</TableCell>
                                                    <TableCell>{product.plan_slug || product.plan_id}</TableCell>
                                                    <TableCell>
                                                        <Badge variant="outline" className="capitalize">
                                                            {product.status}
                                                        </Badge>
                                                    </TableCell>
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </div>
                            ) : (
                                <p className="text-sm text-muted-foreground">No existing bindings to display.</p>
                            )}
                        </CardContent>
                    </Card>

                    <Card className="rounded-3xl border bg-card/60">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <TimerReset className="h-5 w-5 text-primary" />
                                Result console
                            </CardTitle>
                            <CardDescription>Review the latest server acknowledgement.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                            {result ? (
                                <>
                                    <div className="flex items-center justify-between">
                                        <span className="text-muted-foreground">Binding ID</span>
                                        <span className="font-mono text-xs">{result.binding_id}</span>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-muted-foreground">Status</span>
                                        <Badge variant="secondary" className="capitalize">
                                            {result.status}
                                        </Badge>
                                    </div>
                                    <p className="text-muted-foreground">{result.message}</p>
                                </>
                            ) : (
                                <p className="text-muted-foreground">No entitlements recorded yet in this session.</p>
                            )}
                        </CardContent>
                    </Card>
                </div>
            </div>
        </CRMGuard>
    );
}

export default CRMEntitlementsPage;
