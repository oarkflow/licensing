import { useMemo, useState, type Dispatch, type SetStateAction } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Gift, Plus, Ticket } from 'lucide-react';
import api from '@/services/api';
import type { CouponFeaturePatch, CouponScopePatch, CouponCode, Product, SaveCouponRequest } from '@/types/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { parseMetadataText, stringifyMetadata } from '@/lib/featureMetadata';

type ScopePatchForm = {
    scope_slug: string;
    permission: '' | 'allow' | 'deny' | 'limit';
    limit: string;
    metadataText: string;
};

type FeaturePatchForm = {
    feature_slug: string;
    enabledMode: 'inherit' | 'enable' | 'disable';
    metadataText: string;
    scopes: ScopePatchForm[];
};

type CouponForm = {
    code: string;
    name: string;
    description: string;
    product_id: string;
    allowedClientIDsText: string;
    max_redemptions: string;
    max_redemptions_per_client: string;
    is_active: boolean;
    starts_at: string;
    expires_at: string;
    metadataText: string;
    features: FeaturePatchForm[];
};

const defaultForm = (): CouponForm => ({
    code: '',
    name: '',
    description: '',
    product_id: '',
    allowedClientIDsText: '',
    max_redemptions: '',
    max_redemptions_per_client: '',
    is_active: true,
    starts_at: '',
    expires_at: '',
    metadataText: '',
    features: [],
});

export function AdminCouponsPage() {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const [dialogOpen, setDialogOpen] = useState(false);
    const [editingCoupon, setEditingCoupon] = useState<CouponCode | null>(null);
    const [form, setForm] = useState<CouponForm>(defaultForm);

    const { data: couponsResponse } = useQuery({
        queryKey: ['coupons'],
        queryFn: () => api.listCoupons(),
    });
    const { data: productsResponse } = useQuery({
        queryKey: ['products'],
        queryFn: () => api.listProducts(),
    });

    const coupons = couponsResponse?.data || [];
    const products: Product[] = productsResponse?.data || [];

    const saveMutation = useMutation({
        mutationFn: (payload: SaveCouponRequest) =>
            editingCoupon ? api.updateCoupon(editingCoupon.id, payload) : api.createCoupon(payload),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['coupons'] });
            toast({ title: editingCoupon ? 'Coupon updated' : 'Coupon created' });
            setDialogOpen(false);
            setEditingCoupon(null);
            setForm(defaultForm());
        },
        onError: (error) => {
            toast({
                title: 'Failed to save coupon',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const activeCount = useMemo(() => coupons.filter((item) => item.is_active).length, [coupons]);

    const openCreate = () => {
        setEditingCoupon(null);
        setForm(defaultForm());
        setDialogOpen(true);
    };

    const openEdit = (coupon: CouponCode) => {
        setEditingCoupon(coupon);
        setForm({
            code: coupon.code,
            name: coupon.name,
            description: coupon.description || '',
            product_id: coupon.product_id || '',
            allowedClientIDsText: (coupon.allowed_client_ids || []).join(', '),
            max_redemptions: coupon.max_redemptions ? String(coupon.max_redemptions) : '',
            max_redemptions_per_client: coupon.max_redemptions_per_client ? String(coupon.max_redemptions_per_client) : '',
            is_active: coupon.is_active,
            starts_at: coupon.starts_at ? coupon.starts_at.slice(0, 16) : '',
            expires_at: coupon.expires_at ? coupon.expires_at.slice(0, 16) : '',
            metadataText: stringifyMetadata(coupon.metadata),
            features: (coupon.features || []).map((feature) => ({
                feature_slug: feature.feature_slug || '',
                enabledMode: feature.enabled === undefined ? 'inherit' : feature.enabled ? 'enable' : 'disable',
                metadataText: stringifyMetadata(feature.metadata),
                scopes: (feature.scopes || []).map((scope) => ({
                    scope_slug: scope.scope_slug || '',
                    permission: scope.permission || '',
                    limit: scope.limit ? String(scope.limit) : '',
                    metadataText: stringifyMetadata(scope.metadata),
                })),
            })),
        });
        setDialogOpen(true);
    };

    const submit = () => {
        const payload: SaveCouponRequest = {
            code: form.code.trim(),
            name: form.name.trim(),
            description: form.description.trim() || undefined,
            product_id: form.product_id || undefined,
            allowed_client_ids: form.allowedClientIDsText
                .split(',')
                .map((value) => value.trim())
                .filter(Boolean),
            max_redemptions: form.max_redemptions ? Number(form.max_redemptions) : undefined,
            max_redemptions_per_client: form.max_redemptions_per_client ? Number(form.max_redemptions_per_client) : undefined,
            is_active: form.is_active,
            starts_at: form.starts_at ? new Date(form.starts_at).toISOString() : undefined,
            expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : undefined,
            metadata: parseMetadataText(form.metadataText),
            features: form.features.map<CouponFeaturePatch>((feature) => ({
                feature_slug: feature.feature_slug.trim(),
                enabled: feature.enabledMode === 'inherit' ? undefined : feature.enabledMode === 'enable',
                metadata: parseMetadataText(feature.metadataText),
                scopes: feature.scopes
                    .filter((scope) => scope.scope_slug.trim())
                    .map<CouponScopePatch>((scope) => ({
                        scope_slug: scope.scope_slug.trim(),
                        permission: scope.permission || undefined,
                        limit: scope.limit ? Number(scope.limit) : undefined,
                        metadata: parseMetadataText(scope.metadataText),
                    })),
            })).filter((feature) => feature.feature_slug),
        };
        saveMutation.mutate(payload);
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Coupon Codes</h1>
                    <p className="text-muted-foreground">Create redeemable entitlement extensions for specific users and licenses.</p>
                </div>
                <Button onClick={openCreate}>
                    <Plus className="mr-2 h-4 w-4" />
                    New Coupon
                </Button>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
                <Card>
                    <CardHeader>
                        <CardTitle>Total Coupons</CardTitle>
                    </CardHeader>
                    <CardContent className="text-3xl font-semibold">{coupons.length}</CardContent>
                </Card>
                <Card>
                    <CardHeader>
                        <CardTitle>Active</CardTitle>
                    </CardHeader>
                    <CardContent className="text-3xl font-semibold">{activeCount}</CardContent>
                </Card>
                <Card>
                    <CardHeader>
                        <CardTitle>Restricted</CardTitle>
                    </CardHeader>
                    <CardContent className="text-3xl font-semibold">{coupons.filter((item) => (item.allowed_client_ids || []).length > 0).length}</CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2"><Gift className="h-5 w-5" /> Coupon Catalog</CardTitle>
                    <CardDescription>Each coupon can extend flags, limits, settings, and scope permissions on top of a user's plan.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    {coupons.length === 0 ? (
                        <div className="rounded-md border border-dashed p-10 text-center text-sm text-muted-foreground">No coupons yet.</div>
                    ) : coupons.map((coupon) => (
                        <button key={coupon.id} className="w-full rounded-xl border p-4 text-left hover:bg-muted/20" onClick={() => openEdit(coupon)}>
                            <div className="flex items-center gap-3">
                                <Ticket className="h-4 w-4 text-primary" />
                                <div className="min-w-0 flex-1">
                                    <div className="flex items-center gap-2">
                                        <span className="font-semibold">{coupon.name}</span>
                                        <Badge variant={coupon.is_active ? 'default' : 'secondary'}>{coupon.is_active ? 'Active' : 'Inactive'}</Badge>
                                        <Badge variant="outline">{coupon.code}</Badge>
                                    </div>
                                    <p className="text-sm text-muted-foreground">{coupon.description || 'No description'}</p>
                                </div>
                                <div className="text-right text-xs text-muted-foreground">
                                    <p>{coupon.features?.length || 0} feature patches</p>
                                    <p>{coupon.allowed_client_ids?.length || 0} client restrictions</p>
                                </div>
                            </div>
                        </button>
                    ))}
                </CardContent>
            </Card>

            <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
                <DialogContent className="max-w-5xl">
                    <DialogHeader>
                        <DialogTitle>{editingCoupon ? 'Edit Coupon' : 'Create Coupon'}</DialogTitle>
                        <DialogDescription>Define who can redeem this code and what entitlement extensions it applies.</DialogDescription>
                    </DialogHeader>
                    <div className="max-h-[70vh] space-y-6 overflow-y-auto pr-2">
                        <div className="grid gap-4 md:grid-cols-2">
                            <div className="space-y-2">
                                <Label>Code</Label>
                                <Input value={form.code} onChange={(e) => setForm((prev) => ({ ...prev, code: e.target.value.toUpperCase() }))} placeholder="SPRING-PLUS" />
                            </div>
                            <div className="space-y-2">
                                <Label>Name</Label>
                                <Input value={form.name} onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))} placeholder="Spring Plus Upgrade" />
                            </div>
                            <div className="space-y-2 md:col-span-2">
                                <Label>Description</Label>
                                <Textarea value={form.description} onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))} rows={2} />
                            </div>
                            <div className="space-y-2">
                                <Label>Product</Label>
                                <Select value={form.product_id || '__all__'} onValueChange={(value) => setForm((prev) => ({ ...prev, product_id: value === '__all__' ? '' : value }))}>
                                    <SelectTrigger><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="__all__">All products</SelectItem>
                                        {products.map((product) => <SelectItem key={product.id} value={product.id}>{product.name}</SelectItem>)}
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label>Allowed Client IDs</Label>
                                <Input value={form.allowedClientIDsText} onChange={(e) => setForm((prev) => ({ ...prev, allowedClientIDsText: e.target.value }))} placeholder="client-1, client-2" />
                            </div>
                            <div className="space-y-2">
                                <Label>Max Redemptions</Label>
                                <Input type="number" min="0" value={form.max_redemptions} onChange={(e) => setForm((prev) => ({ ...prev, max_redemptions: e.target.value }))} />
                            </div>
                            <div className="space-y-2">
                                <Label>Max Per Client</Label>
                                <Input type="number" min="0" value={form.max_redemptions_per_client} onChange={(e) => setForm((prev) => ({ ...prev, max_redemptions_per_client: e.target.value }))} />
                            </div>
                            <div className="space-y-2">
                                <Label>Starts At</Label>
                                <Input type="datetime-local" value={form.starts_at} onChange={(e) => setForm((prev) => ({ ...prev, starts_at: e.target.value }))} />
                            </div>
                            <div className="space-y-2">
                                <Label>Expires At</Label>
                                <Input type="datetime-local" value={form.expires_at} onChange={(e) => setForm((prev) => ({ ...prev, expires_at: e.target.value }))} />
                            </div>
                            <div className="space-y-2 md:col-span-2">
                                <Label>Coupon Metadata</Label>
                                <Textarea value={form.metadataText} onChange={(e) => setForm((prev) => ({ ...prev, metadataText: e.target.value }))} rows={4} className="font-mono text-xs" placeholder={'flag:campaign=true\nsetting:source=spring_launch'} />
                            </div>
                        </div>

                        <div className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h3 className="font-semibold">Feature Patches</h3>
                                    <p className="text-sm text-muted-foreground">Target plan features by slug and add extensions.</p>
                                </div>
                                <Button type="button" variant="outline" onClick={() => setForm((prev) => ({ ...prev, features: [...prev.features, { feature_slug: '', enabledMode: 'inherit', metadataText: '', scopes: [] }] }))}>
                                    <Plus className="mr-2 h-4 w-4" /> Add Feature Patch
                                </Button>
                            </div>
                            {form.features.map((feature, featureIndex) => (
                                <div key={featureIndex} className="rounded-xl border p-4 space-y-4">
                                    <div className="grid gap-4 md:grid-cols-3">
                                        <div className="space-y-2">
                                            <Label>Feature Slug</Label>
                                            <Input value={feature.feature_slug} onChange={(e) => setForm((prev) => ({
                                                ...prev,
                                                features: prev.features.map((item, idx) => idx === featureIndex ? { ...item, feature_slug: e.target.value } : item),
                                            }))} placeholder="api" />
                                        </div>
                                        <div className="space-y-2">
                                            <Label>Enabled Mode</Label>
                                            <Select value={feature.enabledMode} onValueChange={(value: 'inherit' | 'enable' | 'disable') => setForm((prev) => ({
                                                ...prev,
                                                features: prev.features.map((item, idx) => idx === featureIndex ? { ...item, enabledMode: value } : item),
                                            }))}>
                                                <SelectTrigger><SelectValue /></SelectTrigger>
                                                <SelectContent>
                                                    <SelectItem value="inherit">Inherit</SelectItem>
                                                    <SelectItem value="enable">Enable</SelectItem>
                                                    <SelectItem value="disable">Disable</SelectItem>
                                                </SelectContent>
                                            </Select>
                                        </div>
                                        <div className="flex items-end justify-end">
                                            <Button type="button" variant="ghost" onClick={() => setForm((prev) => ({ ...prev, features: prev.features.filter((_, idx) => idx !== featureIndex) }))}>Remove</Button>
                                        </div>
                                        <div className="space-y-2 md:col-span-3">
                                            <Label>Feature Metadata</Label>
                                            <Textarea value={feature.metadataText} onChange={(e) => setForm((prev) => ({
                                                ...prev,
                                                features: prev.features.map((item, idx) => idx === featureIndex ? { ...item, metadataText: e.target.value } : item),
                                            }))} rows={4} className="font-mono text-xs" placeholder={'flag:beta=true\nlimit:seats=10\nusage:events:limit=1000'} />
                                        </div>
                                    </div>
                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between">
                                            <Label>Scope Overrides</Label>
                                            <Button type="button" size="sm" variant="outline" onClick={() => setForm((prev) => ({
                                                ...prev,
                                                features: prev.features.map((item, idx) => idx === featureIndex ? { ...item, scopes: [...item.scopes, { scope_slug: '', permission: '', limit: '', metadataText: '' }] } : item),
                                            }))}>Add Scope</Button>
                                        </div>
                                        {feature.scopes.map((scope, scopeIndex) => (
                                            <div key={scopeIndex} className="grid gap-3 rounded-lg border p-3 md:grid-cols-4">
                                                <div className="space-y-2">
                                                    <Label>Scope Slug</Label>
                                                    <Input value={scope.scope_slug} onChange={(e) => updateScopePatch(setForm, featureIndex, scopeIndex, { scope_slug: e.target.value })} placeholder="create" />
                                                </div>
                                                <div className="space-y-2">
                                                    <Label>Permission</Label>
                                                    <Select value={scope.permission || '__none__'} onValueChange={(value) => updateScopePatch(setForm, featureIndex, scopeIndex, { permission: value === '__none__' ? '' : value as ScopePatchForm['permission'] })}>
                                                        <SelectTrigger><SelectValue /></SelectTrigger>
                                                        <SelectContent>
                                                            <SelectItem value="__none__">No change</SelectItem>
                                                            <SelectItem value="allow">Allow</SelectItem>
                                                            <SelectItem value="deny">Deny</SelectItem>
                                                            <SelectItem value="limit">Limit</SelectItem>
                                                        </SelectContent>
                                                    </Select>
                                                </div>
                                                <div className="space-y-2">
                                                    <Label>Limit</Label>
                                                    <Input type="number" min="0" value={scope.limit} onChange={(e) => updateScopePatch(setForm, featureIndex, scopeIndex, { limit: e.target.value })} />
                                                </div>
                                                <div className="flex items-end justify-end">
                                                    <Button type="button" variant="ghost" onClick={() => removeScopePatch(setForm, featureIndex, scopeIndex)}>Remove</Button>
                                                </div>
                                                <div className="space-y-2 md:col-span-4">
                                                    <Label>Scope Metadata</Label>
                                                    <Textarea value={scope.metadataText} onChange={(e) => updateScopePatch(setForm, featureIndex, scopeIndex, { metadataText: e.target.value })} rows={3} className="font-mono text-xs" placeholder={'flag:extended=true\nlimit:rows=500'} />
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
                        <Button onClick={submit} disabled={saveMutation.isPending || !form.code.trim() || !form.name.trim()}>
                            {saveMutation.isPending ? 'Saving...' : editingCoupon ? 'Save Coupon' : 'Create Coupon'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}

function updateScopePatch(
    setForm: Dispatch<SetStateAction<CouponForm>>,
    featureIndex: number,
    scopeIndex: number,
    patch: Partial<ScopePatchForm>
) {
    setForm((prev) => ({
        ...prev,
        features: prev.features.map((feature, idx) => idx !== featureIndex ? feature : {
            ...feature,
            scopes: feature.scopes.map((scope, innerIdx) => innerIdx !== scopeIndex ? scope : { ...scope, ...patch }),
        }),
    }));
}

function removeScopePatch(
    setForm: Dispatch<SetStateAction<CouponForm>>,
    featureIndex: number,
    scopeIndex: number
) {
    setForm((prev) => ({
        ...prev,
        features: prev.features.map((feature, idx) => idx !== featureIndex ? feature : {
            ...feature,
            scopes: feature.scopes.filter((_, innerIdx) => innerIdx !== scopeIndex),
        }),
    }));
}
