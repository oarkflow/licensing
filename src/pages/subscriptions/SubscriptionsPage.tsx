import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Ban, Bell, FilePlus2, KeyRound, Play, Plus, RefreshCw, Search, WalletCards } from 'lucide-react';
import api from '@/services/api';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import type { Client, CreateSubscriptionRequest, Plan, Product, Subscription } from '@/types/api';

const date = (value?: string) => value ? new Date(value).toLocaleDateString() : '-';

function statusBadge(status: string) {
    switch (status) {
        case 'active':
            return <Badge>Active</Badge>;
        case 'past_due':
            return <Badge variant="secondary">Past Due</Badge>;
        case 'cancelled':
        case 'expired':
            return <Badge variant="destructive">{status.replace('_', ' ')}</Badge>;
        case 'paused':
            return <Badge variant="outline">Paused</Badge>;
        default:
            return <Badge variant="outline">{status || 'unknown'}</Badge>;
    }
}

function shortID(id?: string) {
    if (!id) return '-';
    return id.length > 14 ? `${id.slice(0, 14)}...` : id;
}

export function SubscriptionsPage() {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const [status, setStatus] = useState('all');
    const [search, setSearch] = useState('');
    const [clientID, setClientID] = useState('');
    const [cancelTarget, setCancelTarget] = useState<Subscription | null>(null);
    const [cancelReason, setCancelReason] = useState('');
    const [createOpen, setCreateOpen] = useState(false);
    const [form, setForm] = useState<CreateSubscriptionRequest>({
        email: '',
        product_id: '',
        plan_id: '',
        max_devices: 1,
        quantity: 1,
        collection_method: 'automatic',
        auto_renew: true,
        grace_period_days: 7,
        send_email: true,
        is_trial: false,
    });

    const subscriptionsQuery = useQuery({
        queryKey: ['subscriptions', clientID],
        queryFn: () => api.listSubscriptions(clientID ? { client_id: clientID } : undefined),
    });
    const clientsQuery = useQuery({ queryKey: ['clients'], queryFn: () => api.listClients() });
    const productsQuery = useQuery({ queryKey: ['products'], queryFn: () => api.listProducts() });
    const plansQuery = useQuery({
        queryKey: ['plans', form.product_id],
        queryFn: () => api.listPlans(form.product_id),
        enabled: Boolean(form.product_id),
    });
    const gatewaysQuery = useQuery({ queryKey: ['billing-gateways'], queryFn: () => api.listBillingGateways() });

    const subscriptions = subscriptionsQuery.data?.data || [];
    const clients = clientsQuery.data?.data || [];
    const products = productsQuery.data?.data || [];
    const plans = plansQuery.data?.data || [];
    const gateways = gatewaysQuery.data?.data || [];

    const clientByID = useMemo(() => new Map(clients.map((client: Client) => [client.id, client])), [clients]);
    const productByID = useMemo(() => new Map(products.map((product: Product) => [product.id, product])), [products]);
    const planByID = useMemo(() => new Map(plans.map((plan: Plan) => [plan.id, plan])), [plans]);

    const filteredSubscriptions = subscriptions.filter((sub) => {
        if (status !== 'all' && sub.status !== status) return false;
        if (!search.trim()) return true;
        const needle = search.toLowerCase();
        const client = clientByID.get(sub.client_id);
        const product = productByID.get(sub.product_id);
        return [
            sub.id,
            sub.client_id,
            sub.license_id || '',
            sub.gateway_subscription_id || '',
            client?.email || '',
            client?.username || '',
            product?.name || '',
        ].some((value) => value.toLowerCase().includes(needle));
    });

    const counts = useMemo(() => {
        return subscriptions.reduce<Record<string, number>>((acc, sub) => {
            acc[sub.status || 'unknown'] = (acc[sub.status || 'unknown'] || 0) + 1;
            return acc;
        }, {});
    }, [subscriptions]);

    const refreshSubscriptions = () => {
        queryClient.invalidateQueries({ queryKey: ['subscriptions'] });
        queryClient.invalidateQueries({ queryKey: ['billing-invoices'] });
    };

    const createInvoice = useMutation({
        mutationFn: (subscriptionID: string) => api.createBillingInvoice(subscriptionID),
        onSuccess: (response) => {
            if (!response.success) {
                toast({ title: 'Invoice failed', description: response.error, variant: 'destructive' });
                return;
            }
            refreshSubscriptions();
            toast({ title: 'Invoice generated', description: response.data?.id });
        },
    });

    const createSubscription = useMutation({
        mutationFn: (payload: CreateSubscriptionRequest) => api.createSubscription(payload),
        onSuccess: (response) => {
            if (!response.success || !response.data?.subscription) {
                toast({ title: 'Subscription failed', description: response.error || response.message, variant: 'destructive' });
                return;
            }
            setCreateOpen(false);
            setForm({
                email: '',
                product_id: '',
                plan_id: '',
                max_devices: 1,
                quantity: 1,
                collection_method: 'automatic',
                auto_renew: true,
                grace_period_days: 7,
                send_email: true,
                is_trial: false,
            });
            refreshSubscriptions();
            queryClient.invalidateQueries({ queryKey: ['licenses'] });
            queryClient.invalidateQueries({ queryKey: ['clients'] });
            toast({
                title: 'Subscription created',
                description: response.data.email_sent ? 'Welcome and license email sent or queued.' : response.data.subscription.id,
            });
        },
    });

    const sendNotification = useMutation({
        mutationFn: ({ id, kind }: { id: string; kind: 'renewal_reminder' | 'payment_retry' }) => api.sendSubscriptionNotification(id, kind),
        onSuccess: (response) => {
            if (!response.success) {
                toast({ title: 'Notification failed', description: response.error, variant: 'destructive' });
                return;
            }
            refreshSubscriptions();
            toast({ title: 'Notification queued', description: response.data?.subject });
        },
    });

    const resumeSubscription = useMutation({
        mutationFn: (subscriptionID: string) => api.resumeSubscription(subscriptionID),
        onSuccess: () => {
            refreshSubscriptions();
            toast({ title: 'Subscription resumed' });
        },
    });

    const cancelSubscription = useMutation({
        mutationFn: ({ id, reason }: { id: string; reason: string }) => api.cancelSubscription(id, reason),
        onSuccess: () => {
            setCancelTarget(null);
            setCancelReason('');
            refreshSubscriptions();
            toast({ title: 'Subscription cancelled' });
        },
    });

    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Subscriptions</h1>
                    <p className="text-muted-foreground">Track recurring access, renewal dates, linked licenses, and lifecycle actions.</p>
                </div>
                <div className="flex gap-2">
                    <Button variant="outline" onClick={refreshSubscriptions}>
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Refresh
                    </Button>
                    <Button onClick={() => setCreateOpen(true)}>
                        <Plus className="mr-2 h-4 w-4" />
                        New Subscription
                    </Button>
                </div>
            </div>

            <div className="grid gap-3 md:grid-cols-4">
                {[
                    ['Total', subscriptions.length],
                    ['Active', counts.active || 0],
                    ['Past Due', counts.past_due || 0],
                    ['Cancelled', counts.cancelled || 0],
                ].map(([label, value]) => (
                    <div key={label} className="rounded-md border p-4">
                        <p className="text-xs uppercase text-muted-foreground">{label}</p>
                        <p className="mt-1 text-2xl font-semibold">{value}</p>
                    </div>
                ))}
            </div>

            <div className="rounded-md border p-4">
                <div className="grid gap-3 lg:grid-cols-[1fr_180px_260px]">
                    <div className="relative">
                        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                        <Input
                            value={search}
                            onChange={(event) => setSearch(event.target.value)}
                            placeholder="Search subscription, client, license, or gateway ID"
                            className="pl-9"
                        />
                    </div>
                    <Select value={status} onValueChange={setStatus}>
                        <SelectTrigger>
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">All Status</SelectItem>
                            <SelectItem value="active">Active</SelectItem>
                            <SelectItem value="past_due">Past Due</SelectItem>
                            <SelectItem value="paused">Paused</SelectItem>
                            <SelectItem value="cancelled">Cancelled</SelectItem>
                            <SelectItem value="expired">Expired</SelectItem>
                        </SelectContent>
                    </Select>
                    <Select value={clientID || 'all'} onValueChange={(value) => setClientID(value === 'all' ? '' : value)}>
                        <SelectTrigger>
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">All Clients</SelectItem>
                            {clients.map((client) => (
                                <SelectItem key={client.id} value={client.id}>
                                    {client.email}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                </div>
            </div>

            {subscriptionsQuery.isLoading ? (
                <div className="space-y-2">
                    {[...Array(8)].map((_, index) => (
                        <Skeleton key={index} className="h-14 w-full" />
                    ))}
                </div>
            ) : filteredSubscriptions.length === 0 ? (
                <div className="flex flex-col items-center justify-center rounded-md border border-dashed py-12 text-center">
                    <WalletCards className="h-12 w-12 text-muted-foreground" />
                    <h2 className="mt-4 text-lg font-semibold">No subscriptions found</h2>
                    <p className="mt-2 text-sm text-muted-foreground">Subscriptions appear here after checkout, subscribe, or license provisioning flows create them.</p>
                </div>
            ) : (
                <div className="overflow-hidden rounded-md border">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Subscription</TableHead>
                                <TableHead>Client</TableHead>
                                <TableHead>Product</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead>Renewal</TableHead>
                                <TableHead>Quantity</TableHead>
                                <TableHead className="text-right">Actions</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {filteredSubscriptions.map((sub) => {
                                const client = clientByID.get(sub.client_id);
                                const product = productByID.get(sub.product_id);
                                const canResume = ['cancelled', 'paused', 'past_due'].includes(sub.status);
                                const canCancel = !['cancelled', 'expired'].includes(sub.status);

                                return (
                                    <TableRow key={sub.id}>
                                        <TableCell>
                                            <div className="space-y-1">
                                                <p className="font-mono text-sm">{shortID(sub.id)}</p>
                                                {sub.license_id && (
                                                    <Button asChild size="sm" variant="link" className="h-auto p-0 text-xs">
                                                        <Link to={`/licenses/${sub.license_id}`}>
                                                            <KeyRound className="mr-1 h-3 w-3" />
                                                            Open license
                                                        </Link>
                                                    </Button>
                                                )}
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <Button asChild variant="link" className="h-auto max-w-56 justify-start p-0">
                                                <Link to={`/clients/${sub.client_id}`} className="truncate">
                                                    {client?.email || shortID(sub.client_id)}
                                                </Link>
                                            </Button>
                                        </TableCell>
                                        <TableCell>{product?.name || shortID(sub.product_id)}</TableCell>
                                        <TableCell>{statusBadge(sub.status)}</TableCell>
                                        <TableCell>
                                            <div className="text-sm">
                                                <p>{date(sub.next_billing_date || sub.end_date)}</p>
                                                <p className="text-xs text-muted-foreground">{sub.billing_cycle || 'cycle unknown'}</p>
                                            </div>
                                        </TableCell>
                                        <TableCell>{sub.quantity || 1}</TableCell>
                                        <TableCell>
                                            <div className="flex justify-end gap-1">
                                                <Button size="icon" variant="outline" onClick={() => createInvoice.mutate(sub.id)} disabled={createInvoice.isPending}>
                                                    <FilePlus2 className="h-4 w-4" />
                                                </Button>
                                                <Button
                                                    size="icon"
                                                    variant="outline"
                                                    onClick={() => sendNotification.mutate({
                                                        id: sub.id,
                                                        kind: sub.status === 'past_due' ? 'payment_retry' : 'renewal_reminder',
                                                    })}
                                                    disabled={sendNotification.isPending}
                                                >
                                                    <Bell className="h-4 w-4" />
                                                </Button>
                                                {canResume && (
                                                    <Button size="icon" variant="outline" onClick={() => resumeSubscription.mutate(sub.id)} disabled={resumeSubscription.isPending}>
                                                        <Play className="h-4 w-4" />
                                                    </Button>
                                                )}
                                                {canCancel && (
                                                    <Button size="icon" variant="outline" onClick={() => setCancelTarget(sub)}>
                                                        <Ban className="h-4 w-4" />
                                                    </Button>
                                                )}
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                );
                            })}
                        </TableBody>
                    </Table>
                </div>
            )}

            <Dialog open={Boolean(cancelTarget)} onOpenChange={(open) => !open && setCancelTarget(null)}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Cancel Subscription</DialogTitle>
                    </DialogHeader>
                    <div className="space-y-2">
                        <Label htmlFor="cancel-reason">Reason</Label>
                        <Textarea
                            id="cancel-reason"
                            value={cancelReason}
                            onChange={(event) => setCancelReason(event.target.value)}
                            rows={4}
                            placeholder="Reason shown in audit records"
                        />
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setCancelTarget(null)}>Keep Active</Button>
                        <Button
                            variant="destructive"
                            onClick={() => cancelTarget && cancelSubscription.mutate({ id: cancelTarget.id, reason: cancelReason })}
                            disabled={cancelSubscription.isPending}
                        >
                            Cancel Subscription
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Dialog open={createOpen} onOpenChange={setCreateOpen}>
                <DialogContent className="max-w-2xl">
                    <DialogHeader>
                        <DialogTitle>New Subscription</DialogTitle>
                    </DialogHeader>
                    <form
                        className="space-y-4"
                        onSubmit={(event) => {
                            event.preventDefault();
                            createSubscription.mutate({
                                ...form,
                                gateway_id: form.gateway_id === 'none' ? '' : form.gateway_id,
                                duration_days: form.duration_days || undefined,
                                max_devices: form.max_devices || 1,
                                quantity: form.quantity || form.max_devices || 1,
                                grace_period_days: form.grace_period_days || 7,
                            });
                        }}
                    >
                        <div className="grid gap-3 md:grid-cols-2">
                            <div className="space-y-2">
                                <Label htmlFor="subscription-email">Client Email</Label>
                                <Input
                                    id="subscription-email"
                                    type="email"
                                    value={form.email}
                                    onChange={(event) => setForm((prev) => ({ ...prev, email: event.target.value }))}
                                    required
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="subscription-start">Start Date</Label>
                                <Input
                                    id="subscription-start"
                                    type="date"
                                    value={form.start_date || ''}
                                    onChange={(event) => setForm((prev) => ({ ...prev, start_date: event.target.value || undefined }))}
                                />
                            </div>
                            <div className="space-y-2">
                                <Label>Product</Label>
                                <Select
                                    value={form.product_id}
                                    onValueChange={(value) => setForm((prev) => ({ ...prev, product_id: value, plan_id: '' }))}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select product" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {products.map((product) => (
                                            <SelectItem key={product.id} value={product.id}>{product.name}</SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label>Plan</Label>
                                <Select
                                    value={form.plan_id}
                                    onValueChange={(value) => {
                                        const selectedPlan = planByID.get(value);
                                        setForm((prev) => ({
                                            ...prev,
                                            plan_id: value,
                                            is_trial: selectedPlan?.is_trial || prev.is_trial,
                                        }));
                                    }}
                                    disabled={!form.product_id}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder={form.product_id ? 'Select plan' : 'Select product first'} />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {plans.map((plan) => (
                                            <SelectItem key={plan.id} value={plan.id}>{plan.name}</SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="subscription-devices">Max Devices</Label>
                                <Input
                                    id="subscription-devices"
                                    type="number"
                                    min={1}
                                    value={form.max_devices || 1}
                                    onChange={(event) => setForm((prev) => ({
                                        ...prev,
                                        max_devices: Number(event.target.value),
                                        quantity: prev.quantity || Number(event.target.value),
                                    }))}
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="subscription-quantity">Billing Quantity</Label>
                                <Input
                                    id="subscription-quantity"
                                    type="number"
                                    min={1}
                                    value={form.quantity || 1}
                                    onChange={(event) => setForm((prev) => ({ ...prev, quantity: Number(event.target.value) }))}
                                />
                            </div>
                            <div className="space-y-2">
                                <Label>Collection Method</Label>
                                <Select
                                    value={form.collection_method || 'automatic'}
                                    onValueChange={(value) => setForm((prev) => ({ ...prev, collection_method: value }))}
                                >
                                    <SelectTrigger>
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="automatic">Automatic</SelectItem>
                                        <SelectItem value="manual">Manual</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label>Gateway</Label>
                                <Select
                                    value={form.gateway_id || 'none'}
                                    onValueChange={(value) => setForm((prev) => ({ ...prev, gateway_id: value === 'none' ? undefined : value }))}
                                >
                                    <SelectTrigger>
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="none">No gateway</SelectItem>
                                        {gateways.map((gateway) => (
                                            <SelectItem key={gateway.id} value={gateway.id}>
                                                {gateway.name} ({gateway.provider})
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="subscription-duration">Duration Override Days</Label>
                                <Input
                                    id="subscription-duration"
                                    type="number"
                                    min={0}
                                    value={form.duration_days || ''}
                                    onChange={(event) => setForm((prev) => ({ ...prev, duration_days: Number(event.target.value) || undefined }))}
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="subscription-grace">Grace Period Days</Label>
                                <Input
                                    id="subscription-grace"
                                    type="number"
                                    min={0}
                                    value={form.grace_period_days || 7}
                                    onChange={(event) => setForm((prev) => ({ ...prev, grace_period_days: Number(event.target.value) }))}
                                />
                            </div>
                        </div>
                        <div className="grid gap-3 md:grid-cols-3">
                            {[
                                ['auto_renew', 'Auto Renew'],
                                ['send_email', 'Send Emails'],
                                ['is_trial', 'Trial'],
                            ].map(([key, label]) => (
                                <label key={key} className="flex items-center justify-between rounded-md border p-3 text-sm">
                                    <span>{label}</span>
                                    <Switch
                                        checked={Boolean(form[key as keyof CreateSubscriptionRequest])}
                                        onCheckedChange={(checked) => setForm((prev) => ({ ...prev, [key]: checked }))}
                                    />
                                </label>
                            ))}
                        </div>
                        <DialogFooter>
                            <Button type="button" variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
                            <Button type="submit" disabled={createSubscription.isPending || !form.email || !form.product_id || !form.plan_id}>
                                Create Subscription
                            </Button>
                        </DialogFooter>
                    </form>
                </DialogContent>
            </Dialog>
        </div>
    );
}
