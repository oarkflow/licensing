import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, CreditCard, Play, Plus, RefreshCw, Search, X } from 'lucide-react';
import api from '@/services/api';
import type { BillingInvoice, PaymentGatewayConfig } from '@/types/api';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/hooks/use-toast';

const cents = (amount: number, currency: string) =>
    new Intl.NumberFormat(undefined, { style: 'currency', currency: currency || 'USD' }).format((amount || 0) / 100);

const date = (value?: string) => value ? new Date(value).toLocaleDateString() : '-';

export function AdminBillingPage() {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const [gatewayOpen, setGatewayOpen] = useState(false);
    const [invoiceFilter, setInvoiceFilter] = useState({ subscription_id: '', client_id: '' });
    const [gatewayForm, setGatewayForm] = useState({
        name: '',
        provider: 'manual',
        environment: 'test',
        enabled: true,
        supports_recurring: true,
        requires_approval: false,
    });

    const gatewaysQuery = useQuery({ queryKey: ['billing-gateways'], queryFn: () => api.listBillingGateways() });
    const approvalsQuery = useQuery({ queryKey: ['billing-approvals'], queryFn: () => api.listBillingApprovals('pending') });
    const invoicesQuery = useQuery({
        queryKey: ['billing-invoices', invoiceFilter],
        queryFn: () => api.listBillingInvoices(invoiceFilter),
        enabled: Boolean(invoiceFilter.subscription_id || invoiceFilter.client_id),
    });

    const gateways = gatewaysQuery.data?.data || [];
    const approvals = approvalsQuery.data?.data || [];
    const invoices = invoicesQuery.data?.data || [];

    const createGateway = useMutation({
        mutationFn: (payload: Partial<PaymentGatewayConfig>) => api.createBillingGateway(payload),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['billing-gateways'] });
            setGatewayOpen(false);
            setGatewayForm({ name: '', provider: 'manual', environment: 'test', enabled: true, supports_recurring: true, requires_approval: false });
            toast({ title: 'Gateway saved' });
        },
    });

    const runJob = useMutation({
        mutationFn: (action: 'generate_invoices' | 'process_due' | 'queue_reminders') => api.runBillingJob(action),
        onSuccess: (res) => {
            toast({ title: 'Billing job complete', description: JSON.stringify(res.data) });
            queryClient.invalidateQueries({ queryKey: ['billing-invoices'] });
            queryClient.invalidateQueries({ queryKey: ['billing-approvals'] });
        },
    });

    const payInvoice = useMutation({
        mutationFn: (invoice: BillingInvoice) => api.markBillingInvoicePaid(invoice.id),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['billing-invoices'] });
            toast({ title: 'Invoice marked paid' });
        },
    });

    const decideApproval = useMutation({
        mutationFn: ({ id, action }: { id: string; action: 'approve' | 'reject' }) => api.decideBillingApproval(id, action),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['billing-approvals'] });
            toast({ title: 'Approval updated' });
        },
    });

    return (
        <div className="space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Billing</h1>
                    <p className="text-muted-foreground">Manage recurring collection, approvals, gateways, and invoice operations.</p>
                </div>
                <Button onClick={() => setGatewayOpen(true)}>
                    <Plus className="mr-2 h-4 w-4" />
                    Gateway
                </Button>
            </div>

            <div className="grid gap-3 md:grid-cols-3">
                {[
                    ['generate_invoices', 'Generate Invoices'],
                    ['process_due', 'Process Due'],
                    ['queue_reminders', 'Queue Reminders'],
                ].map(([action, label]) => (
                    <Button key={action} variant="outline" onClick={() => runJob.mutate(action as 'generate_invoices' | 'process_due' | 'queue_reminders')}>
                        <Play className="mr-2 h-4 w-4" />
                        {label}
                    </Button>
                ))}
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0">
                        <CardTitle className="text-base">Gateways</CardTitle>
                        <RefreshCw className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Name</TableHead>
                                    <TableHead>Provider</TableHead>
                                    <TableHead>Status</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {gateways.map((gateway) => (
                                    <TableRow key={gateway.id}>
                                        <TableCell className="font-medium">{gateway.name}</TableCell>
                                        <TableCell>{gateway.provider}</TableCell>
                                        <TableCell>
                                            <Badge variant={gateway.enabled ? 'default' : 'secondary'}>{gateway.enabled ? 'enabled' : 'disabled'}</Badge>
                                        </TableCell>
                                    </TableRow>
                                ))}
                                {gateways.length === 0 && (
                                    <TableRow><TableCell colSpan={3} className="text-muted-foreground">No gateways configured.</TableCell></TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle className="text-base">Approval Queue</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                        {approvals.map((approval) => (
                            <div key={approval.id} className="flex items-center justify-between gap-3 border-b pb-2 last:border-0">
                                <div className="min-w-0">
                                    <p className="truncate text-sm font-medium">{approval.subject_type}: {approval.subject_id}</p>
                                    <p className="truncate text-xs text-muted-foreground">{approval.reason || approval.client_id || 'Pending decision'}</p>
                                </div>
                                <div className="flex gap-1">
                                    <Button size="icon" variant="outline" onClick={() => decideApproval.mutate({ id: approval.id, action: 'approve' })}>
                                        <Check className="h-4 w-4" />
                                    </Button>
                                    <Button size="icon" variant="outline" onClick={() => decideApproval.mutate({ id: approval.id, action: 'reject' })}>
                                        <X className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>
                        ))}
                        {approvals.length === 0 && <p className="text-sm text-muted-foreground">No pending approvals.</p>}
                    </CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle className="text-base">Invoices</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="grid gap-2 md:grid-cols-[1fr_1fr_auto]">
                        <Input placeholder="Subscription ID" value={invoiceFilter.subscription_id} onChange={(e) => setInvoiceFilter((prev) => ({ ...prev, subscription_id: e.target.value }))} />
                        <Input placeholder="Client ID" value={invoiceFilter.client_id} onChange={(e) => setInvoiceFilter((prev) => ({ ...prev, client_id: e.target.value }))} />
                        <Button variant="outline" onClick={() => invoicesQuery.refetch()}>
                            <Search className="mr-2 h-4 w-4" />
                            Search
                        </Button>
                    </div>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Invoice</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead>Amount</TableHead>
                                <TableHead>Due</TableHead>
                                <TableHead className="text-right">Action</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {invoices.map((invoice) => (
                                <TableRow key={invoice.id}>
                                    <TableCell className="font-mono text-xs">{invoice.id}</TableCell>
                                    <TableCell><Badge variant={invoice.status === 'paid' ? 'default' : 'secondary'}>{invoice.status}</Badge></TableCell>
                                    <TableCell>{cents(invoice.total_amount, invoice.currency)}</TableCell>
                                    <TableCell>{date(invoice.due_at)}</TableCell>
                                    <TableCell className="text-right">
                                        {invoice.status !== 'paid' && (
                                            <Button size="sm" variant="outline" onClick={() => payInvoice.mutate(invoice)}>
                                                <CreditCard className="mr-2 h-4 w-4" />
                                                Paid
                                            </Button>
                                        )}
                                    </TableCell>
                                </TableRow>
                            ))}
                            {invoices.length === 0 && (
                                <TableRow><TableCell colSpan={5} className="text-muted-foreground">Search by subscription or client to view invoices.</TableCell></TableRow>
                            )}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>

            <Dialog open={gatewayOpen} onOpenChange={setGatewayOpen}>
                <DialogContent>
                    <DialogHeader><DialogTitle>Billing Gateway</DialogTitle></DialogHeader>
                    <div className="grid gap-4 py-2">
                        <div className="grid gap-2">
                            <Label>Name</Label>
                            <Input value={gatewayForm.name} onChange={(e) => setGatewayForm((prev) => ({ ...prev, name: e.target.value }))} />
                        </div>
                        <div className="grid gap-2">
                            <Label>Provider</Label>
                            <Select value={gatewayForm.provider} onValueChange={(provider) => setGatewayForm((prev) => ({ ...prev, provider }))}>
                                <SelectTrigger><SelectValue /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="manual">Manual</SelectItem>
                                    <SelectItem value="stripe">Stripe</SelectItem>
                                    <SelectItem value="paypal">PayPal</SelectItem>
                                    <SelectItem value="razorpay">Razorpay</SelectItem>
                                    <SelectItem value="esewa">eSewa</SelectItem>
                                    <SelectItem value="khalti">Khalti</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="flex items-center justify-between">
                            <Label>Requires approval</Label>
                            <Switch checked={gatewayForm.requires_approval} onCheckedChange={(requires_approval) => setGatewayForm((prev) => ({ ...prev, requires_approval }))} />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button onClick={() => createGateway.mutate(gatewayForm)}>Save</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
