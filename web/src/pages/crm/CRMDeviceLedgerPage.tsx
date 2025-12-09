import { useState } from 'react';
import type { FormEvent } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Fingerprint, Search } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { useToast } from '@/components/ui/use-toast';
import { CRMGuard } from '@/components/crm/CRMAuthGate';
import useCRM from '@/hooks/useCRM';
import crmService from '@/services/crm';
import type { CRMDeviceLedgerRecord } from '@/types/crm';

export function CRMDeviceLedgerPage() {
    const { session } = useCRM();
    const { toast } = useToast();
    const [record, setRecord] = useState<CRMDeviceLedgerRecord | null>(null);

    const mutation = useMutation({
        mutationFn: ({ fingerprint, tenant }: { fingerprint: string; tenant?: string }) =>
            crmService.getDeviceLedger(fingerprint, tenant),
        onSuccess: (data) => {
            setRecord(data);
        },
        onError: (error: unknown) => {
            toast({
                title: 'Lookup failed',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    if (!session) {
        return (
            <CRMGuard
                title="Authenticate to inspect devices"
                description="CRM read scopes required for ledger access."
            >
                {null}
            </CRMGuard>
        );
    }

    const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const formData = new FormData(event.currentTarget);
        const fingerprint = String(formData.get('fingerprint') || '').trim();
        const tenant = String(formData.get('tenant_id') || '').trim();
        if (!fingerprint) {
            toast({
                title: 'Fingerprint required',
                description: 'Provide the device fingerprint you wish to inspect.',
                variant: 'destructive',
            });
            return;
        }
        mutation.mutate({ fingerprint, tenant: tenant || session.tenant.id });
    };

    return (
        <CRMGuard
            title="Authenticate to inspect devices"
            description="CRM read scopes required for ledger access."
        >
            <div className="space-y-8">
                <div className="space-y-3">
                    <Badge variant="secondary" className="rounded-full border bg-muted px-4 py-1 text-xs uppercase tracking-[0.4em]">
                        CRM
                    </Badge>
                    <h1 className="text-4xl font-semibold">Device ledger</h1>
                    <p className="text-muted-foreground">
                        Trace offline identities, revocation epochs, and sync telemetry per device fingerprint.
                    </p>
                </div>

                <Card className="rounded-3xl border bg-card/70">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Fingerprint className="h-5 w-5 text-primary" />
                            Ledger lookup
                        </CardTitle>
                        <CardDescription>Provide the fingerprint and optional tenant override.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form className="grid gap-4 md:grid-cols-3" onSubmit={handleSubmit}>
                            <div className="md:col-span-2 space-y-2">
                                <Input
                                    name="fingerprint"
                                    placeholder="device-fingerprint"
                                    className="rounded-2xl"
                                    required
                                />
                            </div>
                            <div className="space-y-2">
                                <Input
                                    name="tenant_id"
                                    placeholder="Tenant ID (optional)"
                                    defaultValue={session.tenant.id}
                                    className="rounded-2xl"
                                />
                            </div>
                            <div className="md:col-span-3">
                                <Button
                                    type="submit"
                                    className="w-full rounded-2xl"
                                    disabled={mutation.isPending}
                                >
                                    <Search className="mr-2 h-4 w-4" />
                                    {mutation.isPending ? 'Resolving…' : 'Lookup device record'}
                                </Button>
                            </div>
                        </form>
                    </CardContent>
                </Card>

                {record && (
                    <Card className="rounded-3xl border bg-card/60">
                        <CardHeader>
                            <CardTitle>Ledger entry</CardTitle>
                            <CardDescription>Snapshot fetched from CRM storage</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-3 text-sm">
                            <LedgerRow label="Fingerprint" value={record.device_fingerprint} monospace />
                            <LedgerRow label="Tenant" value={record.tenant_id} monospace />
                            <LedgerRow label="Client" value={record.client_id || '—'} />
                            <LedgerRow label="License" value={record.license_id || '—'} />
                            <LedgerRow label="Last seen" value={new Date(record.last_seen_at).toLocaleString()} />
                            <LedgerRow label="Last sync" value={new Date(record.last_sync_at).toLocaleString()} />
                            <LedgerRow label="Pending revocation" value={record.pending_revocation ? 'Yes' : 'No'} />
                            <LedgerRow label="Revocation epoch" value={record.revocation_epoch.toString()} monospace />
                            {record.metadata && (
                                <div>
                                    <div className="text-xs uppercase text-muted-foreground tracking-widest">Metadata</div>
                                    <pre className="mt-2 overflow-x-auto rounded-2xl bg-muted p-4 text-xs">{JSON.stringify(record.metadata, null, 2)}</pre>
                                </div>
                            )}
                        </CardContent>
                    </Card>
                )}
            </div>
        </CRMGuard>
    );
}

function LedgerRow({ label, value, monospace = false }: { label: string; value: string; monospace?: boolean }) {
    return (
        <div className="flex items-center justify-between">
            <span className="text-muted-foreground">{label}</span>
            <span className={monospace ? 'font-mono text-xs' : 'font-medium'}>{value}</span>
        </div>
    );
}

export default CRMDeviceLedgerPage;
