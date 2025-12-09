import { useState } from 'react';
import type { FormEvent } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Bot, Copy, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';
import { CRMGuard } from '@/components/crm/CRMAuthGate';
import useCRM from '@/hooks/useCRM';
import crmService from '@/services/crm';
import type { CRMServiceAccountResponse } from '@/types/crm';

export function CRMServiceAccountsPage() {
    const { session } = useCRM();
    const { toast } = useToast();
    const [latest, setLatest] = useState<CRMServiceAccountResponse | null>(null);

    const mutation = useMutation({
        mutationFn: ({
            tenant_id,
            name,
            description,
            scopes,
        }: {
            tenant_id: string;
            name: string;
            description?: string;
            scopes: string[];
        }) => crmService.createServiceAccount({ tenant_id, name, description, scopes }),
        onSuccess: (response) => {
            setLatest(response);
            toast({
                title: 'Service account created',
                description: `${response.name} ready for automation flows.`,
            });
        },
        onError: (error: unknown) => {
            toast({
                title: 'Creation failed',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    if (!session) {
        return (
            <CRMGuard
                title="Authenticate to mint service accounts"
                description="CRM write scopes required for automation credentials."
            >
                {null}
            </CRMGuard>
        );
    }

    const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const formData = new FormData(event.currentTarget);
        const tenantId = String(formData.get('tenant_id') || session.tenant.id || '').trim();
        const name = String(formData.get('name') || '').trim();
        const description = String(formData.get('description') || '').trim();
        const scopesRaw = String(formData.get('scopes') || '').trim();
        if (!tenantId || !name || !scopesRaw) {
            toast({
                title: 'Missing fields',
                description: 'Tenant, name, and scopes are mandatory.',
                variant: 'destructive',
            });
            return;
        }
        const scopes = scopesRaw
            .split(/\s|,/)
            .map((scope) => scope.trim())
            .filter(Boolean);
        mutation.mutate({ tenant_id: tenantId, name, description, scopes });
    };

    return (
        <CRMGuard
            title="Authenticate to mint service accounts"
            description="CRM write scopes required for automation credentials."
        >
            <div className="space-y-8">
                <div className="space-y-3">
                    <Badge variant="secondary" className="rounded-full border bg-muted px-4 py-1 text-xs uppercase tracking-[0.4em]">
                        CRM
                    </Badge>
                    <h1 className="text-4xl font-semibold">Service accounts</h1>
                    <p className="text-muted-foreground">
                        Create scoped machine identities for CI, partners, or integration hubs.
                    </p>
                </div>

                <Card className="rounded-3xl border bg-card/70">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Bot className="h-5 w-5 text-primary" />
                            Credential manifest
                        </CardTitle>
                        <CardDescription>Compose the scopes and metadata for the automation identity.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form className="grid gap-6 lg:grid-cols-2" onSubmit={handleSubmit}>
                            <div className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="tenant_id">Tenant ID</Label>
                                    <Input id="tenant_id" name="tenant_id" defaultValue={session.tenant.id} required />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="name">Account name</Label>
                                    <Input id="name" name="name" placeholder="billing-automation" required />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="description">Description</Label>
                                    <Textarea id="description" name="description" rows={4} placeholder="Automation for invoice sync" />
                                </div>
                            </div>
                            <div className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="scopes">Scopes (space or comma separated)</Label>
                                    <Textarea id="scopes" name="scopes" rows={6} placeholder="crm:read crm:write licensing:manage" required />
                                </div>
                                <Button
                                    type="submit"
                                    className="w-full rounded-2xl"
                                    disabled={mutation.isPending}
                                >
                                    {mutation.isPending ? 'Minting…' : 'Create service account'}
                                </Button>
                            </div>
                        </form>
                    </CardContent>
                </Card>

                {latest && (
                    <Card className="rounded-3xl border bg-card/60">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <ShieldCheck className="h-5 w-5 text-primary" />
                                Newly minted credentials
                            </CardTitle>
                            <CardDescription>Copy the secret now— it is shown once.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-3 text-sm">
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Account</span>
                                <span className="font-medium">{latest.name}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Tenant</span>
                                <span className="font-mono text-xs">{latest.tenant_id}</span>
                            </div>
                            <div>
                                <div className="text-xs uppercase text-muted-foreground tracking-widest">Secret</div>
                                <div className="mt-2 flex items-center gap-2 rounded-2xl border bg-muted px-3 py-2 font-mono text-xs">
                                    <span className="flex-1 truncate">{latest.secret}</span>
                                    <Button
                                        type="button"
                                        size="icon"
                                        variant="ghost"
                                        onClick={() => {
                                            if (typeof navigator !== 'undefined' && navigator.clipboard) {
                                                navigator.clipboard.writeText(latest.secret);
                                                toast({ title: 'Secret copied' });
                                            }
                                        }}
                                    >
                                        <Copy className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                )}
            </div>
        </CRMGuard>
    );
}

export default CRMServiceAccountsPage;
