import { useState } from 'react';
import type { FormEvent } from 'react';
import { useMutation } from '@tanstack/react-query';
import { ArrowLeft, Loader2, ShieldPlus, UserPlus } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';
import { CRMGuard } from '@/components/crm/CRMAuthGate';
import useCRM from '@/hooks/useCRM';
import crmService from '@/services/crm';
import type { CRMTenantView } from '@/types/crm';

const roles = ['owner', 'admin', 'member', 'viewer'] as const;

const parseMetadata = (input: string): Record<string, string> | undefined => {
    const trimmed = input.trim();
    if (!trimmed) return undefined;
    return trimmed.split('\n').reduce<Record<string, string>>((acc, line) => {
        const [key, ...rest] = line.split('=');
        const cleanKey = key.trim();
        if (!cleanKey) return acc;
        acc[cleanKey] = rest.join('=').trim();
        return acc;
    }, {});
};

export function CRMTenantProvisionPage() {
    const { session } = useCRM();
    const { toast } = useToast();
    const [metadataText, setMetadataText] = useState('tier=premium');
    const [role, setRole] = useState<typeof roles[number]>('owner');
    const [lastTenant, setLastTenant] = useState<CRMTenantView | null>(null);

    const mutation = useMutation({
        mutationFn: crmService.provisionTenant.bind(crmService),
        onSuccess: (tenant) => {
            setLastTenant(tenant);
            toast({
                title: 'Tenant provisioned',
                description: `Workspace ${tenant.slug} is live.`,
            });
        },
        onError: (error: unknown) => {
            toast({
                title: 'Provisioning failed',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    if (!session) {
        return (
            <CRMGuard
                title="Authenticate to provision tenants"
                description="Only CRM operators with write scopes can bootstrap workspaces."
            >
                {null}
            </CRMGuard>
        );
    }

    const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const formData = new FormData(event.currentTarget);
        const payload = {
            name: String(formData.get('name')),
            slug: String(formData.get('slug')),
            industry: String(formData.get('industry') || ''),
            region: String(formData.get('region') || ''),
            billing_email: String(formData.get('billing_email') || ''),
            support_email: String(formData.get('support_email') || ''),
            metadata: parseMetadata(metadataText),
            admin_user: {
                email: String(formData.get('admin_email')),
                username: String(formData.get('admin_username')),
                password: String(formData.get('admin_password')),
                role,
            },
        };
        mutation.mutate(payload);
    };

    return (
        <CRMGuard
            title="Authenticate to provision tenants"
            description="Only CRM operators with write scopes can bootstrap workspaces."
        >
            <div className="space-y-8">
                <div className="flex items-center justify-between">
                    <div>
                        <Badge variant="secondary" className="rounded-full border bg-muted px-4 py-1 text-xs uppercase tracking-[0.4em]">
                            CRM
                        </Badge>
                        <h1 className="mt-3 text-4xl font-semibold">Tenant launcher</h1>
                        <p className="text-muted-foreground">
                            Spin up secure workspaces with billing, support, and admin access pre-wired.
                        </p>
                    </div>
                    <Button asChild variant="ghost" className="rounded-2xl">
                        <Link to="/crm">
                            <ArrowLeft className="mr-2 h-4 w-4" />
                            Back to overview
                        </Link>
                    </Button>
                </div>

                <Card className="rounded-3xl border bg-card/70">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <ShieldPlus className="h-5 w-5 text-primary" />
                            Tenant blueprint
                        </CardTitle>
                        <CardDescription>Enter organizational metadata and bootstrap admin credentials.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form className="grid gap-6 lg:grid-cols-2" onSubmit={handleSubmit}>
                            <div className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="name">Tenant name</Label>
                                    <Input id="name" name="name" placeholder="Acme Robotics" required />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="slug">Slug</Label>
                                    <Input id="slug" name="slug" placeholder="acme" required />
                                </div>
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="industry">Industry</Label>
                                        <Input id="industry" name="industry" placeholder="Robotics" />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="region">Region</Label>
                                        <Input id="region" name="region" placeholder="NA" />
                                    </div>
                                </div>
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="billing_email">Billing email</Label>
                                        <Input id="billing_email" name="billing_email" type="email" placeholder="finance@acme.com" />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="support_email">Support email</Label>
                                        <Input id="support_email" name="support_email" type="email" placeholder="support@acme.com" />
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <Label>Metadata (key=value per line)</Label>
                                    <Textarea
                                        value={metadataText}
                                        onChange={(event) => setMetadataText(event.target.value)}
                                        rows={4}
                                    />
                                </div>
                            </div>

                            <div className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="admin_email">Admin email</Label>
                                    <Input id="admin_email" name="admin_email" type="email" placeholder="owner@acme.com" required />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="admin_username">Admin username</Label>
                                    <Input id="admin_username" name="admin_username" placeholder="acme-owner" required />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="admin_password">Temporary password</Label>
                                    <Input id="admin_password" name="admin_password" type="password" placeholder="StrongPass!" required />
                                </div>
                                <div className="space-y-2">
                                    <Label>Role</Label>
                                    <Select value={role} onValueChange={(value) => setRole(value as typeof roles[number])}>
                                        <SelectTrigger className="rounded-2xl">
                                            <SelectValue placeholder="Select a role" />
                                        </SelectTrigger>
                                        <SelectContent>
                                            {roles.map((item) => (
                                                <SelectItem key={item} value={item} className="capitalize">
                                                    {item}
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>
                                </div>
                                <Button
                                    type="submit"
                                    className="mt-6 w-full rounded-2xl"
                                    disabled={mutation.isPending}
                                >
                                    {mutation.isPending ? (
                                        <>
                                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                            Provisioning…
                                        </>
                                    ) : (
                                        <>
                                            <UserPlus className="mr-2 h-4 w-4" />
                                            Launch tenant
                                        </>
                                    )}
                                </Button>
                            </div>
                        </form>
                    </CardContent>
                </Card>

                {lastTenant && (
                    <Card className="rounded-3xl border bg-card/60">
                        <CardHeader>
                            <CardTitle>Latest tenant</CardTitle>
                            <CardDescription>{lastTenant.name}</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Slug</span>
                                <span className="font-mono text-xs">{lastTenant.slug}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Status</span>
                                <Badge variant="outline" className="capitalize">
                                    {lastTenant.status}
                                </Badge>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Created at</span>
                                <span>{new Date(lastTenant.created_at).toLocaleString()}</span>
                            </div>
                        </CardContent>
                    </Card>
                )}
            </div>
        </CRMGuard>
    );
}

export default CRMTenantProvisionPage;
