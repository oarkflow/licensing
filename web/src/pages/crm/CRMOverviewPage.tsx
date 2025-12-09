import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowRight, Building2, KeyRound, RefreshCw, Shield, Sparkles, User2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { CRMGuard } from '@/components/crm/CRMAuthGate';
import useCRM from '@/hooks/useCRM';
import crmService from '@/services/crm';

export function CRMOverviewPage() {
    const { session, refreshSession } = useCRM();
    const tenantId = session?.tenant.id;

    const { data: tenantProducts, isLoading } = useQuery({
        queryKey: ['crm-tenant-products', tenantId],
        queryFn: () => crmService.listTenantProducts(tenantId!),
        enabled: Boolean(tenantId),
    });

    if (!session) {
        return (
            <CRMGuard
                title="Unlock CRM surface"
                description="Authenticate with CRM credentials to inspect tenant posture."
            >
                {null}
            </CRMGuard>
        );
    }

    const { tenant, user } = session;

    const products = tenantProducts || session.products || [];

    return (
        <CRMGuard
            title="Unlock CRM surface"
            description="Authenticate with CRM credentials to inspect tenant posture."
        >
            <div className="space-y-8">
                <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="space-y-3">
                        <Badge variant="secondary" className="rounded-full border bg-muted px-4 py-1 text-xs uppercase tracking-[0.4em]">
                            CRM
                        </Badge>
                        <div>
                            <h1 className="text-4xl font-semibold tracking-tight">Tenant control center</h1>
                            <p className="text-muted-foreground">
                                Monitor CRM sessions, entitlements, and operational scopes in a single cockpit.
                            </p>
                        </div>
                    </div>
                    <div className="flex flex-wrap gap-3">
                        <Button variant="outline" className="rounded-2xl" onClick={() => refreshSession()}>
                            <RefreshCw className="mr-2 h-4 w-4" />
                            Refresh session
                        </Button>
                        <Button asChild className="rounded-2xl bg-primary text-primary-foreground">
                            <Link to="/crm/tenants/new">
                                <Sparkles className="mr-2 h-4 w-4" />
                                Provision tenant
                            </Link>
                        </Button>
                    </div>
                </div>

                <div className="grid gap-6 lg:grid-cols-3">
                    <Card className="rounded-3xl border bg-card/70 backdrop-blur">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-xl">
                                <User2 className="h-4 w-4 text-primary" />
                                Identity
                            </CardTitle>
                            <CardDescription>Scoped CRM session</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Username</span>
                                <span className="font-medium">{user.username}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Email</span>
                                <span className="font-medium">{user.email}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Role</span>
                                <Badge variant="outline" className="capitalize">
                                    {user.role}
                                </Badge>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Scope</span>
                                <span className="font-mono text-xs">{session.scope || '—'}</span>
                            </div>
                        </CardContent>
                    </Card>

                    <Card className="rounded-3xl border bg-card/70 backdrop-blur">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-xl">
                                <Building2 className="h-4 w-4 text-primary" />
                                Tenant
                            </CardTitle>
                            <CardDescription>Operational metadata</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Name</span>
                                <span className="font-medium">{tenant.name}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Slug</span>
                                <span className="font-mono text-xs">{tenant.slug}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Status</span>
                                <Badge variant="secondary" className="capitalize">
                                    {tenant.status}
                                </Badge>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Region</span>
                                <span className="font-medium">{tenant.region || 'Unknown'}</span>
                            </div>
                        </CardContent>
                    </Card>

                    <Card className="rounded-3xl border bg-card/70 backdrop-blur">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-xl">
                                <Shield className="h-4 w-4 text-primary" />
                                Session policy
                            </CardTitle>
                            <CardDescription>Issued tokens</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Issued</span>
                                <span>{new Date(session.issued_at).toLocaleString()}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Expires</span>
                                <span>{new Date(session.expires_at).toLocaleString()}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-muted-foreground">Products cached</span>
                                <span className="font-medium">{session.products?.length || 0}</span>
                            </div>
                            <p className="text-xs text-muted-foreground">
                                Need expanded scopes? Request them while authenticating via the CRM panel.
                            </p>
                        </CardContent>
                    </Card>
                </div>

                <Card className="rounded-3xl border bg-card/70">
                    <CardHeader className="flex flex-wrap items-center justify-between gap-4">
                        <div>
                            <CardTitle className="text-2xl">Tenant product matrix</CardTitle>
                            <CardDescription>Product access hydrated by CRM entitlements</CardDescription>
                        </div>
                        <Button asChild variant="secondary" className="rounded-2xl">
                            <Link to="/crm/entitlements">
                                Manage entitlements
                                <ArrowRight className="ml-2 h-4 w-4" />
                            </Link>
                        </Button>
                    </CardHeader>
                    <CardContent>
                        {isLoading ? (
                            <Skeleton className="h-48 w-full rounded-2xl" />
                        ) : products.length === 0 ? (
                            <div className="flex flex-col items-center justify-center rounded-3xl border border-dashed py-12 text-center text-sm text-muted-foreground">
                                No product access recorded for this tenant yet.
                            </div>
                        ) : (
                            <div className="rounded-3xl border">
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>Product</TableHead>
                                            <TableHead>Plan</TableHead>
                                            <TableHead>Status</TableHead>
                                            <TableHead>Effective</TableHead>
                                            <TableHead>Expires</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {products.map((product) => (
                                            <TableRow key={`${product.product_id}-${product.plan_id}`}>
                                                <TableCell>
                                                    <div className="font-semibold">{product.product_slug || product.product_id}</div>
                                                    <div className="text-xs text-muted-foreground">{product.product_id}</div>
                                                </TableCell>
                                                <TableCell>
                                                    <div className="font-medium">{product.plan_slug || product.plan_id}</div>
                                                    <div className="text-xs text-muted-foreground">{product.plan_id}</div>
                                                </TableCell>
                                                <TableCell>
                                                    <Badge variant="outline" className="capitalize">
                                                        {product.status || 'active'}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell>{new Date(product.effective_at).toLocaleDateString()}</TableCell>
                                                <TableCell>{product.expires_at ? new Date(product.expires_at).toLocaleDateString() : '—'}</TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            </div>
                        )}
                    </CardContent>
                </Card>

                <div className="grid gap-4 md:grid-cols-3">
                    {quickActions.map((action) => (
                        <Link key={action.href} to={action.href} className="group rounded-3xl border bg-card/70 p-4 transition hover:-translate-y-1 hover:border-primary">
                            <div className="flex items-center justify-between">
                                <div className="rounded-2xl bg-primary/10 p-2 text-primary">
                                    <action.icon className="h-5 w-5" />
                                </div>
                                <ArrowRight className="h-4 w-4 text-muted-foreground transition group-hover:translate-x-1" />
                            </div>
                            <div className="mt-4 font-semibold">{action.title}</div>
                            <p className="text-sm text-muted-foreground">{action.description}</p>
                        </Link>
                    ))}
                </div>
            </div>
        </CRMGuard>
    );
}

const quickActions = [
    {
        title: 'Provision tenants',
        description: 'Bootstrap regional workspaces with admin seeds in minutes.',
        href: '/crm/tenants/new',
        icon: Sparkles,
    },
    {
        title: 'Client credentials',
        description: 'Issue, rotate, and revoke CRM logins.',
        href: '/crm/client-credentials',
        icon: KeyRound,
    },
    {
        title: 'Assign entitlements',
        description: 'Bind plans to contacts and push overrides.',
        href: '/crm/entitlements',
        icon: Shield,
    },
    {
        title: 'Offline bundles',
        description: 'Generate signed payloads for air-gapped customers.',
        href: '/crm/offline-bundles',
        icon: Building2,
    },
];

export default CRMOverviewPage;
