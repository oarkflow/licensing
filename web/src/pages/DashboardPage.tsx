import { useQuery } from '@tanstack/react-query';
import {
    Key,
    Users,
    Package,
    ShieldAlert,
    ArrowRight,
    Activity,
    Sparkles,
    ShieldCheck,
    Radar,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import api from '@/services/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Progress } from '@/components/ui/progress';
import type { DashboardStats, License } from '@/types/api';

type StatTone = 'cyan' | 'purple' | 'pink' | 'emerald';

const toneStyles: Record<StatTone, { icon: string; accent: string }> = {
    cyan: { icon: 'bg-primary/20 text-primary', accent: 'text-primary' },
    purple: { icon: 'bg-secondary/20 text-secondary', accent: 'text-secondary' },
    pink: { icon: 'bg-destructive/20 text-destructive', accent: 'text-destructive' },
    emerald: { icon: 'bg-accent/20 text-accent-foreground', accent: 'text-accent-foreground' },
};

function StatCard({
    title,
    value,
    description,
    icon: Icon,
    loading,
    tone = 'cyan',
}: {
    title: string;
    value: number | string;
    description?: string;
    icon: React.ElementType;
    loading?: boolean;
    tone?: StatTone;
}) {
    const palette = toneStyles[tone];
    return (
        <div className="glass-panel relative overflow-hidden rounded-3xl border p-4">
            <div className="flex items-center justify-between">
                <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">{title}</p>
                <div className={`rounded-2xl p-2 ${palette.icon}`}>
                    <Icon className="h-4 w-4" />
                </div>
            </div>
            <div className="mt-4">
                {loading ? (
                    <Skeleton className="h-8 w-24" />
                ) : (
                    <p className="text-3xl font-semibold tracking-tight">{value}</p>
                )}
                {description && <p className={`text-sm ${palette.accent}`}>{description}</p>}
            </div>
            <div className="pointer-events-none absolute inset-x-6 bottom-2 h-px bg-gradient-to-r from-transparent via-border to-transparent opacity-30" />
        </div>
    );
}

function getLicenseStatusBadge(license: License) {
    if (license.is_revoked) {
        return <Badge variant="destructive">Revoked</Badge>;
    }
    if (license.expires_at && new Date(license.expires_at) < new Date()) {
        return <Badge variant="secondary">Expired</Badge>;
    }
    return <Badge variant="default">Active</Badge>;
}

export function DashboardPage() {
    const { data: statsResponse, isLoading: statsLoading } = useQuery({
        queryKey: ['dashboard-stats'],
        queryFn: () => api.getDashboardStats(),
    });

    const { data: licensesResponse, isLoading: licensesLoading } = useQuery({
        queryKey: ['recent-licenses'],
        queryFn: () => api.listLicenses(),
    });

    const stats: DashboardStats = statsResponse?.data || {
        total_licenses: 0,
        active_licenses: 0,
        revoked_licenses: 0,
        expired_licenses: 0,
        total_clients: 0,
        active_clients: 0,
        banned_clients: 0,
        total_products: 0,
        total_admins: 0,
        recent_licenses: [],
    };

    const recentLicenses = stats.recent_licenses?.slice(0, 5) || (licensesResponse?.data || []).slice(0, 5);

    return (
        <div className="space-y-8">
            <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-3">
                    <Badge variant="secondary" className="rounded-full border bg-muted px-4 py-1 text-xs uppercase tracking-[0.4em] text-muted-foreground">
                        Telemetry
                    </Badge>
                    <Badge className="rounded-full bg-primary/20 text-primary">
                        Live sync
                    </Badge>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-4">
                    <div>
                        <h1 className="text-4xl font-semibold tracking-tight">License Mission Control</h1>
                        <p className="mt-2 text-lg text-muted-foreground">
                            Monitor entitlements, clients and product rollouts in real time.
                        </p>
                    </div>
                    <div className="flex flex-wrap gap-3">
                        <Button asChild variant="outline" className="rounded-2xl border bg-muted text-foreground hover:bg-muted/80">
                            <Link to="/products">
                                <Package className="mr-2 h-4 w-4" />
                                Products
                            </Link>
                        </Button>
                        <Button asChild className="rounded-2xl bg-primary px-6 text-primary-foreground shadow-lg shadow-primary/40">
                            <Link to="/licenses/new">
                                <Key className="mr-2 h-4 w-4" />
                                Issue License
                            </Link>
                        </Button>
                    </div>
                </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-[2fr,1fr]">
                <Card className="relative overflow-hidden rounded-3xl border bg-gradient-to-br from-muted/50 via-transparent to-primary/5 text-foreground">
                    <div className="pointer-events-none absolute -right-16 top-0 h-48 w-48 rounded-full bg-primary/20 blur-3xl" />
                    <CardHeader className="space-y-6">
                        <div className="flex items-center gap-3 text-sm text-muted-foreground">
                            <Sparkles className="h-4 w-4" />
                            <span>Signal clarity</span>
                        </div>
                        <div>
                            <CardTitle className="text-3xl font-semibold text-foreground">Total footprint</CardTitle>
                            <CardDescription className="text-base text-muted-foreground">
                                {stats.total_licenses} licenses tracked across {stats.total_clients} active clients.
                            </CardDescription>
                        </div>
                        <div className="grid gap-4 text-sm md:grid-cols-3">
                            <div className="rounded-2xl border bg-muted p-4">
                                <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Active</p>
                                <p className="mt-2 text-2xl font-semibold text-foreground">{stats.total_licenses > 0 ? Math.round((stats.active_licenses / stats.total_licenses) * 100) : 0}%</p>
                                <p className="text-muted-foreground">+12% this week</p>
                            </div>
                            <div className="rounded-2xl border bg-muted p-4">
                                <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Expiring</p>
                                <p className="mt-2 text-2xl font-semibold text-secondary">{stats.total_licenses > 0 ? Math.round((stats.expired_licenses / stats.total_licenses) * 100) : 0}%</p>
                                <p className="text-muted-foreground">Review before renewal</p>
                            </div>
                            <div className="rounded-2xl border bg-muted p-4">
                                <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Revoked</p>
                                <p className="mt-2 text-2xl font-semibold text-destructive">{stats.total_licenses > 0 ? Math.round((stats.revoked_licenses / stats.total_licenses) * 100) : 0}%</p>
                                <p className="text-muted-foreground">Containment mode</p>
                            </div>
                        </div>
                    </CardHeader>
                </Card>

                <Card className="glass-panel rounded-3xl border">
                    <CardHeader>
                        <CardTitle className="text-xl">Live status</CardTitle>
                        <CardDescription>System health across environments</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-5">
                        <div>
                            <div className="mb-2 flex items-center justify-between text-sm">
                                <span className="text-muted-foreground">Signal uptime</span>
                                <span className="font-semibold text-primary">99.92%</span>
                            </div>
                            <Progress value={99.92} className="h-2 rounded-full bg-muted" />
                        </div>
                        <div>
                            <div className="mb-2 flex items-center justify-between text-sm">
                                <span className="text-muted-foreground">Policy drift</span>
                                <span className="font-semibold text-secondary">1.2%</span>
                            </div>
                            <Progress value={20} className="h-2 rounded-full bg-muted" />
                        </div>
                        <div>
                            <div className="mb-2 flex items-center justify-between text-sm">
                                <span className="text-muted-foreground">Security events</span>
                                <span className="font-semibold text-destructive">{stats.revoked_licenses}</span>
                            </div>
                            <Progress value={stats.total_licenses > 0 ? (stats.revoked_licenses / stats.total_licenses) * 100 : 0} className="h-2 rounded-full bg-muted" />
                        </div>
                    </CardContent>
                </Card>
            </div>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <StatCard
                    title="Total Licenses"
                    value={stats.total_licenses}
                    description={`${stats.active_licenses} active`}
                    icon={Key}
                    loading={statsLoading}
                    tone="cyan"
                />
                <StatCard
                    title="Total Clients"
                    value={stats.total_clients}
                    description={`${stats.active_clients} active, ${stats.banned_clients} banned`}
                    icon={Users}
                    loading={statsLoading}
                    tone="emerald"
                />
                <StatCard
                    title="Products"
                    value={stats.total_products}
                    icon={Package}
                    loading={statsLoading}
                    tone="purple"
                />
                <StatCard
                    title="Admin Users"
                    value={stats.total_admins}
                    icon={ShieldAlert}
                    loading={statsLoading}
                    tone="pink"
                />
            </div>

            <div className="grid gap-6 xl:grid-cols-5">
                <Card className="glass-panel rounded-3xl border xl:col-span-3">
                    <CardHeader className="flex flex-row items-center justify-between">
                        <div>
                            <CardTitle className="text-2xl">Recent Licenses</CardTitle>
                            <CardDescription>Latest issuances across your workspace</CardDescription>
                        </div>
                        <Button asChild variant="outline" size="sm" className="rounded-full border bg-muted text-foreground">
                            <Link to="/licenses">
                                View All
                                <ArrowRight className="ml-2 h-4 w-4" />
                            </Link>
                        </Button>
                    </CardHeader>
                    <CardContent>
                        {licensesLoading && !stats.recent_licenses?.length ? (
                            <div className="space-y-2">
                                {[...Array(5)].map((_, i) => (
                                    <Skeleton key={i} className="h-12 w-full rounded-2xl" />
                                ))}
                            </div>
                        ) : recentLicenses.length === 0 ? (
                            <div className="flex flex-col items-center justify-center rounded-3xl border border-dashed bg-muted/50 py-10 text-center">
                                <Key className="h-12 w-12 text-muted-foreground" />
                                <p className="mt-2 text-sm text-muted-foreground">
                                    No licenses found. Create your first license to get started.
                                </p>
                                <Button asChild className="mt-4 rounded-2xl">
                                    <Link to="/licenses/new">Create License</Link>
                                </Button>
                            </div>
                        ) : (
                            <div className="overflow-hidden rounded-2xl border">
                                <Table>
                                    <TableHeader>
                                        <TableRow className="border">
                                            <TableHead>License Key</TableHead>
                                            <TableHead>Email</TableHead>
                                            <TableHead>Product</TableHead>
                                            <TableHead>Plan</TableHead>
                                            <TableHead>Status</TableHead>
                                            <TableHead>Expires</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {recentLicenses.map((license) => (
                                            <TableRow key={license.id} className="border">
                                                <TableCell>
                                                    <Link
                                                        to={`/licenses/${license.id}`}
                                                        className="font-mono text-sm text-primary hover:underline"
                                                    >
                                                        {license.license_key?.substring(0, 16)}...
                                                    </Link>
                                                </TableCell>
                                                <TableCell>
                                                    {license.email || (
                                                        <span className="text-muted-foreground">—</span>
                                                    )}
                                                </TableCell>
                                                <TableCell>
                                                    {license.product_id ? (
                                                        <Link
                                                            to={`/products/${license.product_id}`}
                                                            className="text-sm text-muted-foreground hover:text-foreground"
                                                        >
                                                            {license.product?.name || license.product_id.substring(0, 8)}
                                                        </Link>
                                                    ) : (
                                                        <span className="text-muted-foreground">—</span>
                                                    )}
                                                </TableCell>
                                                <TableCell>
                                                    {license.plan_slug || (
                                                        <span className="text-muted-foreground">—</span>
                                                    )}
                                                </TableCell>
                                                <TableCell>{getLicenseStatusBadge(license)}</TableCell>
                                                <TableCell>
                                                    {license.expires_at
                                                        ? new Date(license.expires_at).toLocaleDateString()
                                                        : 'Never'}
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            </div>
                        )}
                    </CardContent>
                </Card>

                <Card className="glass-panel rounded-3xl border xl:col-span-2">
                    <CardHeader className="space-y-1">
                        <CardTitle className="text-xl">License health</CardTitle>
                        <CardDescription>Signals across your deployment surface</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-5 text-sm">
                        <div className="flex items-center gap-4 rounded-2xl border bg-muted p-4">
                            <Activity className="h-10 w-10 rounded-2xl bg-primary/20 p-2 text-primary" />
                            <div>
                                <p className="text-xs uppercase tracking-[0.4em] text-muted-foreground">Heartbeat</p>
                                <p className="text-2xl font-semibold">{stats.active_clients}</p>
                                <p className="text-muted-foreground">Active clients pinging in the last hour</p>
                            </div>
                        </div>
                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2 text-muted-foreground">
                                    <ShieldCheck className="h-4 w-4 text-primary" />
                                    Verified fingerprints
                                </div>
                                <span className="font-semibold">{stats.total_clients - stats.banned_clients}</span>
                            </div>
                            <Progress value={stats.total_clients > 0 ? ((stats.total_clients - stats.banned_clients) / stats.total_clients) * 100 : 0} className="h-2 rounded-full bg-muted" />
                        </div>
                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2 text-muted-foreground">
                                    <Radar className="h-4 w-4 text-secondary" />
                                    Pending renewals
                                </div>
                                <span className="font-semibold">{stats.expired_licenses}</span>
                            </div>
                            <Progress value={stats.total_licenses > 0 ? (stats.expired_licenses / stats.total_licenses) * 100 : 0} className="h-2 rounded-full bg-muted" />
                        </div>
                        <div className="rounded-2xl border border-dashed p-4 text-center">
                            <p className="text-sm text-muted-foreground">Need help with license rollouts?</p>
                            <Button asChild variant="secondary" size="sm" className="mt-3 rounded-full bg-muted text-foreground">
                                <Link to="/clients">
                                    Review clients
                                </Link>
                            </Button>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
