import { useQuery } from '@tanstack/react-query';
import { Key, Users, Package, ShieldAlert, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import api from '@/services/api';
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
import { DataPanel, EmptyState, MetricTile, PageHeader } from '@/components/layout/PageShell';
import type { DashboardStats, License } from '@/types/api';

function getLicenseStatusBadge(license: License) {
    if (license.is_revoked) {
        return <Badge variant="destructive">Revoked</Badge>;
    }
    if (license.expires_at && new Date(license.expires_at) < new Date()) {
        return <Badge variant="secondary">Expired</Badge>;
    }
    return <Badge variant="default">Active</Badge>;
}

function metricValue(value: number | string, loading: boolean) {
    return loading ? <Skeleton className="h-5 w-16" /> : value;
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

    const recentLicenses = stats.recent_licenses?.slice(0, 8) || (licensesResponse?.data || []).slice(0, 8);
    const activeRate = stats.total_licenses > 0 ? Math.round((stats.active_licenses / stats.total_licenses) * 100) : 0;
    const revokedRate = stats.total_licenses > 0 ? Math.round((stats.revoked_licenses / stats.total_licenses) * 100) : 0;

    return (
        <div className="space-y-4">
            <PageHeader
                eyebrow="Overview"
                title="Dashboard"
                description="Operational summary for licenses, clients, products, and administrative access."
                actions={
                    <>
                        <Button asChild variant="outline" size="sm">
                            <Link to="/products">
                                <Package className="h-3.5 w-3.5" />
                                Products
                            </Link>
                        </Button>
                        <Button asChild size="sm">
                            <Link to="/licenses/new">
                                <Key className="h-3.5 w-3.5" />
                                Issue License
                            </Link>
                        </Button>
                    </>
                }
            />

            <DataPanel>
                <div className="grid divide-y md:grid-cols-2 md:divide-x md:divide-y-0 xl:grid-cols-4">
                    <MetricTile
                        label="Licenses"
                        value={metricValue(stats.total_licenses, statsLoading)}
                        description={`${stats.active_licenses} active`}
                        tone="primary"
                    />
                    <MetricTile
                        label="Clients"
                        value={metricValue(stats.total_clients, statsLoading)}
                        description={`${stats.active_clients} active, ${stats.banned_clients} banned`}
                    />
                    <MetricTile
                        label="Products"
                        value={metricValue(stats.total_products, statsLoading)}
                        description="Catalog records"
                        tone="secondary"
                    />
                    <MetricTile
                        label="Admins"
                        value={metricValue(stats.total_admins, statsLoading)}
                        description="Users with console access"
                        tone="accent"
                    />
                </div>
            </DataPanel>

            <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
                <DataPanel>
                    <div className="flex items-center justify-between border-b px-3 py-2">
                        <div>
                            <h2 className="text-sm font-semibold">Recent Licenses</h2>
                            <p className="text-xs text-muted-foreground">Latest license records across the workspace.</p>
                        </div>
                        <Button asChild variant="outline" size="sm">
                            <Link to="/licenses">
                                View All
                                <ArrowRight className="h-3.5 w-3.5" />
                            </Link>
                        </Button>
                    </div>

                    {licensesLoading && !stats.recent_licenses?.length ? (
                        <div className="space-y-2 p-3">
                            {[...Array(6)].map((_, i) => (
                                <Skeleton key={i} className="h-9 w-full" />
                            ))}
                        </div>
                    ) : recentLicenses.length === 0 ? (
                        <EmptyState
                            title="No licenses"
                            description="Create a license to start tracking entitlements."
                            action={
                                <Button asChild size="sm">
                                    <Link to="/licenses/new">Create License</Link>
                                </Button>
                            }
                        />
                    ) : (
                        <div className="overflow-x-auto">
                            <Table>
                                <TableHeader>
                                    <TableRow>
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
                                        <TableRow key={license.id}>
                                            <TableCell>
                                                <Link
                                                    to={`/licenses/${license.id}`}
                                                    className="font-mono text-xs text-primary hover:underline"
                                                >
                                                    {license.license_key?.substring(0, 18)}...
                                                </Link>
                                            </TableCell>
                                            <TableCell className="max-w-[220px] truncate">
                                                {license.email || <span className="text-muted-foreground">-</span>}
                                            </TableCell>
                                            <TableCell className="max-w-[180px] truncate">
                                                {license.product_id ? (
                                                    <Link
                                                        to={`/products/${license.product_id}`}
                                                        className="text-muted-foreground hover:text-foreground"
                                                    >
                                                        {license.product?.name || license.product_id.substring(0, 8)}
                                                    </Link>
                                                ) : (
                                                    <span className="text-muted-foreground">-</span>
                                                )}
                                            </TableCell>
                                            <TableCell>{license.plan_slug || <span className="text-muted-foreground">-</span>}</TableCell>
                                            <TableCell>{getLicenseStatusBadge(license)}</TableCell>
                                            <TableCell>
                                                {license.expires_at ? new Date(license.expires_at).toLocaleDateString() : 'Never'}
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>
                    )}
                </DataPanel>

                <DataPanel>
                    <div className="border-b px-3 py-2">
                        <h2 className="text-sm font-semibold">License Health</h2>
                        <p className="text-xs text-muted-foreground">Current status distribution.</p>
                    </div>
                    <div className="divide-y text-sm">
                        <div className="flex items-center justify-between px-3 py-3">
                            <span className="flex items-center gap-2 text-muted-foreground">
                                <Key className="h-3.5 w-3.5 text-primary" />
                                Active licenses
                            </span>
                            <span className="font-semibold tabular-nums">{stats.active_licenses} ({activeRate}%)</span>
                        </div>
                        <div className="flex items-center justify-between px-3 py-3">
                            <span className="flex items-center gap-2 text-muted-foreground">
                                <ShieldAlert className="h-3.5 w-3.5 text-destructive" />
                                Revoked licenses
                            </span>
                            <span className="font-semibold tabular-nums">{stats.revoked_licenses} ({revokedRate}%)</span>
                        </div>
                        <div className="flex items-center justify-between px-3 py-3">
                            <span className="flex items-center gap-2 text-muted-foreground">
                                <Users className="h-3.5 w-3.5 text-secondary" />
                                Banned clients
                            </span>
                            <span className="font-semibold tabular-nums">{stats.banned_clients}</span>
                        </div>
                        <div className="px-3 py-3">
                            <Button asChild variant="outline" size="sm" className="w-full justify-start">
                                <Link to="/clients">Review Clients</Link>
                            </Button>
                        </div>
                    </div>
                </DataPanel>
            </div>
        </div>
    );
}
