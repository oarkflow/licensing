import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { Plus, Search, Key, Filter } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
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
import type { License, Product, Plan } from '@/types/api';

function getLicenseStatusBadge(license: License) {
    if (license.is_revoked) {
        return <Badge variant="destructive">Revoked</Badge>;
    }
    if (license.expires_at && new Date(license.expires_at) < new Date()) {
        return <Badge variant="secondary">Expired</Badge>;
    }
    return <Badge variant="default">Active</Badge>;
}

export function LicensesPage() {
    const [searchParams] = useSearchParams();
    const initialProductId = searchParams.get('product_id') || '';
    const initialPlanId = searchParams.get('plan_id') || '';

    const [filter, setFilter] = useState<string>('all');
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedProductId, setSelectedProductId] = useState(initialProductId);
    const [selectedPlanId, setSelectedPlanId] = useState(initialPlanId);

    const { data: response, isLoading } = useQuery({
        queryKey: ['licenses', filter],
        queryFn: () => api.listLicenses(filter !== 'all' ? filter : undefined),
    });

    const { data: productsResponse } = useQuery({
        queryKey: ['products'],
        queryFn: () => api.listProducts(),
    });

    const { data: plansResponse } = useQuery({
        queryKey: ['plans', selectedProductId],
        queryFn: () => api.listPlans(selectedProductId),
        enabled: !!selectedProductId,
    });

    const products: Product[] = productsResponse?.data || [];
    const plans: Plan[] = plansResponse?.data || [];
    const licenses = response?.data || [];

    const filteredLicenses = licenses.filter((license) => {
        // Filter by product
        if (selectedProductId && license.product_id !== selectedProductId) {
            return false;
        }
        // Filter by plan
        if (selectedPlanId && license.plan_id !== selectedPlanId) {
            return false;
        }
        // Filter by search query
        if (!searchQuery) return true;
        const query = searchQuery.toLowerCase();
        return (
            license.license_key?.toLowerCase().includes(query) ||
            license.email?.toLowerCase().includes(query) ||
            license.plan_slug?.toLowerCase().includes(query)
        );
    });

    // Get product name helper
    const getProductName = (productId?: string) => {
        if (!productId) return null;
        const product = products.find(p => p.id === productId);
        return product?.name || null;
    };

    return (
        <div className="space-y-8">
            <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="space-y-3">
                    <Badge variant="secondary" className="rounded-full border border-white/10 bg-white/5 px-4 py-1 text-xs uppercase tracking-[0.4em] text-muted-foreground">
                        Licenses
                    </Badge>
                    <div>
                        <h1 className="text-4xl font-semibold tracking-tight">License Ledger</h1>
                        <p className="text-muted-foreground">
                            Issue, monitor and audit entitlements across every product line.
                        </p>
                    </div>
                </div>
                <Button
                    asChild
                    className="rounded-2xl bg-primary px-6 text-primary-foreground shadow-lg shadow-primary/40"
                >
                    <Link to="/licenses/new">
                        <Plus className="mr-2 h-4 w-4" />
                        New License
                    </Link>
                </Button>
            </div>

            <div className="glass-panel rounded-3xl border border-white/5 p-4">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
                    <div className="relative flex-1">
                        <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                        <Input
                            placeholder="Search licenses, clients or plans"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="h-11 rounded-2xl border-white/10 bg-white/5 pl-10"
                        />
                    </div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Filter className="h-4 w-4" />
                        Refinements
                    </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-3">
                    <Select value={filter} onValueChange={setFilter}>
                        <SelectTrigger className="w-[140px] rounded-2xl border-white/10 bg-transparent">
                            <SelectValue placeholder="Status" />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">All Status</SelectItem>
                            <SelectItem value="active">Active</SelectItem>
                            <SelectItem value="expired">Expired</SelectItem>
                            <SelectItem value="revoked">Revoked</SelectItem>
                        </SelectContent>
                    </Select>
                    <Select
                        value={selectedProductId}
                        onValueChange={(v) => {
                            setSelectedProductId(v === 'all' ? '' : v);
                            setSelectedPlanId('');
                        }}
                    >
                        <SelectTrigger className="w-[180px] rounded-2xl border-white/10 bg-transparent">
                            <SelectValue placeholder="All Products" />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">All Products</SelectItem>
                            {products.map((product) => (
                                <SelectItem key={product.id} value={product.id}>
                                    {product.name}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                    {selectedProductId && (
                        <Select
                            value={selectedPlanId}
                            onValueChange={(v) => setSelectedPlanId(v === 'all' ? '' : v)}
                        >
                            <SelectTrigger className="w-[180px] rounded-2xl border-white/10 bg-transparent">
                                <SelectValue placeholder="All Plans" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">All Plans</SelectItem>
                                {plans.map((plan) => (
                                    <SelectItem key={plan.id} value={plan.id}>
                                        {plan.name}
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    )}
                </div>
            </div>

            {isLoading ? (
                <div className="space-y-3">
                    {[...Array(6)].map((_, i) => (
                        <Skeleton key={i} className="h-16 w-full rounded-2xl" />
                    ))}
                </div>
            ) : filteredLicenses.length === 0 ? (
                <div className="glass-panel flex flex-col items-center justify-center rounded-3xl border border-dashed border-white/10 py-12 text-center">
                    <Key className="h-12 w-12 text-muted-foreground" />
                    <h3 className="mt-4 text-xl font-semibold">No licenses found</h3>
                    <p className="mt-2 text-sm text-muted-foreground">
                        {searchQuery
                            ? 'Try broadening your query or resetting filters.'
                            : 'Get started by minting a new license key.'}
                    </p>
                    {!searchQuery && (
                        <Button asChild className="mt-4 rounded-2xl">
                            <Link to="/licenses/new">
                                <Plus className="mr-2 h-4 w-4" />
                                New License
                            </Link>
                        </Button>
                    )}
                </div>
            ) : (
                <div className="glass-panel overflow-hidden rounded-3xl border border-white/5">
                    <Table>
                        <TableHeader>
                            <TableRow className="border-white/5 text-muted-foreground">
                                <TableHead>License Key</TableHead>
                                <TableHead>Email</TableHead>
                                <TableHead>Product</TableHead>
                                <TableHead>Plan</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead>Devices</TableHead>
                                <TableHead>Expires</TableHead>
                                <TableHead>Issued</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {filteredLicenses.map((license) => (
                                <TableRow key={license.id} className="border-white/5">
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
                                                className="text-muted-foreground hover:text-white"
                                            >
                                                {getProductName(license.product_id) || license.product_id.substring(0, 8)}
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
                                        {license.device_count || 0} / {license.max_devices || '∞'}
                                    </TableCell>
                                    <TableCell>
                                        {license.expires_at
                                            ? new Date(license.expires_at).toLocaleDateString()
                                            : 'Never'}
                                    </TableCell>
                                    <TableCell>
                                        {license.issued_at
                                            ? new Date(license.issued_at).toLocaleDateString()
                                            : '—'}
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            )}
        </div>
    );
}
