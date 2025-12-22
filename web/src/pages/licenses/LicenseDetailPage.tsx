import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
    ArrowLeft,
    Key,
    Copy,
    Ban,
    RotateCcw,
    Monitor,
    Trash2,
    Clock,
    CheckCircle,
    XCircle,
} from 'lucide-react';
import {
    Tooltip,
    TooltipContent,
    TooltipTrigger,
} from '@/components/ui/tooltip';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from '@/components/ui/card';
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
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
    AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import type { FeatureScopeSelection, License, LicenseDevice } from '@/types/api';
import { FeatureScopeSelector } from '@/components/licenses/FeatureScopeSelector';
import { entitlementsToSelections, slugToLabel, groupScopesForFeature, categorizeSelections } from '@/lib/entitlements';

function getLicenseStatusBadge(license: License) {
    if (license.is_revoked) {
        return <Badge variant="destructive">Revoked</Badge>;
    }
    if (license.expires_at && new Date(license.expires_at) < new Date()) {
        return <Badge variant="secondary">Expired</Badge>;
    }
    return <Badge variant="default">Active</Badge>;
}

export function LicenseDetailPage() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const [revokeReason, setRevokeReason] = useState('');
    const [revokeDialogOpen, setRevokeDialogOpen] = useState(false);
    const [issueDialogOpen, setIssueDialogOpen] = useState(false);
    const [deviceFingerprint, setDeviceFingerprint] = useState('');
    const [tokenMaxUses, setTokenMaxUses] = useState<number | undefined>(30);
    const [tokenValidity, setTokenValidity] = useState<number | undefined>(30);
    const [issuedTokenBundle, setIssuedTokenBundle] = useState<any | null>(null);

    const issueMutation = useMutation({
        mutationFn: (payload: { license_key: string; device_fingerprint: string; max_uses?: number; validity_days?: number }) => api.createOfflineToken(payload),
        onSuccess: (response) => {
            if (response.success && response.data) {
                // response.data can be object with token and signed_bundle
                setIssuedTokenBundle(response.data.signed_bundle || response.data.token || null);
                setIssueDialogOpen(true);
                queryClient.invalidateQueries({ queryKey: ['license', id] });
                toast({ title: 'Offline token issued' });
            } else {
                toast({ title: 'Failed to issue offline token', description: response.error || 'Unknown error', variant: 'destructive' });
            }
        },
        onError: (err) => {
            toast({ title: 'Failed to issue offline token', description: (err as Error).message, variant: 'destructive' });
        }
    });
    const [entitlementDialogOpen, setEntitlementDialogOpen] = useState(false);
    const [editedFeatureScopes, setEditedFeatureScopes] = useState<FeatureScopeSelection[]>([]);
    const [initialFeatureScopes, setInitialFeatureScopes] = useState<FeatureScopeSelection[]>([]);

    const { data: licenseResponse, isLoading: licenseLoading } = useQuery({
        queryKey: ['license', id],
        queryFn: () => api.getLicense(id!),
        enabled: !!id,
    });
    const license = licenseResponse?.data;
    const canEditScopes = Boolean(license?.product_id && license?.plan_id);

    const { data: planEntitlementsResponse, isFetching: planEntitlementsLoading } = useQuery({
        queryKey: ['license-plan-entitlements', license?.product_id, license?.plan_id],
        queryFn: () => api.getPlanEntitlements(license!.product_id!, license!.plan_id!),
        enabled: entitlementDialogOpen && canEditScopes,
    });

    const revokeMutation = useMutation({
        mutationFn: (reason: string) => api.revokeLicense(id!, reason),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['license', id] });
            setRevokeDialogOpen(false);
            toast({ title: 'License revoked successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to revoke license',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const reinstateMutation = useMutation({
        mutationFn: () => api.reinstateLicense(id!),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['license', id] });
            toast({ title: 'License reinstated successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to reinstate license',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const deactivateMutation = useMutation({
        mutationFn: (fingerprint: string) => api.deactivateDevice(id!, fingerprint),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['license', id] });
            queryClient.invalidateQueries({ queryKey: ['license-activations', id] });

            useEffect(() => {
                if (!entitlementDialogOpen) {
                    return;
                }
                if (license?.entitlements) {
                    const initial = entitlementsToSelections(license.entitlements);
                    setEditedFeatureScopes(initial);
                    setInitialFeatureScopes(initial);
                    return;
                }
                if (planEntitlementsResponse?.data) {
                    const initial = entitlementsToSelections(planEntitlementsResponse.data);
                    setEditedFeatureScopes(initial);
                    setInitialFeatureScopes(initial);
                }
            }, [entitlementDialogOpen, license?.entitlements, planEntitlementsResponse?.data]);
            toast({ title: 'Device deactivated successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to deactivate device',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const updateEntitlementsMutation = useMutation({
        mutationFn: (scopes: FeatureScopeSelection[]) => api.updateLicenseEntitlements(id!, scopes),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['license', id] });
            toast({ title: 'Feature scopes updated' });
            setEntitlementDialogOpen(false);
        },
        onError: (error) => {
            toast({
                title: 'Failed to update feature scopes',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        toast({ title: 'Copied to clipboard' });
    };

    if (licenseLoading) {
        return (
            <div className="space-y-6">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
            </div>
        );
    }

    if (!license) {
        return (
            <div className="flex flex-col items-center justify-center py-12">
                <Key className="h-12 w-12 text-muted-foreground" />
                <h2 className="mt-4 text-lg font-semibold">License not found</h2>
                <Button asChild className="mt-4">
                    <Link to="/licenses">Back to Licenses</Link>
                </Button>
            </div>
        );
    }

    // Extract devices from the license
    const devices: [string, LicenseDevice][] = license.devices
        ? Object.entries(license.devices)
        : [];

    const handleEntitlementsReset = () => {
        if (planEntitlementsResponse?.data) {
            setEditedFeatureScopes(entitlementsToSelections(planEntitlementsResponse.data));
        } else if (license.entitlements) {
            setEditedFeatureScopes(entitlementsToSelections(license.entitlements));
        }
    };

    const handleEntitlementsSave = () => {
        updateEntitlementsMutation.mutate(editedFeatureScopes);
    };

    const selectorLoading = planEntitlementsLoading && editedFeatureScopes.length === 0;

    return (
        <div className="space-y-6">
            <Dialog open={entitlementDialogOpen} onOpenChange={setEntitlementDialogOpen}>
                <DialogContent className="max-w-3xl">
                    <DialogHeader>
                        <DialogTitle>Adjust Feature Scopes</DialogTitle>
                        <DialogDescription>
                            Toggle individual scopes or apply global allow/deny to tailor this license beyond the plan defaults.
                        </DialogDescription>
                    </DialogHeader>
                    <FeatureScopeSelector
                        selections={editedFeatureScopes}
                        initialSelections={initialFeatureScopes}
                        onChange={setEditedFeatureScopes}
                        loading={selectorLoading}
                        disabled={updateEntitlementsMutation.isPending}
                        onReset={handleEntitlementsReset}
                    />
                    <DialogFooter>
                        <Button
                            type="button"
                            variant="ghost"
                            onClick={() => setEntitlementDialogOpen(false)}
                            disabled={updateEntitlementsMutation.isPending}
                        >
                            Cancel
                        </Button>
                        <Button
                            type="button"
                            onClick={handleEntitlementsSave}
                            disabled={updateEntitlementsMutation.isPending}
                        >
                            {updateEntitlementsMutation.isPending ? 'Saving…' : 'Save Scopes'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
            <div className="flex items-center gap-4">
                <Tooltip>
                    <TooltipTrigger asChild>
                        <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                            <ArrowLeft className="h-4 w-4" />
                        </Button>
                    </TooltipTrigger>
                    <TooltipContent>
                        <p>Go back</p>
                    </TooltipContent>
                </Tooltip>
                <div className="flex-1">
                    <h1 className="text-3xl font-bold tracking-tight">License Details</h1>
                    <p className="text-muted-foreground">
                        View and manage license information
                    </p>
                </div>
                <div className="flex gap-2">
                    <Dialog open={issueDialogOpen} onOpenChange={setIssueDialogOpen}>
                        <DialogTrigger asChild>
                            <Button variant="outline">Issue Offline Token</Button>
                        </DialogTrigger>
                        <DialogContent>
                            <DialogHeader>
                                <DialogTitle>Issue Offline Token</DialogTitle>
                                <DialogDescription>
                                    Create an offline validation token that can be used by clients when offline.
                                </DialogDescription>
                            </DialogHeader>

                            <div className="space-y-3 py-2">
                                <div className="space-y-1">
                                    <Label>Device fingerprint</Label>
                                    <Input placeholder="device fingerprint (e.g. device id)" value={deviceFingerprint} onChange={(e) => setDeviceFingerprint(e.target.value)} />
                                </div>
                                <div className="grid grid-cols-2 gap-2">
                                    <div className="space-y-1">
                                        <Label>Max uses</Label>
                                        <Input type="number" value={tokenMaxUses ?? ''} onChange={(e) => setTokenMaxUses(parseInt(e.target.value || '0'))} />
                                    </div>
                                    <div className="space-y-1">
                                        <Label>Validity days</Label>
                                        <Input type="number" value={tokenValidity ?? ''} onChange={(e) => setTokenValidity(parseInt(e.target.value || '0'))} />
                                    </div>
                                </div>
                            </div>
                            <DialogFooter>
                                <Button variant="ghost" onClick={() => setIssueDialogOpen(false)}>Cancel</Button>
                                <Button onClick={() => issueMutation.mutate({ license_key: license!.license_key, device_fingerprint: deviceFingerprint, max_uses: tokenMaxUses, validity_days: tokenValidity })}>
                                    {issueMutation.isPending ? 'Issuing…' : 'Issue Token'}
                                </Button>
                            </DialogFooter>
                        </DialogContent>
                    </Dialog>

                    <Tooltip>
                        <TooltipTrigger asChild>
                            <Button
                                variant="outline"
                                onClick={() => {
                                    const licenseJson = JSON.stringify({
                                        email: license?.email ?? '',
                                        client_id: license?.client_id ?? '',
                                        license_key: license?.license_key ?? '',
                                    }, null, 2);
                                    copyToClipboard(licenseJson);
                                }}
                            >
                                Copy License JSON
                            </Button>
                        </TooltipTrigger>
                        <TooltipContent>
                            <p>Copy email, client_id and license_key as JSON</p>
                        </TooltipContent>
                    </Tooltip>

                    {/* Show issued bundle dialog */}
                    {issuedTokenBundle && (
                        <Dialog open={Boolean(issuedTokenBundle)} onOpenChange={() => setIssuedTokenBundle(null)}>
                            <DialogContent>
                                <DialogHeader>
                                    <DialogTitle>Issued Offline Token</DialogTitle>
                                    <DialogDescription>Copy the signed bundle or token for the client.</DialogDescription>
                                </DialogHeader>
                                <div className="space-y-3 py-2">
                                    <Textarea readOnly value={typeof issuedTokenBundle === 'string' ? issuedTokenBundle : JSON.stringify(issuedTokenBundle, null, 2)} className="font-mono text-xs" />
                                </div>
                                <DialogFooter>
                                    <Button onClick={() => { navigator.clipboard.writeText(typeof issuedTokenBundle === 'string' ? issuedTokenBundle : JSON.stringify(issuedTokenBundle)); toast({ title: 'Copied to clipboard' }); }}>Copy</Button>
                                    <Button onClick={() => setIssuedTokenBundle(null)}>Close</Button>
                                </DialogFooter>
                            </DialogContent>
                        </Dialog>
                    )}
                    {license.is_revoked ? (
                        <AlertDialog>
                            <AlertDialogTrigger asChild>
                                <Button variant="outline">
                                    <RotateCcw className="mr-2 h-4 w-4" />
                                    Reinstate
                                </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                                <AlertDialogHeader>
                                    <AlertDialogTitle>Reinstate License</AlertDialogTitle>
                                    <AlertDialogDescription>
                                        This will restore the license and allow it to be used again.
                                    </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                                    <AlertDialogAction
                                        onClick={() => reinstateMutation.mutate()}
                                        disabled={reinstateMutation.isPending}
                                    >
                                        {reinstateMutation.isPending ? 'Reinstating...' : 'Reinstate'}
                                    </AlertDialogAction>
                                </AlertDialogFooter>
                            </AlertDialogContent>
                        </AlertDialog>
                    ) : (
                        <Dialog open={revokeDialogOpen} onOpenChange={setRevokeDialogOpen}>
                            <DialogTrigger asChild>
                                <Button variant="destructive">
                                    <Ban className="mr-2 h-4 w-4" />
                                    Revoke
                                </Button>
                            </DialogTrigger>
                            <DialogContent>
                                <DialogHeader>
                                    <DialogTitle>Revoke License</DialogTitle>
                                    <DialogDescription>
                                        This will prevent the license from being used. You can reinstate it later.
                                    </DialogDescription>
                                </DialogHeader>
                                <div className="space-y-4 py-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="reason">Reason for revocation</Label>
                                        <Textarea
                                            id="reason"
                                            placeholder="Enter the reason for revoking this license..."
                                            value={revokeReason}
                                            onChange={(e) => setRevokeReason(e.target.value)}
                                        />
                                    </div>
                                </div>
                                <DialogFooter>
                                    <Button
                                        variant="ghost"
                                        onClick={() => setRevokeDialogOpen(false)}
                                    >
                                        Cancel
                                    </Button>
                                    <Button
                                        variant="destructive"
                                        onClick={() => revokeMutation.mutate(revokeReason)}
                                        disabled={revokeMutation.isPending}
                                    >
                                        {revokeMutation.isPending ? 'Revoking...' : 'Revoke License'}
                                    </Button>
                                </DialogFooter>
                            </DialogContent>
                        </Dialog>
                    )}
                </div>
            </div>

            <div className="grid gap-6 md:grid-cols-2">
                <Card>
                    <CardHeader>
                        <CardTitle>License Information</CardTitle>
                        <CardDescription>Basic license details</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label className="text-muted-foreground">License Key</Label>
                            <div className="flex items-center gap-2">
                                <Input
                                    value={license.license_key}
                                    readOnly
                                    className="font-mono text-sm"
                                />
                                <Button
                                    variant="outline"
                                    size="icon"
                                    onClick={() => copyToClipboard(license.license_key)}
                                >
                                    <Copy className="h-4 w-4" />
                                </Button>
                            </div>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label className="text-muted-foreground">Status</Label>
                                <div>{getLicenseStatusBadge(license)}</div>
                            </div>
                            <div className="space-y-2">
                                <Label className="text-muted-foreground">Devices</Label>
                                <div className="font-medium">
                                    {license.device_count || 0} / {license.max_devices || '∞'}
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label className="text-muted-foreground">Issued</Label>
                                <div className="font-medium">
                                    {license.issued_at ? new Date(license.issued_at).toLocaleDateString() : '—'}
                                </div>
                            </div>
                            <div className="space-y-2">
                                <Label className="text-muted-foreground">Expires</Label>
                                <div className="font-medium">
                                    {license.expires_at
                                        ? new Date(license.expires_at).toLocaleDateString()
                                        : 'Never'}
                                </div>
                            </div>
                        </div>

                        {license.is_revoked && license.revoke_reason && (
                            <div className="space-y-2">
                                <Label className="text-muted-foreground">Revoke Reason</Label>
                                <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
                                    {license.revoke_reason}
                                </div>
                            </div>
                        )}
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>License Info</CardTitle>
                        <CardDescription>Associated client and product</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label className="text-muted-foreground">Email</Label>
                            <div className="flex items-center gap-2">
                                <div className="font-medium">{license.email}</div>
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <Button
                                            variant="outline"
                                            size="icon"
                                            onClick={() => copyToClipboard(license.email ?? '')}
                                            aria-label="Copy email"
                                        >
                                            <Copy className="h-4 w-4" />
                                        </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        <p>Copy email</p>
                                    </TooltipContent>
                                </Tooltip>
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label className="text-muted-foreground">Client ID</Label>
                            <div className="flex items-center gap-2">
                                <Link
                                    to={`/clients/${license.client_id}`}
                                    className="text-primary hover:underline"
                                >
                                    {license.client_id}
                                </Link>
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <Button
                                            variant="outline"
                                            size="icon"
                                            onClick={() => copyToClipboard(license.client_id ?? '')}
                                            aria-label="Copy client ID"
                                        >
                                            <Copy className="h-4 w-4" />
                                        </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        <p>Copy client ID</p>
                                    </TooltipContent>
                                </Tooltip>
                            </div>
                        </div>

                        {license.product_id && (
                            <div className="space-y-2">
                                <Label className="text-muted-foreground">Product</Label>
                                <div>
                                    <Link
                                        to={`/products/${license.product_id}`}
                                        className="text-primary hover:underline"
                                    >
                                        {license.product_id}
                                    </Link>
                                </div>
                            </div>
                        )}

                        <div className="space-y-2">
                            <Label className="text-muted-foreground">Plan</Label>
                            <div className="font-medium">{license.plan_slug}</div>
                        </div>
                    </CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Active Devices</CardTitle>
                    <CardDescription>
                        Devices currently using this license
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {devices.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-8 text-center">
                            <Monitor className="h-12 w-12 text-muted-foreground" />
                            <p className="mt-2 text-sm text-muted-foreground">
                                No devices are currently using this license
                            </p>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Fingerprint</TableHead>
                                    <TableHead>Activated</TableHead>
                                    <TableHead>Last Seen</TableHead>
                                    <TableHead className="w-[100px]">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {devices.map(([fingerprint, device]) => (
                                    <TableRow key={fingerprint}>
                                        <TableCell className="font-mono text-sm">
                                            {fingerprint.substring(0, 20)}...
                                        </TableCell>
                                        <TableCell>
                                            <div className="flex items-center gap-1 text-sm">
                                                <Clock className="h-3 w-3" />
                                                {device.activated_at ? new Date(device.activated_at).toLocaleDateString() : '—'}
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            {device.last_seen_at
                                                ? new Date(device.last_seen_at).toLocaleDateString()
                                                : '—'}
                                        </TableCell>
                                        <TableCell>
                                            <AlertDialog>
                                                <AlertDialogTrigger asChild>
                                                    <Tooltip>
                                                        <TooltipTrigger asChild>
                                                            <Button variant="ghost" size="icon">
                                                                <Trash2 className="h-4 w-4" />
                                                            </Button>
                                                        </TooltipTrigger>
                                                        <TooltipContent>
                                                            <p>Remove device</p>
                                                        </TooltipContent>
                                                    </Tooltip>
                                                </AlertDialogTrigger>
                                                <AlertDialogContent>
                                                    <AlertDialogHeader>
                                                        <AlertDialogTitle>Deactivate Device</AlertDialogTitle>
                                                        <AlertDialogDescription>
                                                            This will remove the device from this license. The device
                                                            will need to reactivate to use the software.
                                                        </AlertDialogDescription>
                                                    </AlertDialogHeader>
                                                    <AlertDialogFooter>
                                                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                                                        <AlertDialogAction
                                                            onClick={() =>
                                                                deactivateMutation.mutate(fingerprint)
                                                            }
                                                        >
                                                            Deactivate
                                                        </AlertDialogAction>
                                                    </AlertDialogFooter>
                                                </AlertDialogContent>
                                            </AlertDialog>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>

            {license.entitlements && license.entitlements.features && Object.keys(license.entitlements.features).length > 0 && (
                <Card>
                    <CardHeader className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                        <div>
                            <CardTitle>Entitlements</CardTitle>
                            <CardDescription>Features included in this license</CardDescription>
                        </div>
                        {canEditScopes ? (
                            <Button
                                variant="outline"
                                size="sm"
                                className="rounded-full"
                                onClick={() => setEntitlementDialogOpen(true)}
                            >
                                Adjust Feature Scopes
                            </Button>
                        ) : (
                            <Badge variant="secondary" className="rounded-full px-3 py-1 text-xs">
                                Link to plan to edit
                            </Badge>
                        )}
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-6">
                            {/* Convert entitlements into selections and categorize into cli/gui/api/other */}
                            {(() => {
                                const selections = entitlementsToSelections(license.entitlements);
                                const categories = categorizeSelections(selections);
                                const catOrder: Array<'cli' | 'gui' | 'api' | 'other'> = ['cli', 'gui', 'api', 'other'];
                                return (
                                    <div className="space-y-6">
                                        {catOrder.map((cat) => (
                                            <div key={cat}>
                                                {categories[cat].length > 0 && (
                                                    <div>
                                                        <div className="mb-2 flex items-center gap-2">
                                                            <span className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">{cat.toUpperCase()}</span>
                                                            <Badge variant="outline" className="text-[11px]">{categories[cat].length}</Badge>
                                                        </div>
                                                        <div>
                                                            {categories[cat].map((feature) => {
                                                                const groups = groupScopesForFeature(feature.feature_slug, feature.scopes);
                                                                return (
                                                                    <div key={feature.feature_slug} className="rounded-md border p-3">
                                                                        <div className="flex items-center gap-2">
                                                                            {feature.enabled ? (
                                                                                <CheckCircle className="h-4 w-4 text-primary" />
                                                                            ) : (
                                                                                <XCircle className="h-4 w-4 text-destructive" />
                                                                            )}
                                                                            <span className="font-medium">{slugToLabel(feature.feature_slug)}</span>
                                                                            {feature.feature_slug && (
                                                                                <Badge variant="outline" className="ml-auto">{feature.feature_slug}</Badge>
                                                                            )}
                                                                        </div>
                                                                        {groups.length === 0 ? (
                                                                            <p className="mt-2 text-sm italic text-muted-foreground">No scopes defined for this feature yet.</p>
                                                                        ) : (
                                                                            <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-3 mt-2 space-y-2">
                                                                                {groups.map((g) => (
                                                                                    <div key={g.title} className="rounded-2xl border border-border/60 bg-muted/10 p-2">
                                                                                        <div className="flex items-center justify-between text-xs uppercase tracking-[0.3em] text-muted-foreground">
                                                                                            <span>{g.title}</span>
                                                                                            <Badge variant="outline" className="rounded-full px-2 py-0.5 text-[10px]">{g.scopes.length}</Badge>
                                                                                        </div>
                                                                                        <div className="mt-2 flex flex-wrap gap-2">
                                                                                            {g.scopes.map(({ selection, definition }) => (
                                                                                                <Badge key={selection.scope_slug} variant={selection.permission === 'deny' ? 'destructive' : selection.permission === 'limit' ? 'outline' : 'default'} className="uppercase text-[11px]">
                                                                                                    {slugToLabel(definition?.slug ?? selection.scope_slug)}{selection.permission === 'limit' && selection.limit ? ` (${selection.limit})` : ''}
                                                                                                </Badge>
                                                                                            ))}
                                                                                        </div>
                                                                                    </div>
                                                                                ))}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                );
                            })()}
                        </div>
                    </CardContent>
                </Card>
            )}
        </div>
    );
}
