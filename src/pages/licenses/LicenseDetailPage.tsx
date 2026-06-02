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
    Ticket,
    ShieldCheck,
    RefreshCw,
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
import type { CouponRedemption, DeviceReplacementToken, FeatureScopeSelection, License, LicenseDevice } from '@/types/api';
import { FeatureScopeSelector } from '@/components/licenses/FeatureScopeSelector';
import { entitlementsToSelections, slugToLabel, groupScopesForFeature, categorizeSelections } from '@/lib/entitlements';

function hasDetailContent(record?: Record<string, unknown>) {
    return Boolean(record && Object.keys(record).length > 0);
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

function getDeviceStatusBadge(status?: LicenseDevice['status']) {
    switch (status || 'trusted') {
        case 'revoked':
            return <Badge variant="destructive">Revoked</Badge>;
        case 'replacement_pending':
            return <Badge variant="secondary">Replacement pending</Badge>;
        case 'replaced':
            return <Badge variant="outline">Replaced</Badge>;
        case 'suspicious':
            return <Badge variant="destructive">Suspicious</Badge>;
        default:
            return <Badge variant="default">Trusted</Badge>;
    }
}

function shortValue(value?: string, length = 20) {
    if (!value) return '—';
    return value.length > length ? `${value.substring(0, length)}...` : value;
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
    const [issuedReplacementToken, setIssuedReplacementToken] = useState<{ token: string; token_record: DeviceReplacementToken } | null>(null);

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
    const [couponCode, setCouponCode] = useState('');

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
    const { data: couponRedemptionsResponse } = useQuery({
        queryKey: ['license-coupons', id],
        queryFn: () => api.listLicenseCoupons(id!),
        enabled: !!id,
    });
    const { data: replacementTokensResponse } = useQuery({
        queryKey: ['device-replacement-tokens', id],
        queryFn: () => api.listDeviceReplacementTokens(id!),
        enabled: !!id,
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

    const deleteDeviceMutation = useMutation({
        mutationFn: (fingerprint: string) => api.deleteDevice(id!, fingerprint),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['license', id] });
            queryClient.invalidateQueries({ queryKey: ['license-activations', id] });
            toast({ title: 'Device deleted successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete device',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const revokeDeviceMutation = useMutation({
        mutationFn: ({ fingerprint, reason }: { fingerprint: string; reason?: string }) => api.revokeDevice(id!, fingerprint, reason),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['license', id] });
            queryClient.invalidateQueries({ queryKey: ['device-replacement-tokens', id] });
            toast({ title: 'Device revoked' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to revoke device',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const reinstateDeviceMutation = useMutation({
        mutationFn: (fingerprint: string) => api.reinstateDevice(id!, fingerprint),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['license', id] });
            toast({ title: 'Device reinstated' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to reinstate device',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const replacementTokenMutation = useMutation({
        mutationFn: (fingerprint: string) => api.issueDeviceReplacementToken(id!, fingerprint, 24),
        onSuccess: (response) => {
            if (response.success && response.data) {
                setIssuedReplacementToken(response.data);
                queryClient.invalidateQueries({ queryKey: ['license', id] });
                queryClient.invalidateQueries({ queryKey: ['device-replacement-tokens', id] });
                toast({ title: 'Replacement token issued' });
            } else {
                toast({ title: 'Failed to issue replacement token', description: response.error || 'Unknown error', variant: 'destructive' });
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to issue replacement token',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

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

    const redeemCouponMutation = useMutation({
        mutationFn: (code: string) => api.redeemLicenseCoupon(id!, code),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['license', id] });
            queryClient.invalidateQueries({ queryKey: ['license-coupons', id] });
            setCouponCode('');
            toast({ title: 'Coupon redeemed successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to redeem coupon',
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
    const couponRedemptions: CouponRedemption[] = couponRedemptionsResponse?.data || [];
    const replacementTokens: DeviceReplacementToken[] = replacementTokensResponse?.data || [];

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
                    {issuedReplacementToken && (
                        <Dialog open={Boolean(issuedReplacementToken)} onOpenChange={() => setIssuedReplacementToken(null)}>
                            <DialogContent>
                                <DialogHeader>
                                    <DialogTitle>Device Replacement Token</DialogTitle>
                                    <DialogDescription>
                                        Share this one-time token with the replacement device. It expires {new Date(issuedReplacementToken.token_record.expires_at).toLocaleString()}.
                                    </DialogDescription>
                                </DialogHeader>
                                <div className="space-y-3 py-2">
                                    <Textarea readOnly value={issuedReplacementToken.token} className="font-mono text-xs" />
                                </div>
                                <DialogFooter>
                                    <Button onClick={() => copyToClipboard(issuedReplacementToken.token)}>Copy</Button>
                                    <Button variant="ghost" onClick={() => setIssuedReplacementToken(null)}>Close</Button>
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
                                    <TableHead>Device</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Proof</TableHead>
                                    <TableHead>Last Seen</TableHead>
                                    <TableHead className="w-[180px]">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {devices.map(([fingerprint, device]) => (
                                    <TableRow key={fingerprint}>
                                        <TableCell className="max-w-[280px]">
                                            <div className="space-y-1">
                                                <div className="font-mono text-sm">{shortValue(fingerprint, 28)}</div>
                                                {device.device_key_id && (
                                                    <div className="text-xs text-muted-foreground">key {shortValue(device.device_key_id, 18)}</div>
                                                )}
                                                {device.replaced_by_fingerprint && (
                                                    <div className="text-xs text-muted-foreground">replaced by {shortValue(device.replaced_by_fingerprint, 14)}</div>
                                                )}
                                                {device.hardware_fingerprint && (
                                                    <div className="text-xs text-muted-foreground">hw {shortValue(device.hardware_fingerprint, 22)}</div>
                                                )}
                                            </div>
                                        </TableCell>
                                        <TableCell>{getDeviceStatusBadge(device.status)}</TableCell>
                                        <TableCell>
                                            <div className="space-y-1 text-sm">
                                                <div className="flex items-center gap-1">
                                                    <ShieldCheck className="h-3 w-3" />
                                                    {device.key_provider || 'unknown'}
                                                </div>
                                                <div className="text-xs text-muted-foreground">
                                                    {device.public_key_algorithm || 'proof pending'}
                                                    {device.attestation_type ? ` / ${device.attestation_type}` : ''}
                                                </div>
                                                {device.last_proof_at && (
                                                    <div className="text-xs text-muted-foreground">
                                                        proof {new Date(device.last_proof_at).toLocaleDateString()}
                                                    </div>
                                                )}
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <div className="space-y-1 text-sm">
                                                <div className="flex items-center gap-1">
                                                    <Clock className="h-3 w-3" />
                                                    {device.last_seen_at ? new Date(device.last_seen_at).toLocaleDateString() : '—'}
                                                </div>
                                                {device.last_ip && <div className="text-xs text-muted-foreground">{device.last_ip}</div>}
                                            </div>
                                        </TableCell>
                                        <TableCell className="flex items-center gap-1">
                                            {device.status === 'revoked' ? (
                                                <Tooltip>
                                                    <TooltipTrigger asChild>
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            onClick={() => reinstateDeviceMutation.mutate(fingerprint)}
                                                            disabled={reinstateDeviceMutation.isPending}
                                                        >
                                                            <RotateCcw className="h-4 w-4" />
                                                        </Button>
                                                    </TooltipTrigger>
                                                    <TooltipContent>
                                                        <p>Reinstate device</p>
                                                    </TooltipContent>
                                                </Tooltip>
                                            ) : (
                                                <Tooltip>
                                                    <TooltipTrigger asChild>
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            onClick={() => revokeDeviceMutation.mutate({ fingerprint, reason: 'Revoked from admin UI' })}
                                                            disabled={revokeDeviceMutation.isPending}
                                                        >
                                                            <Ban className="h-4 w-4" />
                                                        </Button>
                                                    </TooltipTrigger>
                                                    <TooltipContent>
                                                        <p>Revoke device</p>
                                                    </TooltipContent>
                                                </Tooltip>
                                            )}
                                            <Tooltip>
                                                <TooltipTrigger asChild>
                                                    <Button
                                                        variant="ghost"
                                                        size="icon"
                                                        onClick={() => replacementTokenMutation.mutate(fingerprint)}
                                                        disabled={replacementTokenMutation.isPending || device.status === 'replaced'}
                                                    >
                                                        <RefreshCw className="h-4 w-4" />
                                                    </Button>
                                                </TooltipTrigger>
                                                <TooltipContent>
                                                    <p>Issue replacement token</p>
                                                </TooltipContent>
                                            </Tooltip>
                                            <AlertDialog>
                                                <Tooltip>
                                                    <TooltipTrigger asChild>
                                                        <AlertDialogTrigger asChild>
                                                            <Button variant="ghost" size="icon">
                                                                <Trash2 className="h-4 w-4" />
                                                            </Button>
                                                        </AlertDialogTrigger>
                                                    </TooltipTrigger>
                                                    <TooltipContent>
                                                        <p>Delete device</p>
                                                    </TooltipContent>
                                                </Tooltip>
                                                <AlertDialogContent>
                                                    <AlertDialogHeader>
                                                        <AlertDialogTitle>Delete Device</AlertDialogTitle>
                                                        <AlertDialogDescription>
                                                            This will remove the device from this license. The device
                                                            will need to reactivate to use the software.
                                                        </AlertDialogDescription>
                                                    </AlertDialogHeader>
                                                    <AlertDialogFooter>
                                                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                                                        <AlertDialogAction
                                                            onClick={() => deleteDeviceMutation.mutate(fingerprint)}
                                                            disabled={deleteDeviceMutation.isPending}
                                                        >
                                                            {deleteDeviceMutation.isPending ? 'Deleting…' : 'Delete'}
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

            {replacementTokens.length > 0 && (
                <Card>
                    <CardHeader>
                        <CardTitle>Replacement Tokens</CardTitle>
                        <CardDescription>One-time device replacement grants for this license</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Old Device</TableHead>
                                    <TableHead>Replacement</TableHead>
                                    <TableHead>Expires</TableHead>
                                    <TableHead>Status</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {replacementTokens.map((token) => (
                                    <TableRow key={token.id}>
                                        <TableCell className="font-mono text-xs">{shortValue(token.old_fingerprint, 24)}</TableCell>
                                        <TableCell className="font-mono text-xs">{shortValue(token.replacement_fingerprint, 24)}</TableCell>
                                        <TableCell>{new Date(token.expires_at).toLocaleString()}</TableCell>
                                        <TableCell>
                                            {token.revoked_at ? <Badge variant="destructive">Revoked</Badge> : token.used_at ? <Badge variant="secondary">Used</Badge> : <Badge variant="default">Open</Badge>}
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </CardContent>
                </Card>
            )}

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Ticket className="h-5 w-5" />
                        Coupon Extensions
                    </CardTitle>
                    <CardDescription>
                        Redeem coupon codes to add custom limits, flags, settings, and scope extensions for this license.
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex flex-col gap-3 md:flex-row">
                        <Input
                            value={couponCode}
                            onChange={(e) => setCouponCode(e.target.value.toUpperCase())}
                            placeholder="ENTER-COUPON-CODE"
                            className="font-mono"
                        />
                        <Button
                            onClick={() => redeemCouponMutation.mutate(couponCode.trim())}
                            disabled={redeemCouponMutation.isPending || !couponCode.trim()}
                        >
                            {redeemCouponMutation.isPending ? 'Redeeming...' : 'Redeem Coupon'}
                        </Button>
                    </div>
                    {couponRedemptions.length === 0 ? (
                        <div className="rounded-md border border-dashed p-6 text-sm text-muted-foreground">
                            No coupon extensions have been redeemed for this license yet.
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {couponRedemptions.map((redemption) => (
                                <div key={redemption.id} className="rounded-xl border p-4">
                                    <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                                        <div className="space-y-1">
                                            <div className="flex items-center gap-2">
                                                <Badge variant="outline" className="font-mono">
                                                    {redemption.coupon_code}
                                                </Badge>
                                                {redemption.redeemed_by && (
                                                    <Badge variant="secondary">
                                                        by {redemption.redeemed_by}
                                                    </Badge>
                                                )}
                                            </div>
                                            <p className="text-sm text-muted-foreground">
                                                Redeemed {new Date(redemption.redeemed_at).toLocaleString()}
                                            </p>
                                        </div>
                                        <div className="text-sm text-muted-foreground">
                                            Client: <span className="font-medium text-foreground">{redemption.client_id}</span>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
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
                                                                            {'type' in (license.entitlements?.features?.[feature.feature_slug] || {}) && (
                                                                                <Badge variant="secondary">
                                                                                    {(license.entitlements?.features?.[feature.feature_slug]?.type || 'boolean').toString()}
                                                                                </Badge>
                                                                            )}
                                                                            {feature.feature_slug && (
                                                                                <Badge variant="outline" className="ml-auto">{feature.feature_slug}</Badge>
                                                                            )}
                                                                        </div>
                                                                        {(() => {
                                                                            const grant = license.entitlements?.features?.[feature.feature_slug];
                                                                            if (!grant) return null;
                                                                            return (
                                                                                <>
                                                                                    {(hasDetailContent(grant.flags) || hasDetailContent(grant.settings) || hasDetailContent(grant.limits) || hasDetailContent(grant.usage)) && (
                                                                                        <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                                                                                            {hasDetailContent(grant.flags) && (
                                                                                                <div className="rounded-md border bg-muted/20 p-3">
                                                                                                    <p className="text-xs uppercase text-muted-foreground">Flags</p>
                                                                                                    <div className="mt-2 flex flex-wrap gap-2">
                                                                                                        {Object.entries(grant.flags || {}).map(([key, value]) => (
                                                                                                            <Badge key={key} variant={value ? 'default' : 'secondary'}>
                                                                                                                {key}: {value ? 'on' : 'off'}
                                                                                                            </Badge>
                                                                                                        ))}
                                                                                                    </div>
                                                                                                </div>
                                                                                            )}
                                                                                            {hasDetailContent(grant.settings) && (
                                                                                                <div className="rounded-md border bg-muted/20 p-3">
                                                                                                    <p className="text-xs uppercase text-muted-foreground">Settings</p>
                                                                                                    <div className="mt-2 space-y-1 text-sm">
                                                                                                        {Object.entries(grant.settings || {}).map(([key, value]) => (
                                                                                                            <p key={key}><span className="font-medium">{key}</span>: {value}</p>
                                                                                                        ))}
                                                                                                    </div>
                                                                                                </div>
                                                                                            )}
                                                                                            {hasDetailContent(grant.limits) && (
                                                                                                <div className="rounded-md border bg-muted/20 p-3">
                                                                                                    <p className="text-xs uppercase text-muted-foreground">Limits</p>
                                                                                                    <div className="mt-2 space-y-1 text-sm">
                                                                                                        {Object.entries(grant.limits || {}).map(([key, value]) => (
                                                                                                            <p key={key}><span className="font-medium">{key}</span>: {value}</p>
                                                                                                        ))}
                                                                                                    </div>
                                                                                                </div>
                                                                                            )}
                                                                                            {hasDetailContent(grant.usage) && (
                                                                                                <div className="rounded-md border bg-muted/20 p-3">
                                                                                                    <p className="text-xs uppercase text-muted-foreground">Usage</p>
                                                                                                    <div className="mt-2 space-y-1 text-sm">
                                                                                                        {Object.entries(grant.usage || {}).map(([key, value]) => (
                                                                                                            <p key={key}>
                                                                                                                <span className="font-medium">{key}</span>
                                                                                                                {value.limit ? `: ${value.limit}` : ''}
                                                                                                                {value.window_seconds ? ` / ${value.window_seconds}s` : ''}
                                                                                                            </p>
                                                                                                        ))}
                                                                                                    </div>
                                                                                                </div>
                                                                                            )}
                                                                                        </div>
                                                                                    )}
                                                                                </>
                                                                            );
                                                                        })()}
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
                                                                                                <div key={selection.scope_slug} className="rounded-xl border bg-background p-2">
                                                                                                    <Badge variant={selection.permission === 'deny' ? 'destructive' : selection.permission === 'limit' ? 'outline' : 'default'} className="uppercase text-[11px]">
                                                                                                        {slugToLabel(definition?.slug ?? selection.scope_slug)}{selection.permission === 'limit' && selection.limit ? ` (${selection.limit})` : ''}
                                                                                                    </Badge>
                                                                                                    {(() => {
                                                                                                        const scopeGrant = license.entitlements?.features?.[feature.feature_slug]?.scopes?.[selection.scope_slug];
                                                                                                        if (!scopeGrant) return null;
                                                                                                        return (
                                                                                                            <>
                                                                                                                {(hasDetailContent(scopeGrant.flags) || hasDetailContent(scopeGrant.settings) || hasDetailContent(scopeGrant.limits) || hasDetailContent(scopeGrant.usage)) && (
                                                                                                                    <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                                                                                                                        {Object.entries(scopeGrant.flags || {}).map(([key, value]) => (
                                                                                                                            <p key={`flag-${key}`}>flag {key}: {value ? 'on' : 'off'}</p>
                                                                                                                        ))}
                                                                                                                        {Object.entries(scopeGrant.settings || {}).map(([key, value]) => (
                                                                                                                            <p key={`setting-${key}`}>setting {key}: {value}</p>
                                                                                                                        ))}
                                                                                                                        {Object.entries(scopeGrant.limits || {}).map(([key, value]) => (
                                                                                                                            <p key={`limit-${key}`}>limit {key}: {value}</p>
                                                                                                                        ))}
                                                                                                                        {Object.entries(scopeGrant.usage || {}).map(([key, value]) => (
                                                                                                                            <p key={`usage-${key}`}>usage {key}: {value.limit ?? 'unlimited'}{value.window_seconds ? ` / ${value.window_seconds}s` : ''}</p>
                                                                                                                        ))}
                                                                                                                    </div>
                                                                                                                )}
                                                                                                            </>
                                                                                                        );
                                                                                                    })()}
                                                                                                </div>
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
