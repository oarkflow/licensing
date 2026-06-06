import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
    Key,
    Copy,
    Ban,
    RotateCcw,
    Trash2,
    Clock,
    CheckCircle,
    XCircle,
    Ticket,
    ShieldCheck,
    RefreshCw,
    ArrowUpCircle,
} from 'lucide-react';
import {
    Tooltip,
    TooltipContent,
    TooltipTrigger,
} from '@/components/ui/tooltip';
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import type { CouponRedemption, DeviceReplacementToken, FeatureScopeSelection, License, LicenseDevice, Plan, UpgradeLicenseResponse } from '@/types/api';
import { FeatureScopeSelector } from '@/components/licenses/FeatureScopeSelector';
import { entitlementsToSelections, slugToLabel, groupScopesForFeature, categorizeSelections } from '@/lib/entitlements';
import { DataPanel, EmptyState, MetricTile, PageHeader } from '@/components/layout/PageShell';

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

function DetailRow({
    label,
    children,
}: {
    label: string;
    children: ReactNode;
}) {
    return (
        <div className="grid gap-1 border-t px-3 py-2 text-sm md:grid-cols-[180px_1fr] md:gap-4">
            <div className="text-xs font-medium uppercase text-muted-foreground">{label}</div>
            <div className="min-w-0 text-foreground">{children}</div>
        </div>
    );
}

function SectionTitle({
    title,
    description,
    actions,
}: {
    title: string;
    description?: string;
    actions?: ReactNode;
}) {
    return (
        <div className="flex flex-col gap-2 border-b px-3 py-2 md:flex-row md:items-center md:justify-between">
            <div>
                <h2 className="text-sm font-semibold">{title}</h2>
                {description && <p className="text-xs text-muted-foreground">{description}</p>}
            </div>
            {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
    );
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
    const [upgradeDialogOpen, setUpgradeDialogOpen] = useState(false);
    const [upgradePlanId, setUpgradePlanId] = useState('');
    const [upgradeMaxDevices, setUpgradeMaxDevices] = useState<number | undefined>();
    const [upgradeDurationDays, setUpgradeDurationDays] = useState<number | undefined>();
    const [upgradeTrial, setUpgradeTrial] = useState(false);
    const [upgradeResult, setUpgradeResult] = useState<UpgradeLicenseResponse | null>(null);

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
    const { data: upgradePlansResponse, isFetching: upgradePlansLoading } = useQuery({
        queryKey: ['product-plans', license?.product_id],
        queryFn: () => api.listPlans(license!.product_id!),
        enabled: upgradeDialogOpen && Boolean(license?.product_id),
    });
    const upgradePlans: Plan[] = useMemo(
        () => (upgradePlansResponse?.data || []).filter((plan) => plan.is_active),
        [upgradePlansResponse?.data]
    );
    const selectedUpgradePlan = upgradePlans.find((plan) => plan.id === upgradePlanId);

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

    const upgradeMutation = useMutation({
        mutationFn: () => api.upgradeLicense(id!, {
            product_id: license!.product_id!,
            plan_id: upgradePlanId,
            max_devices: upgradeMaxDevices,
            duration_days: upgradeDurationDays,
            trial: upgradeTrial,
            metadata: { source: 'admin-ui' },
        }),
        onSuccess: (response) => {
            if (response.success && response.data?.license) {
                setUpgradeResult(response.data);
                queryClient.invalidateQueries({ queryKey: ['license', id] });
                queryClient.invalidateQueries({ queryKey: ['licenses'] });
                queryClient.invalidateQueries({ queryKey: ['subscriptions'] });
                queryClient.invalidateQueries({ queryKey: ['license', response.data.license.id] });
                toast({ title: 'License upgraded' });
            } else {
                toast({ title: 'Failed to upgrade license', description: response.error || 'Unknown error', variant: 'destructive' });
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to upgrade license',
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

    useEffect(() => {
        if (!upgradeDialogOpen) {
            return;
        }
        if (!upgradePlanId && upgradePlans.length > 0) {
            const currentIndex = upgradePlans.findIndex((plan) => plan.id === license?.plan_id);
            const nextPlan = upgradePlans.find((plan, index) => plan.id !== license?.plan_id && index > currentIndex)
                || upgradePlans.find((plan) => plan.id !== license?.plan_id)
                || upgradePlans[0];
            setUpgradePlanId(nextPlan.id);
        }
    }, [upgradeDialogOpen, upgradePlanId, upgradePlans, license?.plan_id]);

    useEffect(() => {
        if (!selectedUpgradePlan || upgradeResult) {
            return;
        }
        const carriedDevices = license?.current_activations || license?.device_count || 0;
        const planMax = selectedUpgradePlan.max_devices || undefined;
        const nextMax = Math.max(carriedDevices, planMax || license?.max_devices || carriedDevices || 1);
        setUpgradeMaxDevices(nextMax);
        setUpgradeDurationDays(selectedUpgradePlan.duration_days || undefined);
        if (!selectedUpgradePlan.trial_days) {
            setUpgradeTrial(false);
        }
    }, [selectedUpgradePlan?.id, selectedUpgradePlan?.max_devices, selectedUpgradePlan?.duration_days, selectedUpgradePlan?.trial_days, license?.current_activations, license?.device_count, license?.max_devices, upgradeResult]);

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
                <DialogContent className="w-[calc(100vw-1rem)] max-w-[calc(100vw-1rem)] lg:w-[80vw] lg:max-w-[80vw]">
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
            <PageHeader
                eyebrow="Licensing"
                title="License Details"
                description={shortValue(license.license_key, 42)}
                backTo="/licenses"
                backLabel="Licenses"
                actions={
                    <>
                        <Dialog open={issueDialogOpen} onOpenChange={setIssueDialogOpen}>
                            <DialogTrigger asChild>
                                <Button variant="outline" size="sm">Offline Token</Button>
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
                                        <Input placeholder="device fingerprint" value={deviceFingerprint} onChange={(e) => setDeviceFingerprint(e.target.value)} />
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
                                    <Button onClick={() => issueMutation.mutate({ license_key: license.license_key, device_fingerprint: deviceFingerprint, max_uses: tokenMaxUses, validity_days: tokenValidity })}>
                                        {issueMutation.isPending ? 'Issuing...' : 'Issue Token'}
                                    </Button>
                                </DialogFooter>
                            </DialogContent>
                        </Dialog>

                        <Dialog
                            open={upgradeDialogOpen}
                            onOpenChange={(open) => {
                                setUpgradeDialogOpen(open);
                                if (open) {
                                    setUpgradeResult(null);
                                }
                            }}
                        >
                            <DialogTrigger asChild>
                                <Button variant="outline" size="sm" disabled={!license.product_id || license.is_revoked}>
                                    <ArrowUpCircle className="h-3.5 w-3.5" />
                                    Upgrade
                                </Button>
                            </DialogTrigger>
                            <DialogContent>
                                <DialogHeader>
                                    <DialogTitle>Upgrade License</DialogTitle>
                                    <DialogDescription>
                                        A new license key will be issued and this license will be revoked.
                                    </DialogDescription>
                                </DialogHeader>
                                {upgradeResult?.license ? (
                                    <div className="space-y-3 py-2">
                                        <div className="space-y-1">
                                            <Label>New license key</Label>
                                            <div className="flex gap-2">
                                                <Input readOnly value={upgradeResult.license.license_key} className="font-mono text-xs" />
                                                <Button type="button" variant="outline" size="icon" onClick={() => copyToClipboard(upgradeResult.license.license_key)}>
                                                    <Copy className="h-4 w-4" />
                                                </Button>
                                            </div>
                                        </div>
                                        <div className="grid gap-2 sm:grid-cols-2">
                                            <div className="space-y-1">
                                                <Label>Email</Label>
                                                <Input readOnly value={upgradeResult.license.email || ''} />
                                            </div>
                                            <div className="space-y-1">
                                                <Label>Client ID</Label>
                                                <Input readOnly value={upgradeResult.license.client_id || ''} className="font-mono text-xs" />
                                            </div>
                                        </div>
                                        <Textarea
                                            readOnly
                                            value={JSON.stringify({
                                                email: upgradeResult.license.email ?? '',
                                                client_id: upgradeResult.license.client_id ?? '',
                                                license_key: upgradeResult.license.license_key ?? '',
                                            }, null, 2)}
                                            className="min-h-28 font-mono text-xs"
                                        />
                                    </div>
                                ) : (
                                    <div className="space-y-4 py-2">
                                        <div className="space-y-1">
                                            <Label>Target plan</Label>
                                            <Select value={upgradePlanId} onValueChange={setUpgradePlanId} disabled={upgradePlansLoading || upgradeMutation.isPending}>
                                                <SelectTrigger>
                                                    <SelectValue placeholder={upgradePlansLoading ? 'Loading plans...' : 'Select plan'} />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    {upgradePlans.map((plan) => (
                                                        <SelectItem key={plan.id} value={plan.id}>
                                                            {plan.name} ({plan.slug})
                                                        </SelectItem>
                                                    ))}
                                                </SelectContent>
                                            </Select>
                                        </div>
                                        <div className="grid gap-3 sm:grid-cols-2">
                                            <div className="space-y-1">
                                                <Label>Max devices</Label>
                                                <Input
                                                    type="number"
                                                    min={license.current_activations || license.device_count || 1}
                                                    value={upgradeMaxDevices ?? ''}
                                                    onChange={(e) => setUpgradeMaxDevices(e.target.value ? Number(e.target.value) : undefined)}
                                                    disabled={upgradeMutation.isPending}
                                                />
                                            </div>
                                            <div className="space-y-1">
                                                <Label>Duration days</Label>
                                                <Input
                                                    type="number"
                                                    min={1}
                                                    value={upgradeDurationDays ?? ''}
                                                    onChange={(e) => setUpgradeDurationDays(e.target.value ? Number(e.target.value) : undefined)}
                                                    disabled={upgradeMutation.isPending}
                                                />
                                            </div>
                                        </div>
                                        {selectedUpgradePlan?.trial_days ? (
                                            <div className="flex items-center justify-between rounded-md border px-3 py-2">
                                                <div>
                                                    <Label htmlFor="upgrade-trial">Trial</Label>
                                                    <p className="text-xs text-muted-foreground">{selectedUpgradePlan.trial_days} days</p>
                                                </div>
                                                <Switch id="upgrade-trial" checked={upgradeTrial} onCheckedChange={setUpgradeTrial} disabled={upgradeMutation.isPending} />
                                            </div>
                                        ) : null}
                                    </div>
                                )}
                                <DialogFooter>
                                    {upgradeResult?.license ? (
                                        <>
                                            <Button
                                                type="button"
                                                variant="outline"
                                                onClick={() => copyToClipboard(JSON.stringify({
                                                    email: upgradeResult.license.email ?? '',
                                                    client_id: upgradeResult.license.client_id ?? '',
                                                    license_key: upgradeResult.license.license_key ?? '',
                                                }, null, 2))}
                                            >
                                                Copy JSON
                                            </Button>
                                            <Button type="button" onClick={() => navigate(`/licenses/${upgradeResult.license.id}`)}>
                                                Open License
                                            </Button>
                                        </>
                                    ) : (
                                        <>
                                            <Button type="button" variant="ghost" onClick={() => setUpgradeDialogOpen(false)} disabled={upgradeMutation.isPending}>
                                                Cancel
                                            </Button>
                                            <Button
                                                type="button"
                                                onClick={() => upgradeMutation.mutate()}
                                                disabled={!upgradePlanId || !license.product_id || upgradeMutation.isPending}
                                            >
                                                {upgradeMutation.isPending ? 'Upgrading...' : 'Upgrade'}
                                            </Button>
                                        </>
                                    )}
                                </DialogFooter>
                            </DialogContent>
                        </Dialog>

                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                                const licenseJson = JSON.stringify({
                                    email: license.email ?? '',
                                    client_id: license.client_id ?? '',
                                    license_key: license.license_key ?? '',
                                }, null, 2);
                                copyToClipboard(licenseJson);
                            }}
                        >
                            <Copy className="h-3.5 w-3.5" />
                            Copy JSON
                        </Button>

                        {license.is_revoked ? (
                            <AlertDialog>
                                <AlertDialogTrigger asChild>
                                    <Button variant="outline" size="sm">
                                        <RotateCcw className="h-3.5 w-3.5" />
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
                                        <AlertDialogAction onClick={() => reinstateMutation.mutate()} disabled={reinstateMutation.isPending}>
                                            {reinstateMutation.isPending ? 'Reinstating...' : 'Reinstate'}
                                        </AlertDialogAction>
                                    </AlertDialogFooter>
                                </AlertDialogContent>
                            </AlertDialog>
                        ) : (
                            <Dialog open={revokeDialogOpen} onOpenChange={setRevokeDialogOpen}>
                                <DialogTrigger asChild>
                                    <Button variant="destructive" size="sm">
                                        <Ban className="h-3.5 w-3.5" />
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
                                    <div className="space-y-2 py-3">
                                        <Label htmlFor="reason">Reason for revocation</Label>
                                        <Textarea
                                            id="reason"
                                            placeholder="Enter the reason for revoking this license..."
                                            value={revokeReason}
                                            onChange={(e) => setRevokeReason(e.target.value)}
                                        />
                                    </div>
                                    <DialogFooter>
                                        <Button variant="ghost" onClick={() => setRevokeDialogOpen(false)}>Cancel</Button>
                                        <Button variant="destructive" onClick={() => revokeMutation.mutate(revokeReason)} disabled={revokeMutation.isPending}>
                                            {revokeMutation.isPending ? 'Revoking...' : 'Revoke License'}
                                        </Button>
                                    </DialogFooter>
                                </DialogContent>
                            </Dialog>
                        )}
                    </>
                }
            />

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
                            <Button variant="ghost" onClick={() => setIssuedTokenBundle(null)}>Close</Button>
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

            <DataPanel>
                <div className="grid divide-y md:grid-cols-4 md:divide-x md:divide-y-0">
                    <MetricTile label="Status" value={getLicenseStatusBadge(license)} />
                    <MetricTile label="Devices" value={`${license.device_count || 0} / ${license.max_devices || '∞'}`} />
                    <MetricTile label="Issued" value={license.issued_at ? new Date(license.issued_at).toLocaleDateString() : '-'} />
                    <MetricTile label="Expires" value={license.expires_at ? new Date(license.expires_at).toLocaleDateString() : 'Never'} />
                </div>
            </DataPanel>

            <DataPanel>
                <SectionTitle title="License Record" description="Canonical license identifiers and ownership." />
                <DetailRow label="License Key">
                    <div className="flex min-w-0 items-center gap-2">
                        <code className="min-w-0 truncate font-mono text-xs">{license.license_key}</code>
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(license.license_key)}>
                            <Copy className="h-3.5 w-3.5" />
                        </Button>
                    </div>
                </DetailRow>
                <DetailRow label="Email">
                    <div className="flex min-w-0 items-center gap-2">
                        <span className="min-w-0 truncate">{license.email || '-'}</span>
                        {license.email && (
                            <Button variant="outline" size="icon" onClick={() => copyToClipboard(license.email ?? '')} aria-label="Copy email">
                                <Copy className="h-3.5 w-3.5" />
                            </Button>
                        )}
                    </div>
                </DetailRow>
                <DetailRow label="Client">
                    {license.client_id ? (
                        <div className="flex min-w-0 items-center gap-2">
                            <Link to={`/clients/${license.client_id}`} className="min-w-0 truncate font-mono text-xs text-primary hover:underline">
                                {license.client_id}
                            </Link>
                            <Button variant="outline" size="icon" onClick={() => copyToClipboard(license.client_id ?? '')} aria-label="Copy client ID">
                                <Copy className="h-3.5 w-3.5" />
                            </Button>
                        </div>
                    ) : '-'}
                </DetailRow>
                <DetailRow label="Product">
                    {license.product_id ? (
                        <Link to={`/products/${license.product_id}`} className="font-mono text-xs text-primary hover:underline">
                            {license.product_id}
                        </Link>
                    ) : '-'}
                </DetailRow>
                <DetailRow label="Plan">{license.plan_slug || '-'}</DetailRow>
                {license.is_revoked && license.revoke_reason && (
                    <DetailRow label="Revoke Reason">
                        <span className="text-destructive">{license.revoke_reason}</span>
                    </DetailRow>
                )}
            </DataPanel>

            <DataPanel>
                <SectionTitle
                    title="Devices"
                    description="Trusted device identities, proof metadata, and replacement controls."
                />
                {devices.length === 0 ? (
                    <EmptyState
                        title="No devices"
                        description="No devices are currently using this license."
                    />
                ) : (
                    <div className="overflow-x-auto">
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
                    </div>
                )}
            </DataPanel>

            {replacementTokens.length > 0 && (
                <DataPanel>
                    <SectionTitle
                        title="Replacement Tokens"
                        description="One-time device replacement grants for this license."
                    />
                    <div className="overflow-x-auto">
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
                    </div>
                </DataPanel>
            )}

            <DataPanel>
                <SectionTitle
                    title="Coupon Extensions"
                    description="Redeem coupon codes to add custom limits, flags, settings, and scope extensions."
                    actions={<Ticket className="h-4 w-4 text-muted-foreground" />}
                />
                <div className="space-y-3 p-3">
                    <div className="flex flex-col gap-2 md:flex-row">
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
                        <EmptyState
                            title="No coupon extensions"
                            description="No coupon extensions have been redeemed for this license yet."
                        />
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Code</TableHead>
                                    <TableHead>Client</TableHead>
                                    <TableHead>Redeemed By</TableHead>
                                    <TableHead>Redeemed At</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {couponRedemptions.map((redemption) => (
                                    <TableRow key={redemption.id}>
                                        <TableCell><Badge variant="outline" className="font-mono">{redemption.coupon_code}</Badge></TableCell>
                                        <TableCell className="font-mono text-xs">{redemption.client_id}</TableCell>
                                        <TableCell>{redemption.redeemed_by || '-'}</TableCell>
                                        <TableCell>{new Date(redemption.redeemed_at).toLocaleString()}</TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </div>
            </DataPanel>

            {license.entitlements && license.entitlements.features && Object.keys(license.entitlements.features).length > 0 && (
                <DataPanel>
                    <SectionTitle
                        title="Entitlements"
                        description="Feature grants summarized for review. Use the editor for detailed scope changes."
                        actions={
                            canEditScopes ? (
                                <Button variant="outline" size="sm" onClick={() => setEntitlementDialogOpen(true)}>
                                    Adjust Feature Scopes
                                </Button>
                            ) : (
                                <Badge variant="secondary">Link to plan to edit</Badge>
                            )
                        }
                    />
                    {(() => {
                        const selections = entitlementsToSelections(license.entitlements);
                        const categories = categorizeSelections(selections);
                        const rows = (['cli', 'gui', 'api', 'other'] as Array<'cli' | 'gui' | 'api' | 'other'>)
                            .flatMap((category) => categories[category].map((feature) => ({ category, feature })));

                        return rows.length === 0 ? (
                            <EmptyState title="No entitlements" description="This license has no feature grants." />
                        ) : (
                            <div className="overflow-x-auto">
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>Category</TableHead>
                                            <TableHead>Feature</TableHead>
                                            <TableHead>Status</TableHead>
                                            <TableHead>Type</TableHead>
                                            <TableHead>Scopes</TableHead>
                                            <TableHead>Metadata</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {rows.map(({ category, feature }) => {
                                            const grant = license.entitlements?.features?.[feature.feature_slug];
                                            const groups = groupScopesForFeature(feature.feature_slug, feature.scopes);
                                            const metadata = [
                                                hasDetailContent(grant?.flags) ? 'flags' : null,
                                                hasDetailContent(grant?.settings) ? 'settings' : null,
                                                hasDetailContent(grant?.limits) ? 'limits' : null,
                                                hasDetailContent(grant?.usage) ? 'usage' : null,
                                            ].filter(Boolean);

                                            return (
                                                <TableRow key={feature.feature_slug}>
                                                    <TableCell>
                                                        <Badge variant="outline">{category.toUpperCase()}</Badge>
                                                    </TableCell>
                                                    <TableCell>
                                                        <div className="space-y-1">
                                                            <div className="font-medium">{slugToLabel(feature.feature_slug)}</div>
                                                            <div className="font-mono text-xs text-muted-foreground">{feature.feature_slug}</div>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell>
                                                        {feature.enabled ? (
                                                            <Badge><CheckCircle className="h-3 w-3" /> Enabled</Badge>
                                                        ) : (
                                                            <Badge variant="destructive"><XCircle className="h-3 w-3" /> Disabled</Badge>
                                                        )}
                                                    </TableCell>
                                                    <TableCell>{(grant?.type || 'boolean').toString()}</TableCell>
                                                    <TableCell>
                                                        {groups.length === 0 ? (
                                                            <span className="text-muted-foreground">None</span>
                                                        ) : (
                                                            <div className="flex flex-wrap gap-1">
                                                                {groups.map((group) => (
                                                                    <Badge key={group.title} variant="secondary">
                                                                        {group.title}: {group.scopes.length}
                                                                    </Badge>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </TableCell>
                                                    <TableCell>
                                                        {metadata.length === 0 ? (
                                                            <span className="text-muted-foreground">-</span>
                                                        ) : (
                                                            <div className="flex flex-wrap gap-1">
                                                                {metadata.map((item) => (
                                                                    <Badge key={item} variant="outline">{item}</Badge>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </TableCell>
                                                </TableRow>
                                            );
                                        })}
                                    </TableBody>
                                </Table>
                            </div>
                        );
                    })()}
                </DataPanel>
            )}
        </div>
    );
}
