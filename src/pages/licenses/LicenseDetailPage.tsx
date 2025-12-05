import { useState } from 'react';
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
import type { License, LicenseDevice } from '@/types/api';

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

    const { data: licenseResponse, isLoading: licenseLoading } = useQuery({
        queryKey: ['license', id],
        queryFn: () => api.getLicense(id!),
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

    const deactivateMutation = useMutation({
        mutationFn: (fingerprint: string) => api.deactivateDevice(id!, fingerprint),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['license', id] });
            queryClient.invalidateQueries({ queryKey: ['license-activations', id] });
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

    const license = licenseResponse?.data;

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

    return (
        <div className="space-y-6">
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
                            <div className="font-medium">{license.email}</div>
                        </div>

                        <div className="space-y-2">
                            <Label className="text-muted-foreground">Client ID</Label>
                            <div>
                                <Link
                                    to={`/clients/${license.client_id}`}
                                    className="text-primary hover:underline"
                                >
                                    {license.client_id}
                                </Link>
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
                    <CardHeader>
                        <CardTitle>Entitlements</CardTitle>
                        <CardDescription>Features included in this license</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-3">
                            {Object.entries(license.entitlements.features).map(([slug, entitlement]) => (
                                <div
                                    key={slug}
                                    className="flex items-center gap-2 rounded-md border p-3"
                                >
                                    {entitlement.enabled ? (
                                        <CheckCircle className="h-4 w-4 text-primary" />
                                    ) : (
                                        <XCircle className="h-4 w-4 text-destructive" />
                                    )}
                                    <span className="text-sm">{slug}</span>
                                    {entitlement.category && (
                                        <Badge variant="outline" className="ml-auto">
                                            {entitlement.category}
                                        </Badge>
                                    )}
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}
        </div>
    );
}
