import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
    ArrowLeft,
    Users,
    Ban,
    CheckCircle,
    Key,
    Mail,
    Building,
    Calendar,
} from 'lucide-react';
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
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import type { Client, License } from '@/types/api';

function getClientStatusBadge(client: Client) {
    switch (client.status) {
        case 'active':
            return <Badge variant="default">Active</Badge>;
        case 'banned':
            return <Badge variant="destructive">Banned</Badge>;
        default:
            return <Badge variant="outline">{client.status}</Badge>;
    }
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

export function ClientDetailPage() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const [banReason, setBanReason] = useState('');
    const [banDialogOpen, setBanDialogOpen] = useState(false);

    const { data: clientResponse, isLoading: clientLoading } = useQuery({
        queryKey: ['client', id],
        queryFn: () => api.getClient(id!),
        enabled: !!id,
    });

    const { data: licensesResponse, isLoading: licensesLoading } = useQuery({
        queryKey: ['client-licenses', id],
        queryFn: () => api.getClientLicenses(id!),
        enabled: !!id,
    });

    const banMutation = useMutation({
        mutationFn: (reason: string) => api.banClient(id!, reason),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['client', id] });
            setBanDialogOpen(false);
            toast({ title: 'Client banned successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to ban client',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const unbanMutation = useMutation({
        mutationFn: () => api.unbanClient(id!),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['client', id] });
            toast({ title: 'Client unbanned successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to unban client',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    if (clientLoading) {
        return (
            <div className="space-y-6">
                <Skeleton className="h-10 w-48" />
                <Skeleton className="h-64 w-full" />
            </div>
        );
    }

    const client = clientResponse?.data;

    if (!client) {
        return (
            <div className="flex flex-col items-center justify-center py-12">
                <Users className="h-12 w-12 text-muted-foreground" />
                <h2 className="mt-4 text-lg font-semibold">Client not found</h2>
                <Button asChild className="mt-4">
                    <Link to="/clients">Back to Clients</Link>
                </Button>
            </div>
        );
    }

    const licenses: License[] = licensesResponse?.data || [];

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div className="flex-1">
                    <h1 className="text-3xl font-bold tracking-tight">{client.email}</h1>
                    <p className="text-muted-foreground">Client details and licenses</p>
                </div>
                <div className="flex gap-2">
                    {client.status === 'banned' ? (
                        <AlertDialog>
                            <AlertDialogTrigger asChild>
                                <Button variant="outline">
                                    <CheckCircle className="mr-2 h-4 w-4" />
                                    Unban
                                </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                                <AlertDialogHeader>
                                    <AlertDialogTitle>Unban Client</AlertDialogTitle>
                                    <AlertDialogDescription>
                                        This will restore the client's access to all their licenses.
                                    </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                                    <AlertDialogAction
                                        onClick={() => unbanMutation.mutate()}
                                        disabled={unbanMutation.isPending}
                                    >
                                        {unbanMutation.isPending ? 'Unbanning...' : 'Unban Client'}
                                    </AlertDialogAction>
                                </AlertDialogFooter>
                            </AlertDialogContent>
                        </AlertDialog>
                    ) : (
                        <Dialog open={banDialogOpen} onOpenChange={setBanDialogOpen}>
                            <DialogTrigger asChild>
                                <Button variant="destructive">
                                    <Ban className="mr-2 h-4 w-4" />
                                    Ban
                                </Button>
                            </DialogTrigger>
                            <DialogContent>
                                <DialogHeader>
                                    <DialogTitle>Ban Client</DialogTitle>
                                    <DialogDescription>
                                        This will prevent the client from using any of their licenses.
                                    </DialogDescription>
                                </DialogHeader>
                                <div className="space-y-4 py-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="reason">Reason for ban</Label>
                                        <Textarea
                                            id="reason"
                                            placeholder="Enter the reason for banning this client..."
                                            value={banReason}
                                            onChange={(e) => setBanReason(e.target.value)}
                                        />
                                    </div>
                                </div>
                                <DialogFooter>
                                    <Button
                                        variant="ghost"
                                        onClick={() => setBanDialogOpen(false)}
                                    >
                                        Cancel
                                    </Button>
                                    <Button
                                        variant="destructive"
                                        onClick={() => banMutation.mutate(banReason)}
                                        disabled={banMutation.isPending}
                                    >
                                        {banMutation.isPending ? 'Banning...' : 'Ban Client'}
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
                        <CardTitle>Client Information</CardTitle>
                        <CardDescription>Basic client details</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="flex items-center gap-3">
                            <Mail className="h-4 w-4 text-muted-foreground" />
                            <div>
                                <Label className="text-muted-foreground">Email</Label>
                                <p className="font-medium">{client.email}</p>
                            </div>
                        </div>

                        <div className="flex items-center gap-3">
                            <Calendar className="h-4 w-4 text-muted-foreground" />
                            <div>
                                <Label className="text-muted-foreground">Joined</Label>
                                <p className="font-medium">
                                    {client.created_at ? new Date(client.created_at).toLocaleDateString() : '—'}
                                </p>
                            </div>
                        </div>

                        <div className="flex items-center gap-3">
                            <Users className="h-4 w-4 text-muted-foreground" />
                            <div>
                                <Label className="text-muted-foreground">Status</Label>
                                <div className="mt-1">{getClientStatusBadge(client)}</div>
                            </div>
                        </div>

                        {client.ban_reason && (
                            <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
                                <strong>Ban Reason:</strong> {client.ban_reason}
                            </div>
                        )}
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Statistics</CardTitle>
                        <CardDescription>Client usage statistics</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="grid grid-cols-2 gap-4">
                            <div className="rounded-lg border p-4 text-center">
                                <div className="text-2xl font-bold">{licenses.length}</div>
                                <div className="text-sm text-muted-foreground">
                                    Total Licenses
                                </div>
                            </div>
                            <div className="rounded-lg border p-4 text-center">
                                <div className="text-2xl font-bold">
                                    {licenses.filter(
                                        (l) =>
                                            !l.is_revoked &&
                                            (!l.expires_at || new Date(l.expires_at) > new Date())
                                    ).length}
                                </div>
                                <div className="text-sm text-muted-foreground">
                                    Active Licenses
                                </div>
                            </div>
                        </div>
                    </CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                    <div>
                        <CardTitle>Licenses</CardTitle>
                        <CardDescription>Licenses assigned to this client</CardDescription>
                    </div>
                    <Button asChild>
                        <Link to={`/licenses/new?clientId=${client.id}`}>
                            <Key className="mr-2 h-4 w-4" />
                            New License
                        </Link>
                    </Button>
                </CardHeader>
                <CardContent>
                    {licensesLoading ? (
                        <div className="space-y-2">
                            {[...Array(3)].map((_, i) => (
                                <Skeleton key={i} className="h-12 w-full" />
                            ))}
                        </div>
                    ) : licenses.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-8 text-center">
                            <Key className="h-12 w-12 text-muted-foreground" />
                            <p className="mt-2 text-sm text-muted-foreground">
                                No licenses found for this client
                            </p>
                            <Button asChild className="mt-4">
                                <Link to={`/licenses/new?clientId=${client.id}`}>
                                    Create License
                                </Link>
                            </Button>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>License Key</TableHead>
                                    <TableHead>Plan</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Devices</TableHead>
                                    <TableHead>Expires</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {licenses.map((license) => (
                                    <TableRow key={license.id}>
                                        <TableCell>
                                            <Link
                                                to={`/licenses/${license.id}`}
                                                className="font-mono text-sm hover:underline"
                                            >
                                                {license.license_key?.substring(0, 16)}...
                                            </Link>
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
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}
