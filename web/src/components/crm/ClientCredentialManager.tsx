import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, RefreshCcw, Trash2, Copy, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
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
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import { useCRMContext } from '@/contexts/CRMContext';
import crmService from '@/services/crm';
import type {
    CRMClientCredential,
    CRMClientCredentialRequest,
    CRMClientCredentialResetRequest,
} from '@/types/crm';

interface ClientCredentialManagerProps {
    clientId: string;
    clientLabel?: string;
}

interface CredentialFormState {
    username: string;
    password: string;
    roles: string;
    scopes: string;
    expires_at: string;
    notify_via: CRMClientCredentialRequest['notify_via'];
}

interface SecretDialogState {
    username: string;
    secret?: string;
}

const getCredentialStatusBadge = (credential: CRMClientCredential) => {
    switch (credential.status) {
        case 'active':
            return <Badge variant="default">Active</Badge>;
        case 'revoked':
            return <Badge variant="destructive">Revoked</Badge>;
        case 'suspended':
            return <Badge variant="secondary">Suspended</Badge>;
        default:
            return <Badge variant="outline">{credential.status}</Badge>;
    }
};

const initialFormState: CredentialFormState = {
    username: '',
    password: '',
    roles: '',
    scopes: '',
    expires_at: '',
    notify_via: 'email',
};

export function ClientCredentialManager({ clientId, clientLabel }: ClientCredentialManagerProps) {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const { isAuthenticated: isCRMSignedIn } = useCRMContext();
    const [credentialDialogOpen, setCredentialDialogOpen] = useState(false);
    const [credentialForm, setCredentialForm] = useState<CredentialFormState>(initialFormState);
    const [secretDialog, setSecretDialog] = useState<SecretDialogState | null>(null);
    const [credentialToDelete, setCredentialToDelete] = useState<CRMClientCredential | null>(null);
    const [rotatingId, setRotatingId] = useState<string | null>(null);

    const { data: credentialList, isLoading: credentialsLoading } = useQuery({
        queryKey: ['client-credentials', clientId],
        queryFn: () => crmService.listClientCredentials(clientId),
        enabled: Boolean(clientId && isCRMSignedIn),
    });

    const credentials = credentialList || [];

    const credentialCreateMutation = useMutation({
        mutationFn: (payload: CRMClientCredentialRequest) => crmService.createClientCredential(clientId, payload),
        onSuccess: (credential) => {
            queryClient.invalidateQueries({ queryKey: ['client-credentials', clientId] });
            setCredentialDialogOpen(false);
            setCredentialForm(initialFormState);
            toast({ title: 'Credential issued successfully' });
            if (credential.one_time_password) {
                setSecretDialog({ username: credential.username, secret: credential.one_time_password });
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to issue credential',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const rotateCredentialMutation = useMutation({
        mutationFn: (credentialId: string) =>
            crmService.updateClientCredential(
                clientId,
                credentialId,
                { rotate_password: true } satisfies CRMClientCredentialResetRequest,
            ),
        onMutate: (credentialId: string) => {
            setRotatingId(credentialId);
        },
        onSuccess: (credential) => {
            queryClient.invalidateQueries({ queryKey: ['client-credentials', clientId] });
            toast({ title: 'Credential rotated' });
            if (credential.one_time_password) {
                setSecretDialog({ username: credential.username, secret: credential.one_time_password });
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to rotate credential',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
        onSettled: () => {
            setRotatingId(null);
        },
    });

    const deleteCredentialMutation = useMutation({
        mutationFn: (credentialId: string) => crmService.deleteClientCredential(clientId, credentialId),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['client-credentials', clientId] });
            setCredentialToDelete(null);
            toast({ title: 'Credential revoked' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to revoke credential',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const splitList = (value: string) =>
        value
            .split(',')
            .map((entry) => entry.trim())
            .filter(Boolean);

    const toISODateTime = (value: string) => (value ? new Date(value).toISOString() : undefined);

    const handleCredentialSubmit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        if (!isCRMSignedIn) {
            toast({ title: 'Sign in to the CRM workspace first', variant: 'destructive' });
            return;
        }
        const payload: CRMClientCredentialRequest = {
            username: credentialForm.username.trim(),
            notify_via: credentialForm.notify_via,
        };
        const password = credentialForm.password.trim();
        if (password) {
            payload.password = password;
        }
        const roleList = splitList(credentialForm.roles);
        if (roleList.length) {
            payload.roles = roleList;
        }
        const scopeList = splitList(credentialForm.scopes);
        if (scopeList.length) {
            payload.scopes = scopeList;
        }
        const expires = toISODateTime(credentialForm.expires_at);
        if (expires) {
            payload.expires_at = expires;
        }
        credentialCreateMutation.mutate(payload);
    };

    const handleCopy = async (value: string) => {
        try {
            await navigator.clipboard.writeText(value);
            toast({ title: 'Copied to clipboard' });
        } catch (error) {
            console.error('Copy failed', error);
            toast({
                title: 'Failed to copy',
                description: 'Please copy the value manually.',
                variant: 'destructive',
            });
        }
    };

    return (
        <>
            <Card>
                <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                        <CardTitle>CRM Credentials</CardTitle>
                        <CardDescription>
                            Issue scoped CRM access for {clientLabel || 'this client'}.
                        </CardDescription>
                    </div>
                    {isCRMSignedIn && (
                        <Dialog open={credentialDialogOpen} onOpenChange={setCredentialDialogOpen}>
                            <DialogTrigger asChild>
                                <Button>
                                    <KeyRound className="mr-2 h-4 w-4" />
                                    Issue Credential
                                </Button>
                            </DialogTrigger>
                            <DialogContent>
                                <DialogHeader>
                                    <DialogTitle>Issue CRM Credential</DialogTitle>
                                    <DialogDescription>
                                        Define the login details that will unlock CRM functionality for this client.
                                    </DialogDescription>
                                </DialogHeader>
                                <form onSubmit={handleCredentialSubmit} className="space-y-4">
                                    <div className="grid gap-4 sm:grid-cols-2">
                                        <div className="space-y-2">
                                            <Label htmlFor="credential-username">Username *</Label>
                                            <Input
                                                id="credential-username"
                                                value={credentialForm.username}
                                                onChange={(event) =>
                                                    setCredentialForm((prev) => ({
                                                        ...prev,
                                                        username: event.target.value,
                                                    }))
                                                }
                                                placeholder="client.portal@example.com"
                                                required
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <Label htmlFor="credential-password">Password (optional)</Label>
                                            <Input
                                                id="credential-password"
                                                type="text"
                                                value={credentialForm.password}
                                                onChange={(event) =>
                                                    setCredentialForm((prev) => ({
                                                        ...prev,
                                                        password: event.target.value,
                                                    }))
                                                }
                                                placeholder="Leave blank to auto-generate"
                                            />
                                        </div>
                                    </div>
                                    <div className="grid gap-4 sm:grid-cols-2">
                                        <div className="space-y-2">
                                            <Label htmlFor="credential-roles">Roles</Label>
                                            <Input
                                                id="credential-roles"
                                                value={credentialForm.roles}
                                                onChange={(event) =>
                                                    setCredentialForm((prev) => ({
                                                        ...prev,
                                                        roles: event.target.value,
                                                    }))
                                                }
                                                placeholder="owner,admin"
                                            />
                                            <p className="text-xs text-muted-foreground">
                                                Comma-separated CRM roles (defaults to client role).
                                            </p>
                                        </div>
                                        <div className="space-y-2">
                                            <Label htmlFor="credential-scopes">Scopes</Label>
                                            <Input
                                                id="credential-scopes"
                                                value={credentialForm.scopes}
                                                onChange={(event) =>
                                                    setCredentialForm((prev) => ({
                                                        ...prev,
                                                        scopes: event.target.value,
                                                    }))
                                                }
                                                placeholder="crm:read licensing:verify"
                                            />
                                            <p className="text-xs text-muted-foreground">
                                                Comma-separated API scopes to attach to this credential.
                                            </p>
                                        </div>
                                    </div>
                                    <div className="grid gap-4 sm:grid-cols-2">
                                        <div className="space-y-2">
                                            <Label htmlFor="credential-expires">Expires At</Label>
                                            <Input
                                                id="credential-expires"
                                                type="datetime-local"
                                                value={credentialForm.expires_at}
                                                onChange={(event) =>
                                                    setCredentialForm((prev) => ({
                                                        ...prev,
                                                        expires_at: event.target.value,
                                                    }))
                                                }
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <Label>Notify Via</Label>
                                            <Select
                                                value={credentialForm.notify_via}
                                                onValueChange={(value) =>
                                                    setCredentialForm((prev) => ({
                                                        ...prev,
                                                        notify_via: value as CredentialFormState['notify_via'],
                                                    }))
                                                }
                                            >
                                                <SelectTrigger>
                                                    <SelectValue placeholder="Choose channel" />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    <SelectItem value="email">Email</SelectItem>
                                                    <SelectItem value="sms">SMS</SelectItem>
                                                    <SelectItem value="none">Do not notify</SelectItem>
                                                </SelectContent>
                                            </Select>
                                        </div>
                                    </div>
                                    <DialogFooter>
                                        <Button type="button" variant="ghost" onClick={() => setCredentialDialogOpen(false)}>
                                            Cancel
                                        </Button>
                                        <Button
                                            type="submit"
                                            disabled={
                                                credentialCreateMutation.isPending ||
                                                !credentialForm.username.trim()
                                            }
                                        >
                                            {credentialCreateMutation.isPending ? 'Issuing...' : 'Issue Credential'}
                                        </Button>
                                    </DialogFooter>
                                </form>
                            </DialogContent>
                        </Dialog>
                    )}
                </CardHeader>
                <CardContent>
                    {!isCRMSignedIn ? (
                        <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed p-8 text-center">
                            <ShieldCheck className="h-10 w-10 text-muted-foreground" />
                            <p className="text-sm text-muted-foreground">
                                Sign in to the CRM workspace to issue or manage client credentials.
                            </p>
                            <Button asChild variant="outline">
                                <Link to="/crm">Open CRM Workspace</Link>
                            </Button>
                        </div>
                    ) : credentialsLoading ? (
                        <div className="space-y-2">
                            {[...Array(3)].map((_, index) => (
                                <Skeleton key={index} className="h-12 w-full" />
                            ))}
                        </div>
                    ) : credentials.length === 0 ? (
                        <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed p-8 text-center">
                            <KeyRound className="h-10 w-10 text-muted-foreground" />
                            <p className="text-sm text-muted-foreground">
                                No CRM credentials issued for this client yet.
                            </p>
                            <Button onClick={() => setCredentialDialogOpen(true)}>Issue Credential</Button>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Username</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Scopes</TableHead>
                                    <TableHead>Last Login</TableHead>
                                    <TableHead>Expires</TableHead>
                                    <TableHead className="text-right">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {credentials.map((credential) => (
                                    <TableRow key={credential.id}>
                                        <TableCell className="font-mono text-sm">{credential.username}</TableCell>
                                        <TableCell>{getCredentialStatusBadge(credential)}</TableCell>
                                        <TableCell>
                                            {credential.scopes?.length ? (
                                                <div className="flex flex-wrap gap-1">
                                                    {credential.scopes.map((scope) => (
                                                        <Badge key={scope} variant="outline" className="font-mono text-xs">
                                                            {scope}
                                                        </Badge>
                                                    ))}
                                                </div>
                                            ) : (
                                                <span className="text-muted-foreground">—</span>
                                            )}
                                        </TableCell>
                                        <TableCell>
                                            {credential.last_login_at
                                                ? new Date(credential.last_login_at).toLocaleString()
                                                : 'Never'}
                                        </TableCell>
                                        <TableCell>
                                            {credential.expires_at
                                                ? new Date(credential.expires_at).toLocaleString()
                                                : 'Never'}
                                        </TableCell>
                                        <TableCell className="flex justify-end gap-2">
                                            <Button
                                                variant="outline"
                                                size="icon"
                                                onClick={() => handleCopy(credential.username)}
                                            >
                                                <Copy className="h-4 w-4" />
                                            </Button>
                                            <Button
                                                variant="outline"
                                                size="icon"
                                                disabled={rotateCredentialMutation.isPending && rotatingId === credential.id}
                                                onClick={() => rotateCredentialMutation.mutate(credential.id)}
                                            >
                                                <RefreshCcw className="h-4 w-4" />
                                            </Button>
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                onClick={() => setCredentialToDelete(credential)}
                                            >
                                                <Trash2 className="h-4 w-4" />
                                            </Button>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>

            <Dialog open={Boolean(secretDialog)} onOpenChange={(open) => !open && setSecretDialog(null)}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Share credential secret</DialogTitle>
                        <DialogDescription>
                            Copy the values below now—passwords are only shown once for security reasons.
                        </DialogDescription>
                    </DialogHeader>
                    {secretDialog && (
                        <div className="space-y-4">
                            <div className="space-y-2">
                                <Label>Username</Label>
                                <div className="flex gap-2">
                                    <Input readOnly value={secretDialog.username} />
                                    <Button
                                        type="button"
                                        variant="outline"
                                        size="icon"
                                        onClick={() => handleCopy(secretDialog.username)}
                                    >
                                        <Copy className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>
                            {secretDialog.secret ? (
                                <div className="space-y-2">
                                    <Label>One-time password</Label>
                                    <div className="flex gap-2">
                                        <Input readOnly value={secretDialog.secret} />
                                        <Button
                                            type="button"
                                            variant="outline"
                                            size="icon"
                                            onClick={() => handleCopy(secretDialog.secret ?? '')}
                                        >
                                            <Copy className="h-4 w-4" />
                                        </Button>
                                    </div>
                                    <p className="text-xs text-muted-foreground">
                                        Passwords are only returned once—store it securely before closing.
                                    </p>
                                </div>
                            ) : (
                                <p className="text-sm text-muted-foreground">
                                    Password rotation succeeded, but no new password was returned.
                                </p>
                            )}
                        </div>
                    )}
                    <DialogFooter>
                        <Button type="button" onClick={() => setSecretDialog(null)}>
                            Close
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <AlertDialog open={Boolean(credentialToDelete)} onOpenChange={(open) => !open && setCredentialToDelete(null)}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>Revoke credential</AlertDialogTitle>
                        <AlertDialogDescription>
                            This client will immediately lose access via
                            {credentialToDelete ? ` ${credentialToDelete.username}` : ''}. This action cannot be undone.
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                            onClick={() =>
                                credentialToDelete &&
                                deleteCredentialMutation.mutate(credentialToDelete.id)
                            }
                            disabled={deleteCredentialMutation.isPending}
                        >
                            {deleteCredentialMutation.isPending ? 'Revoking...' : 'Revoke'}
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </>
    );
}

export default ClientCredentialManager;
