import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Key, Trash2, Copy, AlertTriangle } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import {
    Tooltip,
    TooltipContent,
    TooltipTrigger,
} from '@/components/ui/tooltip';
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
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';

export function AdminAPIKeysPage() {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const { user } = useAuth();
    const [newKeyDialog, setNewKeyDialog] = useState(false);
    const [newKeyValue, setNewKeyValue] = useState('');

    const { data: response, isLoading } = useQuery({
        queryKey: ['api-keys', user?.id],
        queryFn: () => api.listAPIKeys(user!.id),
        enabled: !!user?.id,
    });

    const createMutation = useMutation({
        mutationFn: () => api.createAPIKey(user!.id),
        onSuccess: (response) => {
            if (response.success && response.data) {
                setNewKeyValue(response.data.token);
                setNewKeyDialog(true);
                queryClient.invalidateQueries({ queryKey: ['api-keys'] });
                toast({ title: 'API key created successfully' });
            } else {
                toast({
                    title: 'Failed to create API key',
                    description: response.error || 'Unknown error',
                    variant: 'destructive',
                });
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to create API key',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const deleteMutation = useMutation({
        mutationFn: (id: string) => api.deleteAPIKey(id),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['api-keys'] });
            toast({ title: 'API key deleted successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete API key',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        toast({ title: 'Copied to clipboard' });
    };

    const keys = response?.data || [];

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">API Keys</h1>
                    <p className="text-muted-foreground">
                        Manage API keys for programmatic access
                    </p>
                </div>
                <Button
                    onClick={() => createMutation.mutate()}
                    disabled={createMutation.isPending}
                >
                    <Plus className="mr-2 h-4 w-4" />
                    {createMutation.isPending ? 'Creating...' : 'New API Key'}
                </Button>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Key className="h-5 w-5" />
                        API Keys
                    </CardTitle>
                    <CardDescription>
                        Keys used to authenticate API requests
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {isLoading ? (
                        <div className="space-y-2">
                            {[...Array(5)].map((_, i) => (
                                <Skeleton key={i} className="h-12 w-full" />
                            ))}
                        </div>
                    ) : keys.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-8 text-center">
                            <Key className="h-12 w-12 text-muted-foreground" />
                            <p className="mt-2 text-sm text-muted-foreground">
                                No API keys found
                            </p>
                            <Button
                                className="mt-4"
                                onClick={() => createMutation.mutate()}
                                disabled={createMutation.isPending}
                            >
                                {createMutation.isPending ? 'Creating...' : 'Create API Key'}
                            </Button>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Key Prefix</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Created</TableHead>
                                    <TableHead>Last Used</TableHead>
                                    <TableHead className="w-[100px]">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {keys.map((key) => (
                                    <TableRow key={key.id}>
                                        <TableCell className="font-mono text-sm">
                                            {key.prefix}...
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant="default">Active</Badge>
                                        </TableCell>
                                        <TableCell>
                                            {key.created_at
                                                ? new Date(key.created_at).toLocaleDateString()
                                                : '—'}
                                        </TableCell>
                                        <TableCell>
                                            {key.last_used_at
                                                ? new Date(key.last_used_at).toLocaleDateString()
                                                : 'Never'}
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
                                                            <p>Delete API key</p>
                                                        </TooltipContent>
                                                    </Tooltip>
                                                </AlertDialogTrigger>
                                                <AlertDialogContent>
                                                    <AlertDialogHeader>
                                                        <AlertDialogTitle>Delete API Key</AlertDialogTitle>
                                                        <AlertDialogDescription>
                                                            This will permanently delete the API key. Any
                                                            applications using this key will lose access.
                                                        </AlertDialogDescription>
                                                    </AlertDialogHeader>
                                                    <AlertDialogFooter>
                                                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                                                        <AlertDialogAction
                                                            onClick={() => deleteMutation.mutate(key.id)}
                                                            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                                        >
                                                            Delete
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

            <Dialog open={newKeyDialog} onOpenChange={setNewKeyDialog}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>API Key Created</DialogTitle>
                        <DialogDescription>
                            Copy your API key now. You won't be able to see it again!
                        </DialogDescription>
                    </DialogHeader>
                    <Alert>
                        <AlertTriangle className="h-4 w-4" />
                        <AlertTitle>Important</AlertTitle>
                        <AlertDescription>
                            Store this key securely. It will only be shown once.
                        </AlertDescription>
                    </Alert>
                    <div className="flex items-center gap-2">
                        <Input value={newKeyValue} readOnly className="font-mono text-xs" />
                        <Button
                            variant="outline"
                            size="icon"
                            onClick={() => copyToClipboard(newKeyValue)}
                        >
                            <Tooltip>
                                <TooltipTrigger asChild>
                                    <Copy className="h-4 w-4" />
                                </TooltipTrigger>
                                <TooltipContent>
                                    <p>Copy to clipboard</p>
                                </TooltipContent>
                            </Tooltip>
                        </Button>
                    </div>
                    <DialogFooter>
                        <Button onClick={() => setNewKeyDialog(false)}>Done</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
