import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Trash2 } from 'lucide-react';
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
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { DataPanel, EmptyState, PageHeader } from '@/components/layout';
import type { APIKey } from '@/types/api';

function isExpired(key: APIKey) {
    return Boolean(key.expires_at && new Date(key.expires_at) < new Date());
}

function renderList(values?: string[], fallback = 'Any') {
    if (!values || values.length === 0) {
        return <span className="text-muted-foreground">{fallback}</span>;
    }
    return (
        <div className="flex max-w-sm flex-wrap gap-1">
            {values.map((value) => (
                <Badge key={value} variant="outline" className="font-mono text-[0.65rem]">
                    {value}
                </Badge>
            ))}
        </div>
    );
}

export function AdminAPIKeysPage() {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const { user } = useAuth();

    const { data: response, isLoading } = useQuery({
        queryKey: ['api-keys', user?.id],
        queryFn: () => api.listAPIKeys(user!.id),
        enabled: !!user?.id,
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

    const keys = useMemo(() => response?.data || [], [response?.data]);

    return (
        <div className="space-y-4">
            <PageHeader
                eyebrow="Administration"
                title="API Keys"
                description="Manage scoped platform keys for programmatic admin access."
                actions={
                    <Button asChild size="sm">
                        <Link to="/admin/api-keys/new">
                            <Plus className="h-3.5 w-3.5" />
                            New API Key
                        </Link>
                    </Button>
                }
            />

            <DataPanel>
                <div className="border-b px-3 py-2">
                    <h2 className="text-sm font-semibold">Platform Keys</h2>
                    <p className="text-xs text-muted-foreground">
                        Prefer scoped, expiring keys with IP and origin restrictions for production integrations.
                    </p>
                </div>
                {isLoading ? (
                    <div className="space-y-2 p-3">
                        {[...Array(5)].map((_, i) => (
                            <Skeleton key={i} className="h-10 w-full" />
                        ))}
                    </div>
                ) : keys.length === 0 ? (
                    <EmptyState
                        title="No API keys"
                        description="Create a scoped key for platform or automation access."
                        action={
                            <Button asChild size="sm">
                                <Link to="/admin/api-keys/new">Create API Key</Link>
                            </Button>
                        }
                    />
                ) : (
                    <div className="overflow-x-auto">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Prefix</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Scopes</TableHead>
                                    <TableHead>IP Restrictions</TableHead>
                                    <TableHead>Origins</TableHead>
                                    <TableHead>Expires</TableHead>
                                    <TableHead>Last Used</TableHead>
                                    <TableHead className="w-[80px] text-right">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {keys.map((key) => (
                                    <TableRow key={key.id}>
                                        <TableCell className="font-mono text-xs">{key.prefix}...</TableCell>
                                        <TableCell>
                                            {isExpired(key) ? (
                                                <Badge variant="secondary">Expired</Badge>
                                            ) : (
                                                <Badge>Active</Badge>
                                            )}
                                        </TableCell>
                                        <TableCell>{renderList(key.scopes, 'admin:*')}</TableCell>
                                        <TableCell>{renderList(key.allowed_ips)}</TableCell>
                                        <TableCell>{renderList(key.allowed_origins)}</TableCell>
                                        <TableCell>
                                            {key.expires_at ? new Date(key.expires_at).toLocaleString() : 'Never'}
                                        </TableCell>
                                        <TableCell>
                                            {key.last_used_at ? new Date(key.last_used_at).toLocaleString() : 'Never'}
                                        </TableCell>
                                        <TableCell className="text-right">
                                            <AlertDialog>
                                                <AlertDialogTrigger asChild>
                                                    <Button variant="ghost" size="icon" className="text-destructive">
                                                        <Trash2 className="h-3.5 w-3.5" />
                                                    </Button>
                                                </AlertDialogTrigger>
                                                <AlertDialogContent>
                                                    <AlertDialogHeader>
                                                        <AlertDialogTitle>Delete API Key</AlertDialogTitle>
                                                        <AlertDialogDescription>
                                                            This permanently deletes the API key. Applications using it will lose access immediately.
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
                    </div>
                )}
            </DataPanel>
        </div>
    );
}
