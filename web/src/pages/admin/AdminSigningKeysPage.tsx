import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Key, ToggleRight } from 'lucide-react';
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
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';

export function AdminSigningKeysPage() {
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const [name, setName] = useState('');

    const { data: resp, isLoading } = useQuery({
        queryKey: ['signing-keys'],
        queryFn: () => api.listSigningKeys(),
    });

    const createMutation = useMutation({
        mutationFn: () => api.createSigningKey({ name: name || undefined, activate: true }),
        onSuccess: (response) => {
            if (response.success) {
                toast({ title: 'Signing key created' });
                queryClient.invalidateQueries({ queryKey: ['signing-keys'] });
            } else {
                toast({ title: 'Failed to create signing key', description: response.error || '', variant: 'destructive' })
            }
        },
        onError: (err) => {
            toast({ title: 'Failed to create signing key', description: (err as Error).message, variant: 'destructive' });
        }
    });

    const activateMutation = useMutation({
        mutationFn: (id: string) => api.activateSigningKey(id),
        onSuccess: () => {
            toast({ title: 'Signing key activated' });
            queryClient.invalidateQueries({ queryKey: ['signing-keys'] });
        },
        onError: (err) => {
            toast({ title: 'Failed to activate', description: (err as Error).message, variant: 'destructive' });
        }
    });

    const keys = resp?.data || [];

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Signing Keys</h1>
                    <p className="text-muted-foreground">Manage offline signing keys used for issuing signed license bundles</p>
                </div>
                <div className="flex items-center gap-2">
                    <Input placeholder="Key name (optional)" value={name} onChange={(e) => setName(e.target.value)} />
                    <Button onClick={() => createMutation.mutate()} disabled={createMutation.isPending}>
                        <Plus className="mr-2 h-4 w-4" />
                        {createMutation.isPending ? 'Creating…' : 'Create & Activate'}
                    </Button>
                </div>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2"><Key className="h-5 w-5" /> Signing Keys</CardTitle>
                    <CardDescription>Private keys are stored in the server or environment (KMS). Prefer KMS for production.</CardDescription>
                </CardHeader>
                <CardContent>
                    {isLoading ? (
                        <div className="space-y-2">
                            {[...Array(4)].map((_, i) => (
                                <Skeleton key={i} className="h-12 w-full" />
                            ))}
                        </div>
                    ) : keys.length === 0 ? (
                        <div className="py-6 text-center text-sm text-muted-foreground">No signing keys found.</div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Key ID</TableHead>
                                    <TableHead>Name</TableHead>
                                    <TableHead>Active</TableHead>
                                    <TableHead>Created</TableHead>
                                    <TableHead className="w-[140px]">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {keys.map(k => (
                                    <TableRow key={k.id}>
                                        <TableCell className="font-mono text-sm">{k.id}</TableCell>
                                        <TableCell>{k.name || '—'}</TableCell>
                                        <TableCell>{k.is_active ? <Badge variant="default">Active</Badge> : <Badge variant="secondary">Inactive</Badge>}</TableCell>
                                        <TableCell>{new Date(k.created_at).toLocaleString()}</TableCell>
                                        <TableCell>
                                            {!k.is_active && (
                                                <Button size="icon" variant="ghost" onClick={() => activateMutation.mutate(k.id)}>
                                                    <ToggleRight className="h-4 w-4" />
                                                </Button>
                                            )}
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
