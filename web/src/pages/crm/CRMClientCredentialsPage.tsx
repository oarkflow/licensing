import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Search, Users, ShieldCheck, Mail, Calendar, KeyRound } from 'lucide-react';
import { CRMGuard } from '@/components/crm/CRMAuthGate';
import { ClientCredentialManager } from '@/components/crm/ClientCredentialManager';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import api from '@/services/api';
import type { Client } from '@/types/api';

const buildStatusBadge = (client: Client) => {
    if (client.status === 'banned') {
        return <Badge variant="destructive">Banned</Badge>;
    }
    return <Badge variant="secondary">Active</Badge>;
};

export function CRMClientCredentialsPage() {
    const [filter, setFilter] = useState('');
    const [selectedClientId, setSelectedClientId] = useState<string | null>(null);

    const {
        data: clients = [],
        isLoading: clientsLoading,
        error: clientsError,
    } = useQuery<Client[], Error>({
        queryKey: ['crm-clients', filter],
        queryFn: async () => {
            const response = await api.listClients(filter || undefined);
            if (!response.success || !response.data) {
                throw new Error(response.error || 'Failed to load clients');
            }
            return response.data;
        },
    });

    useEffect(() => {
        if (!clients.length) {
            setSelectedClientId(null);
            return;
        }
        if (!selectedClientId) {
            setSelectedClientId(clients[0].id);
            return;
        }
        const stillVisible = clients.some((client) => client.id === selectedClientId);
        if (!stillVisible) {
            setSelectedClientId(clients[0].id);
        }
    }, [clients, selectedClientId]);

    const {
        data: selectedClient,
        isLoading: selectedClientLoading,
        error: selectedClientError,
    } = useQuery<Client, Error>({
        queryKey: ['crm-client-detail', selectedClientId],
        queryFn: async () => {
            const response = await api.getClient(selectedClientId!);
            if (!response.success || !response.data) {
                throw new Error(response.error || 'Failed to load client');
            }
            return response.data;
        },
        enabled: Boolean(selectedClientId),
    });

    const selectionSubtitle = useMemo(() => {
        if (!selectedClient) {
            return 'Select a client from the directory';
        }
        const created = selectedClient.created_at
            ? new Date(selectedClient.created_at).toLocaleDateString()
            : 'Unknown';
        return `Created ${created}`;
    }, [selectedClient]);

    return (
        <CRMGuard
            title="Unlock CRM surface"
            description="Authenticate with CRM credentials to provision and rotate client login material."
        >
            <div className="space-y-8">
                <div className="flex flex-wrap items-center justify-between gap-4">
                    <div>
                        <p className="text-xs uppercase tracking-[0.4em] text-muted-foreground">CRM</p>
                        <h1 className="mt-1 text-3xl font-semibold tracking-tight">Client credential ops</h1>
                        <p className="text-muted-foreground">
                            Search across every client, issue CRM logins, and rotate secrets without leaving the admin hub.
                        </p>
                    </div>
                    <Button
                        variant="outline"
                        className="rounded-2xl"
                        onClick={() => setFilter('')}
                        disabled={!filter.trim()}
                    >
                        Clear filter
                    </Button>
                </div>

                <div className="grid gap-6 lg:grid-cols-5">
                    <Card className="lg:col-span-2">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-xl">
                                <Users className="h-4 w-4" />
                                Client directory
                            </CardTitle>
                            <CardDescription>Locate the client that needs CRM credentials.</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <div className="relative">
                                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                                <Input
                                    placeholder="Filter by email or ID"
                                    value={filter}
                                    onChange={(event) => setFilter(event.target.value)}
                                    className="pl-9"
                                />
                            </div>
                            <div className="mt-4 space-y-2">
                                {clientsError ? (
                                    <div className="rounded-2xl border border-destructive/30 bg-destructive/5 p-4 text-sm text-destructive">
                                        {clientsError.message}
                                    </div>
                                ) : clientsLoading ? (
                                    [...Array(5)].map((_, index) => (
                                        <Skeleton key={index} className="h-16 w-full rounded-2xl" />
                                    ))
                                ) : clients.length === 0 ? (
                                    <div className="rounded-2xl border border-dashed p-6 text-center text-sm text-muted-foreground">
                                        No clients match this filter yet.
                                    </div>
                                ) : (
                                    clients.map((client) => (
                                        <button
                                            key={client.id}
                                            type="button"
                                            onClick={() => setSelectedClientId(client.id)}
                                            className={cn(
                                                'w-full rounded-2xl border p-3 text-left transition hover:border-primary/40',
                                                selectedClientId === client.id ? 'border-primary bg-primary/5 shadow-sm' : 'border-border'
                                            )}
                                        >
                                            <div className="flex items-center justify-between gap-3">
                                                <span className="truncate font-medium">{client.email}</span>
                                                {buildStatusBadge(client)}
                                            </div>
                                            <p className="mt-1 text-xs text-muted-foreground">
                                                Created {client.created_at ? new Date(client.created_at).toLocaleDateString() : 'Unknown'}
                                            </p>
                                        </button>
                                    ))
                                )}
                            </div>
                        </CardContent>
                    </Card>

                    <div className="space-y-6 lg:col-span-3">
                        {selectedClientId && selectedClientLoading && (
                            <Card className="rounded-3xl border border-dashed">
                                <CardContent className="space-y-4 py-6">
                                    <Skeleton className="h-5 w-1/2" />
                                    <Skeleton className="h-4 w-1/3" />
                                    <Skeleton className="h-4 w-2/3" />
                                </CardContent>
                            </Card>
                        )}

                        {selectedClientError && (
                            <div className="rounded-3xl border border-destructive/30 bg-destructive/5 p-6 text-sm text-destructive">
                                {selectedClientError.message}
                            </div>
                        )}

                        {!selectedClient && !selectedClientLoading ? (
                            <div className="flex flex-col items-center justify-center gap-3 rounded-3xl border border-dashed py-16 text-center text-muted-foreground">
                                <ShieldCheck className="h-10 w-10" />
                                <p className="text-sm">Select a client from the left to manage CRM credentials.</p>
                            </div>
                        ) : null}

                        {selectedClient && (
                            <>
                                <Card className="rounded-3xl border bg-card/70">
                                    <CardHeader>
                                        <CardTitle className="flex items-center gap-2 text-2xl">
                                            <KeyRound className="h-5 w-5 text-primary" />
                                            {selectedClient.email}
                                        </CardTitle>
                                        <CardDescription className="flex flex-wrap items-center gap-2 text-sm">
                                            <span>{selectionSubtitle}</span>
                                            {selectedClient.ban_reason && (
                                                <Badge variant="outline" className="text-xs">
                                                    {selectedClient.ban_reason}
                                                </Badge>
                                            )}
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent className="grid gap-4 sm:grid-cols-2">
                                        <div className="flex items-center gap-2 text-sm">
                                            <Mail className="h-4 w-4 text-muted-foreground" />
                                            <span className="truncate">{selectedClient.email}</span>
                                        </div>
                                        <div className="flex items-center gap-2 text-sm">
                                            <Calendar className="h-4 w-4 text-muted-foreground" />
                                            <span>
                                                Joined {selectedClient.created_at ? new Date(selectedClient.created_at).toLocaleDateString() : 'Unknown'}
                                            </span>
                                        </div>
                                        <div className="flex items-center gap-2 text-sm">
                                            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
                                            {buildStatusBadge(selectedClient)}
                                        </div>
                                    </CardContent>
                                </Card>

                                <ClientCredentialManager clientId={selectedClient.id} clientLabel={selectedClient.email} />
                            </>
                        )}
                    </div>
                </div>
            </div>
        </CRMGuard>
    );
}

export default CRMClientCredentialsPage;
