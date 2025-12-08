import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Plus, Search, Users, Filter } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
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
import type { Client } from '@/types/api';

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

export function ClientsPage() {
    const [filter, setFilter] = useState<string>('all');
    const [searchQuery, setSearchQuery] = useState('');

    const { data: response, isLoading } = useQuery({
        queryKey: ['clients', filter],
        queryFn: () => api.listClients(filter !== 'all' ? filter : undefined),
    });

    const clients = response?.data || [];

    const filteredClients = clients.filter((client) => {
        if (!searchQuery) return true;
        const query = searchQuery.toLowerCase();
        return (
            client.email.toLowerCase().includes(query) ||
            client.id.toLowerCase().includes(query)
        );
    });

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Clients</h1>
                    <p className="text-muted-foreground">
                        Manage your licensed clients
                    </p>
                </div>
                <Button asChild>
                    <Link to="/clients/new">
                        <Plus className="mr-2 h-4 w-4" />
                        New Client
                    </Link>
                </Button>
            </div>

            <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
                <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                        placeholder="Search clients..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-9"
                    />
                </div>
                <div className="flex items-center gap-2">
                    <Filter className="h-4 w-4 text-muted-foreground" />
                    <Select value={filter} onValueChange={setFilter}>
                        <SelectTrigger className="w-[180px]">
                            <SelectValue placeholder="Filter by status" />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">All Clients</SelectItem>
                            <SelectItem value="active">Active</SelectItem>
                            <SelectItem value="suspended">Suspended</SelectItem>
                            <SelectItem value="banned">Banned</SelectItem>
                        </SelectContent>
                    </Select>
                </div>
            </div>

            {isLoading ? (
                <div className="space-y-2">
                    {[...Array(10)].map((_, i) => (
                        <Skeleton key={i} className="h-16 w-full" />
                    ))}
                </div>
            ) : filteredClients.length === 0 ? (
                <div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-12">
                    <Users className="h-12 w-12 text-muted-foreground" />
                    <h3 className="mt-4 text-lg font-semibold">No clients found</h3>
                    <p className="mt-2 text-sm text-muted-foreground">
                        {searchQuery
                            ? 'Try adjusting your search query'
                            : 'Get started by creating a new client'}
                    </p>
                    {!searchQuery && (
                        <Button asChild className="mt-4">
                            <Link to="/clients/new">
                                <Plus className="mr-2 h-4 w-4" />
                                New Client
                            </Link>
                        </Button>
                    )}
                </div>
            ) : (
                <div className="rounded-md border">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>ID</TableHead>
                                <TableHead>Email</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead>Created</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {filteredClients.map((client) => (
                                <TableRow key={client.id}>
                                    <TableCell>
                                        <Link
                                            to={`/clients/${client.id}`}
                                            className="font-mono text-sm hover:underline"
                                        >
                                            {client.id.substring(0, 12)}...
                                        </Link>
                                    </TableCell>
                                    <TableCell>{client.email}</TableCell>
                                    <TableCell>{getClientStatusBadge(client)}</TableCell>
                                    <TableCell>
                                        {client.created_at ? new Date(client.created_at).toLocaleDateString() : '—'}
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            )}
        </div>
    );
}
