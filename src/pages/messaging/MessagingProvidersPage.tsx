import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { AlertTriangle, Plus, Power, RefreshCcw, Star } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
    Tooltip,
    TooltipContent,
    TooltipTrigger,
} from '@/components/ui/tooltip';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { DataPanel, EmptyState, MetricTile, PageHeader } from '@/components/layout/PageShell';
import { useToast } from '@/hooks/use-toast';
import type { EmailProvider } from '@/types/api';

function formatProviderType(type: string) {
    switch (type) {
        case 'smtp':
            return 'SMTP';
        case 'sendgrid':
            return 'SendGrid';
        case 'ses':
            return 'Amazon SES';
        case 'custom':
            return 'Custom';
        default:
            return type.toUpperCase();
    }
}

export function MessagingProvidersPage() {
    const navigate = useNavigate();
    const { toast } = useToast();

    const { data, isLoading, refetch } = useQuery({
        queryKey: ['emailProviders'],
        queryFn: () => api.listEmailProviders({ includeDisabled: true }),
    });

    const providers: EmailProvider[] = useMemo(() => data?.data ?? [], [data]);

    const toggleMutation = useMutation({
        mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
            api.toggleEmailProvider(id, enabled),
        onSuccess: () => {
            toast({ title: 'Provider updated' });
            refetch();
        },
        onError: (error) => {
            toast({
                title: 'Failed to update provider',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const defaultMutation = useMutation({
        mutationFn: (id: string) => api.setDefaultEmailProvider(id),
        onSuccess: () => {
            toast({ title: 'Default provider updated' });
            refetch();
        },
        onError: (error) => {
            toast({
                title: 'Failed to update default provider',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const deleteMutation = useMutation({
        mutationFn: (id: string) => api.deleteEmailProvider(id),
        onSuccess: () => {
            toast({ title: 'Provider deleted' });
            refetch();
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete provider',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleToggle = (provider: EmailProvider) => {
        toggleMutation.mutate({ id: provider.id, enabled: !provider.enabled });
    };

    const handleSetDefault = (provider: EmailProvider) => {
        defaultMutation.mutate(provider.id);
    };

    const handleDelete = (provider: EmailProvider) => {
        if (!window.confirm(`Delete provider ${provider.name}?`)) return;
        deleteMutation.mutate(provider.id);
    };

    const enabledCount = providers.filter((p) => p.enabled).length;
    const defaultProvider = providers.find((p) => p.is_default);
    const averageRetries = providers.length
        ? (providers.reduce((sum, p) => sum + (p.max_retries || 0), 0) / providers.length).toFixed(1)
        : '0.0';

    return (
        <div className="space-y-4">
            <PageHeader
                eyebrow="Messaging"
                title="Email Providers"
                description="Configure delivery providers, routing priority, default provider, and provider state."
                actions={
                    <Button onClick={() => navigate('/messaging/providers/new')} size="sm">
                        <Plus className="h-3.5 w-3.5" />
                        New Provider
                    </Button>
                }
            />

            <DataPanel>
                <div className="grid divide-y md:grid-cols-3 md:divide-x md:divide-y-0">
                    <MetricTile
                        label="Enabled Providers"
                        value={`${enabledCount} / ${providers.length}`}
                        description="Available for delivery"
                        tone="primary"
                    />
                    <MetricTile
                        label="Default Provider"
                        value={defaultProvider?.name || 'None'}
                        description="First provider used for routing"
                        tone="secondary"
                    />
                    <MetricTile
                        label="Average Retries"
                        value={averageRetries}
                        description="Across configured providers"
                        tone="accent"
                    />
                </div>
            </DataPanel>

            <DataPanel>
                <div className="border-b px-3 py-2">
                    <h2 className="text-sm font-semibold">Provider Routing</h2>
                    <p className="text-xs text-muted-foreground">
                        Providers are ordered by priority. The enabled default provider is used unless a template overrides it.
                    </p>
                </div>
                    {isLoading ? (
                        <div className="space-y-2 p-3">
                            {[...Array(4)].map((_, idx) => (
                                <Skeleton key={idx} className="h-9 w-full" />
                            ))}
                        </div>
                    ) : providers.length === 0 ? (
                        <EmptyState
                            title="No providers configured"
                            description="Add at least one SMTP or downstream provider to send emails."
                            action={
                                <Button size="sm" onClick={() => navigate('/messaging/providers/new')}>
                                    <Plus className="h-3.5 w-3.5" />
                                    Add Provider
                                </Button>
                            }
                        />
                    ) : (
                        <div className="overflow-x-auto">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Name</TableHead>
                                        <TableHead>Type</TableHead>
                                        <TableHead>Priority</TableHead>
                                        <TableHead>Status</TableHead>
                                        <TableHead>Delivery</TableHead>
                                        <TableHead className="text-right">Actions</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {providers.map((provider) => (
                                        <TableRow key={provider.id}>
                                            <TableCell>
                                                <div className="flex flex-col">
                                                    <span className="font-medium text-foreground">{provider.name}</span>
                                                    <span className="font-mono text-xs text-muted-foreground">{provider.slug}</span>
                                                </div>
                                            </TableCell>
                                            <TableCell>
                                                <Badge variant="outline">{formatProviderType(provider.type)}</Badge>
                                            </TableCell>
                                            <TableCell>
                                                <div className="font-mono text-xs">{provider.priority}</div>
                                                {provider.is_default && (
                                                    <Badge variant="secondary" className="mt-1 gap-1">
                                                        <Star className="h-3 w-3" />
                                                        Default
                                                    </Badge>
                                                )}
                                            </TableCell>
                                            <TableCell>
                                                {provider.enabled ? (
                                                    <Badge>Active</Badge>
                                                ) : (
                                                    <Badge variant="secondary">Disabled</Badge>
                                                )}
                                            </TableCell>
                                            <TableCell>
                                                <div className="text-xs text-muted-foreground">
                                                    {provider.success_count.toLocaleString()} sent
                                                </div>
                                                <div className="text-xs text-muted-foreground">
                                                    {provider.failure_count.toLocaleString()} failed
                                                </div>
                                            </TableCell>
                                            <TableCell className="space-x-1 text-right">
                                                <Tooltip>
                                                    <TooltipTrigger asChild>
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            onClick={() => navigate(`/messaging/providers/${provider.id}`)}
                                                        >
                                                            <RefreshCcw className="h-3.5 w-3.5" />
                                                        </Button>
                                                    </TooltipTrigger>
                                                    <TooltipContent>
                                                        <p>Edit provider</p>
                                                    </TooltipContent>
                                                </Tooltip>
                                                <Tooltip>
                                                    <TooltipTrigger asChild>
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            disabled={provider.is_default || defaultMutation.isPending}
                                                            onClick={() => handleSetDefault(provider)}
                                                        >
                                                            <Star className="h-3.5 w-3.5" />
                                                        </Button>
                                                    </TooltipTrigger>
                                                    <TooltipContent>
                                                        <p>Set as default</p>
                                                    </TooltipContent>
                                                </Tooltip>
                                                <Tooltip>
                                                    <TooltipTrigger asChild>
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            disabled={toggleMutation.isPending}
                                                            onClick={() => handleToggle(provider)}
                                                        >
                                                            <Power className="h-3.5 w-3.5" />
                                                        </Button>
                                                    </TooltipTrigger>
                                                    <TooltipContent>
                                                        <p>{provider.enabled ? 'Disable' : 'Enable'} provider</p>
                                                    </TooltipContent>
                                                </Tooltip>
                                                <Tooltip>
                                                    <TooltipTrigger asChild>
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            className="text-destructive"
                                                            disabled={deleteMutation.isPending}
                                                            onClick={() => handleDelete(provider)}
                                                        >
                                                            <AlertTriangle className="h-3.5 w-3.5" />
                                                        </Button>
                                                    </TooltipTrigger>
                                                    <TooltipContent>
                                                        <p>Delete provider</p>
                                                    </TooltipContent>
                                                </Tooltip>
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
