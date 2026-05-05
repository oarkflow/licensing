import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { AlertTriangle, MailCheck, MailWarning, Plus, Power, RefreshCcw, Shield, Star } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
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
import { Skeleton } from '@/components/ui/skeleton';
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

    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                    <p className="text-xs uppercase tracking-[0.4em] text-muted-foreground">
                        Messaging
                    </p>
                    <h1 className="text-3xl font-semibold tracking-tight">Email Providers</h1>
                    <p className="text-muted-foreground">
                        Control upstream integrations, routing priority, and health.
                    </p>
                </div>
                <Button onClick={() => navigate('/messaging/providers/new')} className="rounded-2xl">
                    <Plus className="mr-2 h-4 w-4" /> New Provider
                </Button>
            </div>

            <Card className="border bg-muted/50">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-lg">
                        <Shield className="h-5 w-5 text-primary" />
                        Delivery mesh
                    </CardTitle>
                    <CardDescription>
                        Ordered by priority. First enabled default provider is used unless overridden per template.
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {isLoading ? (
                        <div className="space-y-3">
                            {[...Array(4)].map((_, idx) => (
                                <Skeleton key={idx} className="h-16 w-full rounded-2xl" />
                            ))}
                        </div>
                    ) : providers.length === 0 ? (
                        <div className="flex flex-col items-center justify-center rounded-3xl border border-dashed bg-muted/50 py-12 text-center">
                            <MailWarning className="h-10 w-10 text-muted-foreground" />
                            <h3 className="mt-4 text-xl font-semibold">No providers configured</h3>
                            <p className="mt-2 text-sm text-muted-foreground">
                                Add at least one SMTP or downstream provider to send emails.
                            </p>
                            <Button
                                className="mt-4 rounded-2xl"
                                onClick={() => navigate('/messaging/providers/new')}
                            >
                                <Plus className="mr-2 h-4 w-4" /> Add Provider
                            </Button>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow className="border text-xs uppercase tracking-[0.2em] text-muted-foreground">
                                    <TableHead>Name</TableHead>
                                    <TableHead>Type</TableHead>
                                    <TableHead>Priority</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Success</TableHead>
                                    <TableHead className="text-right">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {providers.map((provider) => (
                                    <TableRow key={provider.id} className="border">
                                        <TableCell>
                                            <div className="flex flex-col">
                                                <span className="font-medium text-foreground">{provider.name}</span>
                                                <span className="text-xs text-muted-foreground">{provider.slug}</span>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant="outline" className="rounded-full border">
                                                {formatProviderType(provider.type)}
                                            </Badge>
                                        </TableCell>
                                        <TableCell>
                                            <div className="font-mono text-sm">{provider.priority}</div>
                                            {provider.is_default && (
                                                <Badge variant="secondary" className="mt-1 flex items-center gap-1 rounded-full text-xs">
                                                    <Star className="h-3 w-3" /> Default
                                                </Badge>
                                            )}
                                        </TableCell>
                                        <TableCell>
                                            {provider.enabled ? (
                                                <Badge className="rounded-full bg-primary/20 text-primary">
                                                    Active
                                                </Badge>
                                            ) : (
                                                <Badge variant="secondary" className="rounded-full text-secondary">
                                                    Disabled
                                                </Badge>
                                            )}
                                        </TableCell>
                                        <TableCell>
                                            <div className="text-sm text-muted-foreground">
                                                {provider.success_count.toLocaleString()} sent
                                            </div>
                                            <div className="text-xs text-muted-foreground/70">
                                                {provider.failure_count.toLocaleString()} failed
                                            </div>
                                        </TableCell>
                                        <TableCell className="space-x-1 text-right">
                                            <Tooltip>
                                                <TooltipTrigger asChild>
                                                    <Button
                                                        variant="ghost"
                                                        size="sm"
                                                        className="rounded-full"
                                                        onClick={() => navigate(`/messaging/providers/${provider.id}`)}
                                                    >
                                                        <RefreshCcw className="h-4 w-4" />
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
                                                        size="sm"
                                                        className="rounded-full"
                                                        disabled={provider.is_default || defaultMutation.isPending}
                                                        onClick={() => handleSetDefault(provider)}
                                                    >
                                                        <Star className="h-4 w-4" />
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
                                                        size="sm"
                                                        className="rounded-full"
                                                        disabled={toggleMutation.isPending}
                                                        onClick={() => handleToggle(provider)}
                                                    >
                                                        <Power className="h-4 w-4" />
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
                                                        size="sm"
                                                        className="rounded-full text-destructive"
                                                        disabled={deleteMutation.isPending}
                                                        onClick={() => handleDelete(provider)}
                                                    >
                                                        <AlertTriangle className="h-4 w-4" />
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
                    )}
                </CardContent>
            </Card>

            <div className="grid gap-4 md:grid-cols-3">
                <Card className="rounded-3xl border bg-gradient-to-br from-emerald-500/10 to-transparent">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                            <MailCheck className="h-4 w-4 text-primary" /> Deliverability
                        </CardTitle>
                        <CardDescription>
                            Enabled providers used for warm failover routing.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <p className="text-3xl font-semibold text-foreground">
                            {providers.filter((p) => p.enabled).length} / {providers.length}
                        </p>
                    </CardContent>
                </Card>
                <Card className="rounded-3xl border bg-gradient-to-br from-blue-500/10 to-transparent">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                            <Shield className="h-4 w-4 text-secondary" /> Default Guard
                        </CardTitle>
                        <CardDescription>
                            Traffic automatically flows to the default provider first.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        {providers.find((p) => p.is_default) ? (
                            <div>
                                <p className="text-sm text-muted-foreground">Currently pinned to</p>
                                <p className="text-xl font-semibold text-foreground">
                                    {providers.find((p) => p.is_default)?.name}
                                </p>
                            </div>
                        ) : (
                            <p className="text-muted-foreground">
                                No default provider selected
                            </p>
                        )}
                    </CardContent>
                </Card>
                <Card className="rounded-3xl border bg-gradient-to-br from-amber-500/10 to-transparent">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                            <MailWarning className="h-4 w-4 text-secondary" /> Retries
                        </CardTitle>
                        <CardDescription>
                            Average max retries across providers.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <p className="text-3xl font-semibold text-foreground">
                            {providers.length
                                ? (
                                    providers.reduce((sum, p) => sum + (p.max_retries || 0), 0) /
                                    providers.length
                                ).toFixed(1)
                                : '0.0'}
                        </p>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
