import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { FileText, Layers, MailPlus, PenSquare, Plus, Trash2 } from 'lucide-react';
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
import { useToast } from '@/hooks/use-toast';
import type { EmailProvider, EmailTemplate } from '@/types/api';

export function MessagingTemplatesPage() {
    const navigate = useNavigate();
    const { toast } = useToast();
    const queryClient = useQueryClient();

    const { data: templateResponse, isLoading } = useQuery({
        queryKey: ['emailTemplates'],
        queryFn: () => api.listEmailTemplates(),
    });

    const { data: providerResponse } = useQuery({
        queryKey: ['emailProviders', 'light'],
        queryFn: () => api.listEmailProviders({ includeDisabled: true }),
    });

    const templates: EmailTemplate[] = templateResponse?.data ?? [];
    const providers: EmailProvider[] = providerResponse?.data ?? [];
    const providerLookup = useMemo(() => {
        const map = new Map<string, EmailProvider>();
        providers.forEach((provider) => map.set(provider.id, provider));
        return map;
    }, [providers]);

    const deleteMutation = useMutation({
        mutationFn: (id: string) => api.deleteEmailTemplate(id),
        onSuccess: () => {
            toast({ title: 'Template deleted' });
            queryClient.invalidateQueries({ queryKey: ['emailTemplates'] });
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete template',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleDelete = (template: EmailTemplate) => {
        if (!window.confirm(`Delete template ${template.name}?`)) return;
        deleteMutation.mutate(template.id);
    };

    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                    <p className="text-xs uppercase tracking-[0.4em] text-muted-foreground">Messaging</p>
                    <h1 className="text-3xl font-semibold tracking-tight">Email Templates</h1>
                    <p className="text-muted-foreground">
                        Store repeatable subject/body pairs with provider routing.
                    </p>
                </div>
                <Button className="rounded-2xl" onClick={() => navigate('/messaging/templates/new')}>
                    <Plus className="mr-2 h-4 w-4" /> New Template
                </Button>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
                <Card className="rounded-3xl border-border">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                            <Layers className="h-4 w-4 text-primary" /> Catalog
                        </CardTitle>
                        <CardDescription>Total reusable workflows.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <p className="text-4xl font-semibold">{templates.length}</p>
                    </CardContent>
                </Card>
                <Card className="rounded-3xl border-border">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                            <FileText className="h-4 w-4 text-primary" /> Categories
                        </CardTitle>
                        <CardDescription>Group templates for fallbacks.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <p className="text-4xl font-semibold">
                            {new Set(templates.map((tpl) => tpl.category)).size}
                        </p>
                    </CardContent>
                </Card>
                <Card className="rounded-3xl border-border">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                            <MailPlus className="h-4 w-4 text-primary" /> Defaults
                        </CardTitle>
                        <CardDescription>Templates pinned to a provider override.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <p className="text-4xl font-semibold">
                            {templates.filter((tpl) => tpl.default_provider_id).length}
                        </p>
                    </CardContent>
                </Card>
            </div>

            <Card className="border-border">
                <CardHeader>
                    <CardTitle>Templates</CardTitle>
                    <CardDescription>Each template encapsulates HTML + plaintext bodies.</CardDescription>
                </CardHeader>
                <CardContent>
                    {isLoading ? (
                        <div className="space-y-3">
                            {[...Array(4)].map((_, idx) => (
                                <Skeleton key={idx} className="h-16 w-full rounded-2xl" />
                            ))}
                        </div>
                    ) : templates.length === 0 ? (
                        <div className="flex flex-col items-center justify-center rounded-3xl border border-dashed border-border py-12 text-center">
                            <FileText className="h-10 w-10 text-muted-foreground" />
                            <h3 className="mt-4 text-xl font-semibold">No templates yet</h3>
                            <p className="mt-2 text-sm text-muted-foreground">
                                Draft your first transactional template to start composing.
                            </p>
                            <Button className="mt-4 rounded-2xl" onClick={() => navigate('/messaging/templates/new')}>
                                <Plus className="mr-2 h-4 w-4" /> Create Template
                            </Button>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow className="border-border text-xs uppercase tracking-[0.2em] text-muted-foreground">
                                    <TableHead>Name</TableHead>
                                    <TableHead>Category</TableHead>
                                    <TableHead>Subject</TableHead>
                                    <TableHead>Default Provider</TableHead>
                                    <TableHead className="text-right">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {templates.map((template) => (
                                    <TableRow key={template.id} className="border-border">
                                        <TableCell>
                                            <div className="flex flex-col">
                                                <span className="font-medium text-foreground">{template.name}</span>
                                                <span className="text-xs text-muted-foreground">{template.slug}</span>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant="secondary" className="rounded-full">
                                                {template.category || 'general'}
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="max-w-[280px] truncate text-sm text-muted-foreground">
                                            {template.subject}
                                        </TableCell>
                                        <TableCell>
                                            {template.default_provider_id ? (
                                                <span className="text-sm text-foreground">
                                                    {providerLookup.get(template.default_provider_id)?.name || 'Override'}
                                                </span>
                                            ) : (
                                                <span className="text-muted-foreground">Inherit fallback</span>
                                            )}
                                        </TableCell>
                                        <TableCell className="space-x-2 text-right">
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                className="rounded-full"
                                                onClick={() => navigate(`/messaging/templates/${template.id}`)}
                                            >
                                                <PenSquare className="h-4 w-4" />
                                            </Button>
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                className="rounded-full text-destructive"
                                                disabled={deleteMutation.isPending}
                                                onClick={() => handleDelete(template)}
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
        </div>
    );
}
