import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, BookOpenText, Loader2, Save, Trash2 } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import type { EmailProvider, EmailTemplate, SaveEmailTemplateRequest } from '@/types/api';

interface TemplateFormState {
    name: string;
    slug: string;
    category: string;
    subject: string;
    htmlBody: string;
    textBody: string;
    description: string;
    defaultProviderId: string;
    maxRetriesOverride: string;
    metadataText: string;
}

export function MessagingTemplateFormPage() {
    const { templateId } = useParams();
    const isEditMode = Boolean(templateId);
    const navigate = useNavigate();
    const { toast } = useToast();
    const queryClient = useQueryClient();

    const [formState, setFormState] = useState<TemplateFormState>({
        name: '',
        slug: '',
        category: 'general',
        subject: '',
        htmlBody: '<h1>Hello {{ .Client.Email }}</h1>',
        textBody: 'Hi {{ .Client.Email }}',
        description: '',
        defaultProviderId: '',
        maxRetriesOverride: '',
        metadataText: '',
    });

    const { data: templateResponse, isLoading: isLoadingTemplate } = useQuery({
        queryKey: ['emailTemplate', templateId],
        queryFn: () => api.getEmailTemplate(templateId || ''),
        enabled: isEditMode,
    });

    const { data: providerResponse } = useQuery({
        queryKey: ['emailProviders', 'select'],
        queryFn: () => api.listEmailProviders({ includeDisabled: true }),
    });

    const template: EmailTemplate | undefined = useMemo(
        () => templateResponse?.data,
        [templateResponse]
    );
    const providers: EmailProvider[] = providerResponse?.data ?? [];

    useEffect(() => {
        if (!template) return;
        setFormState({
            name: template.name,
            slug: template.slug,
            category: template.category || 'general',
            subject: template.subject,
            htmlBody: template.html_body,
            textBody: template.text_body,
            description: template.description || '',
            defaultProviderId: template.default_provider_id || '',
            maxRetriesOverride: template.max_retries_override?.toString() || '',
            metadataText: template.metadata ? JSON.stringify(template.metadata, null, 2) : '',
        });
    }, [template]);

    const buildPayload = (): SaveEmailTemplateRequest | null => {
        if (!formState.name || !formState.slug || !formState.subject) {
            toast({
                title: 'Missing required fields',
                description: 'Name, slug and subject are required.',
                variant: 'destructive',
            });
            return null;
        }
        let metadata: Record<string, unknown> | undefined;
        if (formState.metadataText.trim()) {
            try {
                metadata = JSON.parse(formState.metadataText);
            } catch (error) {
                toast({
                    title: 'Invalid metadata JSON',
                    description: error instanceof Error ? error.message : 'Check the JSON formatting.',
                    variant: 'destructive',
                });
                return null;
            }
        }
        const payload: SaveEmailTemplateRequest = {
            name: formState.name.trim(),
            slug: formState.slug.trim(),
            category: formState.category.trim() || 'general',
            subject: formState.subject,
            html_body: formState.htmlBody,
            text_body: formState.textBody,
            description: formState.description || undefined,
            metadata,
            default_provider_id: formState.defaultProviderId || undefined,
            max_retries_override: formState.maxRetriesOverride
                ? Number(formState.maxRetriesOverride)
                : undefined,
        };
        return payload;
    };

    const saveMutation = useMutation({
        mutationFn: (payload: SaveEmailTemplateRequest) =>
            isEditMode && templateId
                ? api.updateEmailTemplate(templateId, payload)
                : api.createEmailTemplate(payload),
        onSuccess: () => {
            toast({ title: isEditMode ? 'Template updated' : 'Template created' });
            queryClient.invalidateQueries({ queryKey: ['emailTemplates'] });
            navigate('/messaging/templates');
        },
        onError: (error) => {
            toast({
                title: 'Unable to save template',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const deleteMutation = useMutation({
        mutationFn: (id: string) => api.deleteEmailTemplate(id),
        onSuccess: () => {
            toast({ title: 'Template deleted' });
            queryClient.invalidateQueries({ queryKey: ['emailTemplates'] });
            navigate('/messaging/templates');
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete template',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (event: React.FormEvent) => {
        event.preventDefault();
        const payload = buildPayload();
        if (!payload) return;
        saveMutation.mutate(payload);
    };

    const handleDelete = () => {
        if (!templateId) return;
        if (!window.confirm('Delete this template?')) return;
        deleteMutation.mutate(templateId);
    };

    if (isEditMode && isLoadingTemplate) {
        return (
            <div className="flex h-64 items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-3">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)} className="rounded-full">
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <p className="text-xs uppercase tracking-[0.4em] text-muted-foreground">Templates</p>
                    <h1 className="text-3xl font-semibold tracking-tight">
                        {isEditMode ? template?.name || 'Edit Template' : 'Compose Template'}
                    </h1>
                    <p className="text-muted-foreground">
                        Merge variables are rendered with Go template syntax (<code>{'{{ .Client.Name }}'}</code>).
                    </p>
                </div>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
                <Card className="border-white/5">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <BookOpenText className="h-5 w-5 text-primary" /> Template meta
                        </CardTitle>
                        <CardDescription>Keep slugs stable for integrations.</CardDescription>
                    </CardHeader>
                    <CardContent className="grid gap-6 md:grid-cols-2">
                        <div className="space-y-2">
                            <Label htmlFor="name">Name *</Label>
                            <Input
                                id="name"
                                value={formState.name}
                                onChange={(e) => setFormState((prev) => ({ ...prev, name: e.target.value }))}
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="slug">Slug *</Label>
                            <Input
                                id="slug"
                                value={formState.slug}
                                onChange={(e) => setFormState((prev) => ({ ...prev, slug: e.target.value }))}
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="category">Category</Label>
                            <Input
                                id="category"
                                value={formState.category}
                                onChange={(e) => setFormState((prev) => ({ ...prev, category: e.target.value }))}
                                placeholder="general"
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="description">Description</Label>
                            <Input
                                id="description"
                                value={formState.description}
                                onChange={(e) => setFormState((prev) => ({ ...prev, description: e.target.value }))}
                                placeholder="Welcome email for new licenses"
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>Default provider</Label>
                            <Select
                                value={formState.defaultProviderId || 'inherit'}
                                onValueChange={(value) =>
                                    setFormState((prev) => ({
                                        ...prev,
                                        defaultProviderId: value === 'inherit' ? '' : value,
                                    }))
                                }
                            >
                                <SelectTrigger className="rounded-2xl border border-white/10 bg-transparent">
                                    <SelectValue placeholder="Follow routing">
                                        {formState.defaultProviderId
                                            ? providers.find((p) => p.id === formState.defaultProviderId)?.name
                                            : 'Inherit routing'}
                                    </SelectValue>
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="inherit">Inherit routing</SelectItem>
                                    {providers.map((provider) => (
                                        <SelectItem key={provider.id} value={provider.id}>
                                            {provider.name}
                                        </SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="maxRetries">Max retries override</Label>
                            <Input
                                id="maxRetries"
                                type="number"
                                min={1}
                                value={formState.maxRetriesOverride}
                                onChange={(e) =>
                                    setFormState((prev) => ({ ...prev, maxRetriesOverride: e.target.value }))
                                }
                                placeholder="Leave blank to inherit"
                            />
                        </div>
                    </CardContent>
                </Card>

                <Card className="border-white/5">
                    <CardHeader>
                        <CardTitle>Content</CardTitle>
                        <CardDescription>Write HTML + plaintext bodies along with the subject line.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="subject">Subject *</Label>
                            <Input
                                id="subject"
                                value={formState.subject}
                                onChange={(e) => setFormState((prev) => ({ ...prev, subject: e.target.value }))}
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="htmlBody">HTML body</Label>
                            <Textarea
                                id="htmlBody"
                                rows={10}
                                value={formState.htmlBody}
                                onChange={(e) => setFormState((prev) => ({ ...prev, htmlBody: e.target.value }))}
                                className="font-mono"
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="textBody">Text body</Label>
                            <Textarea
                                id="textBody"
                                rows={6}
                                value={formState.textBody}
                                onChange={(e) => setFormState((prev) => ({ ...prev, textBody: e.target.value }))}
                                className="font-mono"
                            />
                        </div>
                    </CardContent>
                </Card>

                <Card className="border-white/5">
                    <CardHeader>
                        <CardTitle>Metadata (optional)</CardTitle>
                        <CardDescription>Attach structured data for downstream automation.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Textarea
                            rows={6}
                            value={formState.metadataText}
                            onChange={(e) => setFormState((prev) => ({ ...prev, metadataText: e.target.value }))}
                            placeholder='{"category": "activation"}'
                            className="font-mono"
                        />
                    </CardContent>
                </Card>

                <div className="flex flex-wrap gap-3">
                    <Button type="submit" className="rounded-2xl" disabled={saveMutation.isPending}>
                        {saveMutation.isPending ? (
                            <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Saving...
                            </>
                        ) : (
                            <>
                                <Save className="mr-2 h-4 w-4" />
                                {isEditMode ? 'Save Template' : 'Create Template'}
                            </>
                        )}
                    </Button>
                    <Button
                        type="button"
                        variant="outline"
                        className="rounded-2xl"
                        onClick={() => navigate('/messaging/templates')}
                    >
                        Cancel
                    </Button>
                    {isEditMode && (
                        <Button
                            type="button"
                            variant="destructive"
                            className="rounded-2xl"
                            disabled={deleteMutation.isPending}
                            onClick={handleDelete}
                        >
                            <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </Button>
                    )}
                </div>
            </form>
        </div>
    );
}
