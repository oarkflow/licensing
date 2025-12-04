import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Beaker, Loader2, Save, Shield, Trash2 } from 'lucide-react';
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
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/hooks/use-toast';
import type { EmailProvider, EmailProviderType, SaveEmailProviderRequest } from '@/types/api';

interface ProviderFormState {
    name: string;
    slug: string;
    type: EmailProviderType;
    priority: string;
    maxRetries: string;
    retryBaseMs: string;
    retryMaxMs: string;
    retryJitterPct: string;
    isDefault: boolean;
    enabled: boolean;
}

const providerTypeOptions: { label: string; value: EmailProviderType }[] = [
    { label: 'SMTP', value: 'smtp' },
    { label: 'SendGrid', value: 'sendgrid' },
    { label: 'Amazon SES', value: 'ses' },
    { label: 'Custom', value: 'custom' },
];

const defaultConfigTemplate = JSON.stringify(
    {
        host: 'smtp.example.com',
        port: 587,
        username: 'api@example.com',
        password: 'change-me',
        from_email: 'noreply@example.com',
        use_tls: false,
        start_tls: true,
        skip_tls_verify: false,
        timeout_seconds: 10,
    },
    null,
    2
);

export function MessagingProviderFormPage() {
    const { providerId } = useParams();
    const isEditMode = Boolean(providerId);
    const navigate = useNavigate();
    const { toast } = useToast();
    const queryClient = useQueryClient();

    const [formState, setFormState] = useState<ProviderFormState>({
        name: '',
        slug: '',
        type: 'smtp',
        priority: '100',
        maxRetries: '3',
        retryBaseMs: '1000',
        retryMaxMs: '60000',
        retryJitterPct: '0.25',
        isDefault: true,
        enabled: true,
    });
    const [configText, setConfigText] = useState(defaultConfigTemplate);
    const [metadataText, setMetadataText] = useState('');
    const [testEmail, setTestEmail] = useState('');

    const { data: providerResponse, isLoading: isLoadingProvider } = useQuery({
        queryKey: ['emailProvider', providerId],
        queryFn: () => api.getEmailProvider(providerId || ''),
        enabled: isEditMode,
    });

    const provider: EmailProvider | undefined = useMemo(
        () => providerResponse?.data,
        [providerResponse]
    );

    useEffect(() => {
        if (!provider) return;
        setFormState({
            name: provider.name,
            slug: provider.slug,
            type: provider.type,
            priority: provider.priority.toString(),
            maxRetries: provider.max_retries?.toString() || '3',
            retryBaseMs: provider.retry_base_ms?.toString() || '1000',
            retryMaxMs: provider.retry_max_ms?.toString() || '60000',
            retryJitterPct: provider.retry_jitter_pct?.toString() || '0.25',
            isDefault: provider.is_default,
            enabled: provider.enabled,
        });
        setConfigText(JSON.stringify(provider.config ?? {}, null, 2));
        setMetadataText(provider.metadata ? JSON.stringify(provider.metadata, null, 2) : '');
    }, [provider]);

    const buildPayload = (): SaveEmailProviderRequest | null => {
        if (!formState.name || !formState.slug) {
            toast({
                title: 'Missing fields',
                description: 'Name and slug are required.',
                variant: 'destructive',
            });
            return null;
        }
        let config: Record<string, unknown> = {};
        try {
            config = configText.trim() ? JSON.parse(configText) : {};
        } catch (error) {
            toast({
                title: 'Invalid config JSON',
                description: error instanceof Error ? error.message : 'Check JSON formatting.',
                variant: 'destructive',
            });
            return null;
        }
        let metadata: Record<string, string> | undefined;
        if (metadataText.trim()) {
            try {
                const parsed = JSON.parse(metadataText);
                metadata = Object.keys(parsed).reduce<Record<string, string>>((acc, key) => {
                    acc[key] = String(parsed[key]);
                    return acc;
                }, {});
            } catch (error) {
                toast({
                    title: 'Invalid metadata JSON',
                    description: error instanceof Error ? error.message : 'Check JSON formatting.',
                    variant: 'destructive',
                });
                return null;
            }
        }
        return {
            name: formState.name.trim(),
            slug: formState.slug.trim(),
            type: formState.type,
            priority: Number(formState.priority) || 0,
            max_retries: Number(formState.maxRetries) || 3,
            retry_base_ms: Number(formState.retryBaseMs) || 1000,
            retry_max_ms: Number(formState.retryMaxMs) || 60000,
            retry_jitter_pct: Number(formState.retryJitterPct) || 0,
            is_default: formState.isDefault,
            enabled: formState.enabled,
            config,
            metadata,
        };
    };

    const saveMutation = useMutation({
        mutationFn: (payload: SaveEmailProviderRequest) =>
            isEditMode && providerId ? api.updateEmailProvider(providerId, payload) : api.createEmailProvider(payload),
        onSuccess: () => {
            toast({ title: isEditMode ? 'Provider updated' : 'Provider created' });
            queryClient.invalidateQueries({ queryKey: ['emailProviders'] });
            navigate('/messaging/providers');
        },
        onError: (error) => {
            toast({
                title: 'Unable to save provider',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const testMutation = useMutation({
        mutationFn: (payload: { provider: SaveEmailProviderRequest; test_email: string }) =>
            api.testEmailProvider(payload),
        onSuccess: () => {
            toast({ title: 'Test email enqueued successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Test failed',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const deleteMutation = useMutation({
        mutationFn: (id: string) => api.deleteEmailProvider(id),
        onSuccess: () => {
            toast({ title: 'Provider deleted' });
            queryClient.invalidateQueries({ queryKey: ['emailProviders'] });
            navigate('/messaging/providers');
        },
        onError: (error) => {
            toast({
                title: 'Failed to delete provider',
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

    const handleTest = () => {
        const payload = buildPayload();
        if (!payload || !testEmail.trim()) {
            toast({
                title: 'Provide a test recipient',
                description: 'Enter an email address before running a live test.',
                variant: 'destructive',
            });
            return;
        }
        testMutation.mutate({ provider: payload, test_email: testEmail.trim() });
    };

    const handleDelete = () => {
        if (!providerId) return;
        if (!window.confirm('Delete this provider? This cannot be undone.')) {
            return;
        }
        deleteMutation.mutate(providerId);
    };

    if (isEditMode && isLoadingProvider) {
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
                    <p className="text-xs uppercase tracking-[0.4em] text-muted-foreground">Providers</p>
                    <h1 className="text-3xl font-semibold tracking-tight">
                        {isEditMode ? provider?.name || 'Edit Provider' : 'New Email Provider'}
                    </h1>
                    <p className="text-muted-foreground">
                        Configure upstream credentials, retry policy, and routing role.
                    </p>
                </div>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
                <Card className="border-white/5">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Shield className="h-5 w-5 text-primary" /> Identity
                        </CardTitle>
                        <CardDescription>
                            Slug is used for programmatic routing and should be unique.
                        </CardDescription>
                    </CardHeader>
                    <CardContent className="grid gap-6 md:grid-cols-2">
                        <div className="space-y-2">
                            <Label htmlFor="name">Provider name *</Label>
                            <Input
                                id="name"
                                value={formState.name}
                                onChange={(e) => setFormState((prev) => ({ ...prev, name: e.target.value }))}
                                placeholder="Transactional SMTP"
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="slug">Slug *</Label>
                            <Input
                                id="slug"
                                value={formState.slug}
                                onChange={(e) => setFormState((prev) => ({ ...prev, slug: e.target.value }))}
                                placeholder="smtp-primary"
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>Provider type</Label>
                            <select
                                className="w-full rounded-2xl border border-white/10 bg-transparent px-3 py-2"
                                value={formState.type}
                                onChange={(e) =>
                                    setFormState((prev) => ({
                                        ...prev,
                                        type: e.target.value as EmailProviderType,
                                    }))
                                }
                            >
                                {providerTypeOptions.map((option) => (
                                    <option key={option.value} value={option.value} className="bg-background text-foreground">
                                        {option.label}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="priority">Priority</Label>
                            <Input
                                id="priority"
                                type="number"
                                min={0}
                                value={formState.priority}
                                onChange={(e) => setFormState((prev) => ({ ...prev, priority: e.target.value }))}
                            />
                            <p className="text-xs text-muted-foreground">Lower numbers are attempted first.</p>
                        </div>
                    </CardContent>
                </Card>

                <Card className="border-white/5">
                    <CardHeader>
                        <CardTitle>Retry & failover policy</CardTitle>
                        <CardDescription>Define delivery guardrails and jitter behavior.</CardDescription>
                    </CardHeader>
                    <CardContent className="grid gap-6 md:grid-cols-2">
                        <div className="space-y-2">
                            <Label htmlFor="maxRetries">Max retries</Label>
                            <Input
                                id="maxRetries"
                                type="number"
                                min={1}
                                value={formState.maxRetries}
                                onChange={(e) => setFormState((prev) => ({ ...prev, maxRetries: e.target.value }))}
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="retryBase">Retry base (ms)</Label>
                            <Input
                                id="retryBase"
                                type="number"
                                min={0}
                                value={formState.retryBaseMs}
                                onChange={(e) => setFormState((prev) => ({ ...prev, retryBaseMs: e.target.value }))}
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="retryMax">Retry max (ms)</Label>
                            <Input
                                id="retryMax"
                                type="number"
                                min={0}
                                value={formState.retryMaxMs}
                                onChange={(e) => setFormState((prev) => ({ ...prev, retryMaxMs: e.target.value }))}
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="retryJitter">Jitter percent</Label>
                            <Input
                                id="retryJitter"
                                type="number"
                                step="0.05"
                                value={formState.retryJitterPct}
                                onChange={(e) => setFormState((prev) => ({ ...prev, retryJitterPct: e.target.value }))}
                            />
                        </div>
                        <div className="flex items-center gap-4 rounded-2xl border border-white/5 p-4">
                            <div className="flex-1">
                                <p className="font-medium">Default provider</p>
                                <p className="text-sm text-muted-foreground">Use as the primary send node.</p>
                            </div>
                            <Switch
                                checked={formState.isDefault}
                                onCheckedChange={(checked) => setFormState((prev) => ({ ...prev, isDefault: checked }))}
                            />
                        </div>
                        <div className="flex items-center gap-4 rounded-2xl border border-white/5 p-4">
                            <div className="flex-1">
                                <p className="font-medium">Enabled</p>
                                <p className="text-sm text-muted-foreground">Disable to take out of rotation.</p>
                            </div>
                            <Switch
                                checked={formState.enabled}
                                onCheckedChange={(checked) => setFormState((prev) => ({ ...prev, enabled: checked }))}
                            />
                        </div>
                    </CardContent>
                </Card>

                <Card className="border-white/5">
                    <CardHeader>
                        <CardTitle>Connection config</CardTitle>
                        <CardDescription>Paste the JSON payload consumed by the provider driver.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="config">Config JSON *</Label>
                            <Textarea
                                id="config"
                                value={configText}
                                rows={12}
                                onChange={(e) => setConfigText(e.target.value)}
                                className="font-mono"
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="metadata">Metadata (optional)</Label>
                            <Textarea
                                id="metadata"
                                value={metadataText}
                                rows={6}
                                onChange={(e) => setMetadataText(e.target.value)}
                                placeholder={`{"region": "us-east-1"\n}`}
                                className="font-mono"
                            />
                        </div>
                    </CardContent>
                </Card>

                <Card className="border-white/5">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Beaker className="h-5 w-5 text-primary" /> Live test
                        </CardTitle>
                        <CardDescription>Send a verification message without saving changes.</CardDescription>
                    </CardHeader>
                    <CardContent className="flex flex-col gap-4 md:flex-row">
                        <div className="flex-1 space-y-2">
                            <Label htmlFor="testEmail">Recipient address</Label>
                            <Input
                                id="testEmail"
                                type="email"
                                placeholder="founder@example.com"
                                value={testEmail}
                                onChange={(e) => setTestEmail(e.target.value)}
                            />
                        </div>
                        <Button
                            type="button"
                            className="mt-6 rounded-2xl md:mt-auto"
                            disabled={testMutation.isPending || saveMutation.isPending}
                            onClick={handleTest}
                        >
                            {testMutation.isPending ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Testing...
                                </>
                            ) : (
                                <>
                                    <Beaker className="mr-2 h-4 w-4" /> Send Test
                                </>
                            )}
                        </Button>
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
                                {isEditMode ? 'Save Changes' : 'Create Provider'}
                            </>
                        )}
                    </Button>
                    <Button
                        type="button"
                        variant="outline"
                        className="rounded-2xl"
                        onClick={() => navigate('/messaging/providers')}
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
