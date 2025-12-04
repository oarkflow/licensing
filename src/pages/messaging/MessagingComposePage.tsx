import { useMemo, useState, useRef } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { ArrowLeft, Mail, MailCheck, MailPlus, Paperclip, Rocket, Send, Sparkles, X } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
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
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import type { Client, EmailAttachment, EmailComposeRequest, EmailComposeResponse, EmailTemplate } from '@/types/api';

export function MessagingComposePage() {
    const navigate = useNavigate();
    const { toast } = useToast();

    const { data: templatesResponse } = useQuery({
        queryKey: ['emailTemplates'],
        queryFn: () => api.listEmailTemplates(),
    });

    const { data: clientsResponse, isLoading: isLoadingClients } = useQuery({
        queryKey: ['clients', 'compose'],
        queryFn: () => api.listClients(),
    });

    const templates: EmailTemplate[] = templatesResponse?.data ?? [];
    const clients: Client[] = clientsResponse?.data ?? [];

    const [selectedTemplateId, setSelectedTemplateId] = useState('');
    const [selectedClientIds, setSelectedClientIds] = useState<string[]>([]);
    const [additionalEmails, setAdditionalEmails] = useState('');
    const [variablesText, setVariablesText] = useState('');
    const [preview, setPreview] = useState<EmailComposeResponse['preview'] | null>(null);
    const [attachments, setAttachments] = useState<EmailAttachment[]>([]);
    const fileInputRef = useRef<HTMLInputElement>(null);

    const selectedTemplate = useMemo(
        () => templates.find((tpl) => tpl.id === selectedTemplateId),
        [selectedTemplateId, templates]
    );

    const buildRequest = (): EmailComposeRequest | null => {
        if (!selectedTemplateId) {
            toast({
                title: 'Template required',
                description: 'Select a template before composing.',
                variant: 'destructive',
            });
            return null;
        }
        const manualEmails = additionalEmails
            .split(/\r?\n|,/)
            .map((value) => value.trim())
            .filter(Boolean);
        if (selectedClientIds.length === 0 && manualEmails.length === 0) {
            toast({
                title: 'Recipients missing',
                description: 'Select at least one client or specify email addresses.',
                variant: 'destructive',
            });
            return null;
        }
        let variables: Record<string, unknown> | undefined;
        if (variablesText.trim()) {
            try {
                variables = JSON.parse(variablesText);
            } catch (error) {
                toast({
                    title: 'Invalid variables JSON',
                    description: error instanceof Error ? error.message : 'Check the JSON formatting.',
                    variant: 'destructive',
                });
                return null;
            }
        }
        return {
            template_id: selectedTemplateId,
            client_ids: selectedClientIds,
            additional_emails: manualEmails,
            variables,
            attachments: attachments.length > 0 ? attachments : undefined,
        };
    };

    const previewMutation = useMutation({
        mutationFn: (payload: EmailComposeRequest) =>
            api.previewEmailCompose(payload),
        onSuccess: (response) => {
            setPreview(response.data?.preview ?? null);
            toast({ title: 'Preview rendered' });
        },
        onError: (error) => {
            toast({
                title: 'Preview failed',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const sendMutation = useMutation({
        mutationFn: (payload: EmailComposeRequest) => api.sendEmailCompose(payload),
        onSuccess: (response) => {
            const count = response.data?.queued_count ?? selectedClientIds.length;
            toast({ title: `Queued ${count} email${count === 1 ? '' : 's'}` });
            setPreview(null);
            setAdditionalEmails('');
            setSelectedClientIds([]);
            setAttachments([]);
        },
        onError: (error) => {
            toast({
                title: 'Send failed',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const toggleClient = (clientId: string, checked: boolean) => {
        setSelectedClientIds((prev) =>
            checked ? [...prev, clientId] : prev.filter((id) => id !== clientId)
        );
    };

    const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const files = event.target.files;
        if (!files || files.length === 0) return;

        const maxFileSize = 10 * 1024 * 1024; // 10MB limit
        const newAttachments: EmailAttachment[] = [];

        for (let i = 0; i < files.length; i++) {
            const file = files[i];

            if (file.size > maxFileSize) {
                toast({
                    title: 'File too large',
                    description: `${file.name} exceeds the 10MB limit.`,
                    variant: 'destructive',
                });
                continue;
            }

            try {
                const base64 = await fileToBase64(file);
                newAttachments.push({
                    filename: file.name,
                    content_type: file.type || 'application/octet-stream',
                    data_base64: base64,
                    size: file.size,
                });
            } catch (error) {
                toast({
                    title: 'Failed to read file',
                    description: `Could not read ${file.name}.`,
                    variant: 'destructive',
                });
            }
        }

        setAttachments((prev) => [...prev, ...newAttachments]);

        // Reset file input
        if (fileInputRef.current) {
            fileInputRef.current.value = '';
        }
    };

    const fileToBase64 = (file: File): Promise<string> => {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => {
                const result = reader.result as string;
                // Remove the data URL prefix (e.g., "data:application/pdf;base64,")
                const base64 = result.split(',')[1];
                resolve(base64);
            };
            reader.onerror = reject;
            reader.readAsDataURL(file);
        });
    };

    const removeAttachment = (index: number) => {
        setAttachments((prev) => prev.filter((_, i) => i !== index));
    };

    const formatFileSize = (bytes: number): string => {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    };

    const handlePreview = () => {
        const payload = buildRequest();
        if (!payload) return;
        previewMutation.mutate({ ...payload, preview: true });
    };

    const handleSend = () => {
        const payload = buildRequest();
        if (!payload) return;
        sendMutation.mutate(payload);
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-3">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)} className="rounded-full">
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <p className="text-xs uppercase tracking-[0.4em] text-muted-foreground">Messaging</p>
                    <h1 className="text-3xl font-semibold tracking-tight">Broadcast Center</h1>
                    <p className="text-muted-foreground">
                        Assemble recipients, variables, and render before enqueueing.
                    </p>
                </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
                <div className="space-y-6">
                    <Card className="border-white/5">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <MailPlus className="h-5 w-5 text-primary" /> Template & recipients
                            </CardTitle>
                            <CardDescription>Select a template then target clients and inboxes.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="space-y-2">
                                <Label>Template</Label>
                                <Select value={selectedTemplateId} onValueChange={setSelectedTemplateId}>
                                    <SelectTrigger className="rounded-2xl border border-white/10 bg-transparent">
                                        <SelectValue placeholder="Pick a template" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {templates.map((template) => (
                                            <SelectItem key={template.id} value={template.id}>
                                                {template.name}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                                {selectedTemplate && (
                                    <p className="text-xs text-muted-foreground">
                                        Subject preview: {selectedTemplate.subject}
                                    </p>
                                )}
                            </div>

                            <div className="grid gap-4 md:grid-cols-2">
                                <div className="space-y-3">
                                    <div className="flex items-center justify-between">
                                        <Label>Clients</Label>
                                        <Badge variant="secondary" className="rounded-full">
                                            {selectedClientIds.length} selected
                                        </Badge>
                                    </div>
                                    <div className="rounded-2xl border border-white/5">
                                        <ScrollArea className="h-72 p-4">
                                            {isLoadingClients ? (
                                                <p className="text-sm text-muted-foreground">Loading clients…</p>
                                            ) : clients.length === 0 ? (
                                                <p className="text-sm text-muted-foreground">
                                                    No clients available
                                                </p>
                                            ) : (
                                                clients.map((client) => (
                                                    <div key={client.id} className="flex items-center gap-3 py-2">
                                                        <Checkbox
                                                            id={`client-${client.id}`}
                                                            checked={selectedClientIds.includes(client.id)}
                                                            onCheckedChange={(checked) =>
                                                                toggleClient(client.id, Boolean(checked))
                                                            }
                                                        />
                                                        <Label htmlFor={`client-${client.id}`} className="flex flex-col gap-0 text-sm">
                                                            <span className="font-medium text-white">{client.email}</span>
                                                            <span className="text-xs text-muted-foreground">{client.id.substring(0, 8)}…</span>
                                                        </Label>
                                                    </div>
                                                ))
                                            )}
                                        </ScrollArea>
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="manualEmails">Ad-hoc recipients</Label>
                                    <Textarea
                                        id="manualEmails"
                                        rows={10}
                                        value={additionalEmails}
                                        onChange={(e) => setAdditionalEmails(e.target.value)}
                                        placeholder="ceo@example.com, ops@example.com"
                                    />
                                    <p className="text-xs text-muted-foreground">Comma or newline separated.</p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>

                    <Card className="border-white/5">
                        <CardHeader>
                            <CardTitle>Template variables</CardTitle>
                            <CardDescription>JSON payload merged into the template context.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-2">
                            <Textarea
                                rows={8}
                                value={variablesText}
                                onChange={(e) => setVariablesText(e.target.value)}
                                placeholder={`{"product": "Pro Plan"\n}`}
                                className="font-mono"
                            />
                            <p className="text-xs text-muted-foreground">
                                Accessed inside templates via {'{{ index .Vars "product" }}'}.
                            </p>
                        </CardContent>
                    </Card>

                    <Card className="border-white/5">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Paperclip className="h-5 w-5 text-primary" /> Attachments
                            </CardTitle>
                            <CardDescription>Attach files to include with the email (max 10MB each).</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="flex items-center gap-3">
                                <input
                                    ref={fileInputRef}
                                    type="file"
                                    multiple
                                    onChange={handleFileSelect}
                                    className="hidden"
                                    id="file-upload"
                                />
                                <Button
                                    type="button"
                                    variant="outline"
                                    className="rounded-2xl"
                                    onClick={() => fileInputRef.current?.click()}
                                >
                                    <Paperclip className="mr-2 h-4 w-4" /> Add Files
                                </Button>
                                {attachments.length > 0 && (
                                    <Badge variant="secondary" className="rounded-full">
                                        {attachments.length} file{attachments.length === 1 ? '' : 's'}
                                    </Badge>
                                )}
                            </div>

                            {attachments.length > 0 && (
                                <div className="space-y-2">
                                    {attachments.map((att, index) => (
                                        <div
                                            key={index}
                                            className="flex items-center justify-between rounded-xl border border-white/10 bg-black/20 px-4 py-2"
                                        >
                                            <div className="flex items-center gap-3">
                                                <Paperclip className="h-4 w-4 text-muted-foreground" />
                                                <div>
                                                    <p className="text-sm font-medium">{att.filename}</p>
                                                    <p className="text-xs text-muted-foreground">
                                                        {att.content_type} • {formatFileSize(att.size || 0)}
                                                    </p>
                                                </div>
                                            </div>
                                            <Button
                                                type="button"
                                                variant="ghost"
                                                size="icon"
                                                className="h-8 w-8 rounded-full"
                                                onClick={() => removeAttachment(index)}
                                            >
                                                <X className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    <div className="flex flex-wrap gap-3">
                        <Button
                            type="button"
                            variant="outline"
                            className="rounded-2xl"
                            disabled={previewMutation.isPending}
                            onClick={handlePreview}
                        >
                            {previewMutation.isPending ? (
                                <>
                                    <Sparkles className="mr-2 h-4 w-4 animate-spin" /> Rendering…
                                </>
                            ) : (
                                <>
                                    <Mail className="mr-2 h-4 w-4" /> Preview
                                </>
                            )}
                        </Button>
                        <Button
                            type="button"
                            className="rounded-2xl"
                            disabled={sendMutation.isPending}
                            onClick={handleSend}
                        >
                            {sendMutation.isPending ? (
                                <>
                                    <Rocket className="mr-2 h-4 w-4 animate-spin" /> Queueing…
                                </>
                            ) : (
                                <>
                                    <Send className="mr-2 h-4 w-4" /> Send
                                </>
                            )}
                        </Button>
                        <Button
                            type="button"
                            variant="ghost"
                            className="rounded-2xl"
                            onClick={() => {
                                setSelectedClientIds([]);
                                setAdditionalEmails('');
                                setVariablesText('');
                                setPreview(null);
                                setAttachments([]);
                            }}
                        >
                            Reset
                        </Button>
                    </div>
                </div>

                <div className="space-y-6">
                    <Card className="border-white/5">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <MailCheck className="h-5 w-5 text-primary" /> Preview
                            </CardTitle>
                            <CardDescription>Generate preview to inspect subject + body.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            {preview ? (
                                <div className="space-y-3">
                                    <div>
                                        <Label>Recipient</Label>
                                        <p className="font-mono text-sm text-primary">{preview.recipient}</p>
                                    </div>
                                    <div>
                                        <Label>Subject</Label>
                                        <p className="font-semibold">{preview.subject}</p>
                                    </div>
                                    {preview.html && (
                                        <div>
                                            <Label>HTML</Label>
                                            <div className="rounded-2xl border border-white/5 bg-black/20 p-4" dangerouslySetInnerHTML={{ __html: preview.html }} />
                                        </div>
                                    )}
                                    {preview.text && (
                                        <div>
                                            <Label>Text</Label>
                                            <pre className="rounded-2xl border border-white/5 bg-black/30 p-4 text-sm text-muted-foreground overflow-auto">
                                                {preview.text}
                                            </pre>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="rounded-3xl border border-dashed border-white/10 p-8 text-center text-sm text-muted-foreground">
                                    <MailCheck className="mx-auto mb-4 h-10 w-10 text-muted-foreground" />
                                    Preview renders appear here after you select a template, recipients, and click Preview.
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    <Card className="border-white/5">
                        <CardHeader>
                            <CardTitle>Delivery health</CardTitle>
                            <CardDescription>Quick stats before sending.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm text-muted-foreground">
                            <div className="flex items-center justify-between">
                                <span>Templates available</span>
                                <span className="text-white">{templates.length}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span>Clients selected</span>
                                <span className="text-white">{selectedClientIds.length}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span>Manual recipients</span>
                                <span className="text-white">{
                                    additionalEmails
                                        .split(/\r?\n|,/)
                                        .map((value) => value.trim())
                                        .filter(Boolean).length
                                }</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span>Attachments</span>
                                <span className="text-white">{attachments.length}</span>
                            </div>
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}
