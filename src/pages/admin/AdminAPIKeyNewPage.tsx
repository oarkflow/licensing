import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Copy, AlertTriangle } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { FormPanel, PageHeader } from '@/components/layout';

const scopeOptions = [
    { value: 'admin:*', label: 'Full admin access' },
    { value: 'licenses:read', label: 'Read licenses' },
    { value: 'licenses:write', label: 'Write licenses' },
    { value: 'clients:read', label: 'Read clients' },
    { value: 'clients:write', label: 'Write clients' },
    { value: 'catalog:read', label: 'Read catalog' },
    { value: 'catalog:write', label: 'Write catalog' },
    { value: 'coupons:read', label: 'Read coupons' },
    { value: 'coupons:write', label: 'Write coupons' },
    { value: 'audit:read', label: 'Read audit logs' },
];

function linesToList(value: string) {
    return value
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
}

export function AdminAPIKeyNewPage() {
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();
    const { user } = useAuth();

    const [scopes, setScopes] = useState<string[]>(['licenses:read', 'clients:read']);
    const [ttlHours, setTTLHours] = useState('720');
    const [expiresAt, setExpiresAt] = useState('');
    const [allowedIPs, setAllowedIPs] = useState('');
    const [allowedOrigins, setAllowedOrigins] = useState('');
    const [showKeyDialog, setShowKeyDialog] = useState(false);
    const [newKeyValue, setNewKeyValue] = useState('');

    const createMutation = useMutation({
        mutationFn: () => api.createAPIKey(user!.id, {
            scopes,
            ttl_hours: ttlHours ? Number(ttlHours) : undefined,
            expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
            allowed_ips: linesToList(allowedIPs),
            allowed_origins: linesToList(allowedOrigins),
        }),
        onSuccess: (response) => {
            queryClient.invalidateQueries({ queryKey: ['api-keys', user?.id] });
            if (response.data?.token) {
                setNewKeyValue(response.data.token);
                setShowKeyDialog(true);
            } else {
                toast({ title: 'API key created successfully' });
                navigate('/admin/api-keys');
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to create API key',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const toggleScope = (scope: string, checked: boolean) => {
        setScopes((current) => {
            if (checked) {
                if (scope === 'admin:*') return ['admin:*'];
                return current.includes(scope)
                    ? current.filter((item) => item !== 'admin:*')
                    : [...current.filter((item) => item !== 'admin:*'), scope];
            }
            return current.filter((item) => item !== scope);
        });
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (scopes.length === 0) {
            toast({ title: 'Select at least one scope', variant: 'destructive' });
            return;
        }
        createMutation.mutate();
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        toast({ title: 'Copied to clipboard' });
    };

    const handleDialogClose = () => {
        setShowKeyDialog(false);
        navigate('/admin/api-keys');
    };

    return (
        <div className="space-y-4">
            <PageHeader
                eyebrow="Administration"
                title="New API Key"
                description="Issue a scoped platform key with optional expiry, IP, and origin restrictions."
                backTo="/admin/api-keys"
                backLabel="API Keys"
            />

            <form onSubmit={handleSubmit} className="space-y-4">
                <FormPanel
                    title="Access Scopes"
                    description="Use the narrowest scope set needed by the integration."
                >
                    <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                        {scopeOptions.map((scope) => (
                            <label key={scope.value} className="flex items-center gap-2 border-y px-2 py-2 text-sm">
                                <Checkbox
                                    checked={scopes.includes(scope.value)}
                                    onCheckedChange={(checked) => toggleScope(scope.value, checked === true)}
                                />
                                <span>{scope.label}</span>
                                <code className="ml-auto text-[0.65rem] text-muted-foreground">{scope.value}</code>
                            </label>
                        ))}
                    </div>
                </FormPanel>

                <FormPanel
                    title="Expiration"
                    description="Prefer expiring keys. TTL takes precedence unless left empty."
                >
                    <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-1.5">
                            <Label htmlFor="ttlHours">TTL Hours</Label>
                            <Input
                                id="ttlHours"
                                type="number"
                                min="1"
                                value={ttlHours}
                                onChange={(e) => setTTLHours(e.target.value)}
                                placeholder="720"
                            />
                            <p className="text-xs text-muted-foreground">720 hours is 30 days.</p>
                        </div>
                        <div className="space-y-1.5">
                            <Label htmlFor="expiresAt">Explicit Expiration</Label>
                            <Input
                                id="expiresAt"
                                type="datetime-local"
                                value={expiresAt}
                                onChange={(e) => setExpiresAt(e.target.value)}
                                disabled={Boolean(ttlHours)}
                            />
                        </div>
                    </div>
                </FormPanel>

                <FormPanel
                    title="Request Restrictions"
                    description="Optional allow-lists. Put one value per line or comma-separated."
                >
                    <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-1.5">
                            <Label htmlFor="allowedIPs">Allowed IPs / CIDRs</Label>
                            <Textarea
                                id="allowedIPs"
                                value={allowedIPs}
                                onChange={(e) => setAllowedIPs(e.target.value)}
                                placeholder={'203.0.113.10\n10.0.0.0/24'}
                                className="min-h-28 font-mono text-xs"
                            />
                        </div>
                        <div className="space-y-1.5">
                            <Label htmlFor="allowedOrigins">Allowed Origins</Label>
                            <Textarea
                                id="allowedOrigins"
                                value={allowedOrigins}
                                onChange={(e) => setAllowedOrigins(e.target.value)}
                                placeholder={'https://admin.example.com\nhttps://ops.example.com'}
                                className="min-h-28 font-mono text-xs"
                            />
                        </div>
                    </div>
                </FormPanel>

                <div className="sticky bottom-0 flex justify-end gap-2 border-t bg-background px-3 py-3">
                    <Button type="button" variant="outline" onClick={() => navigate('/admin/api-keys')}>
                        Cancel
                    </Button>
                    <Button type="submit" disabled={createMutation.isPending || scopes.length === 0}>
                        {createMutation.isPending ? 'Creating...' : 'Create API Key'}
                    </Button>
                </div>
            </form>

            <Dialog open={showKeyDialog} onOpenChange={handleDialogClose}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>API Key Created</DialogTitle>
                        <DialogDescription>
                            Copy this key now. It will not be shown again.
                        </DialogDescription>
                    </DialogHeader>
                    <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertTitle>Store securely</AlertTitle>
                        <AlertDescription>
                            Treat this key like a password for the selected scopes.
                        </AlertDescription>
                    </Alert>
                    <div className="flex items-center gap-2">
                        <Input value={newKeyValue} readOnly className="font-mono text-xs" />
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(newKeyValue)}>
                            <Copy className="h-4 w-4" />
                        </Button>
                    </div>
                    <DialogFooter>
                        <Button onClick={handleDialogClose}>Done</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
