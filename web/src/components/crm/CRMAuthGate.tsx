import { useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { ShieldCheck, LogIn } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import useCRM from '@/hooks/useCRM';
import { useAuth } from '@/contexts/AuthContext';

interface CRMLoginPanelProps {
    title?: string;
    description?: string;
    className?: string;
}

export function CRMLoginPanel({
    title = 'CRM credentials required',
    description = 'Authenticate with your CRM identity to manage tenants, entitlements, and offline bundles.',
    className,
}: CRMLoginPanelProps) {
    const { login, isLoading } = useCRM();
    const { toast } = useToast();
    const [identifier, setIdentifier] = useState('');
    const [password, setPassword] = useState('');
    const [scope, setScope] = useState('crm:read crm:write');
    const [deviceId, setDeviceId] = useState('');
    const [submitting, setSubmitting] = useState(false);

    const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setSubmitting(true);
        const result = await login({
            identifier,
            password,
            scope: scope.trim() || undefined,
            device_id: deviceId.trim() || undefined,
        });
        setSubmitting(false);
        if (!result.success) {
            toast({
                title: 'CRM login failed',
                description: result.error || 'Verify your credentials and try again.',
                variant: 'destructive',
            });
            return;
        }
        toast({
            title: 'CRM session established',
            description: 'Secure tenant controls unlocked.',
        });
        setPassword('');
    };

    return (
        <Card className={cn('w-full max-w-xl border border-primary/20 bg-card/80 shadow-2xl', className)}>
            <CardHeader>
                <CardTitle className="flex items-center gap-2 text-2xl">
                    <ShieldCheck className="h-5 w-5 text-primary" />
                    {title}
                </CardTitle>
                <CardDescription>{description}</CardDescription>
            </CardHeader>
            <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                    <div className="space-y-2">
                        <Label htmlFor="crm-identifier">Email or username</Label>
                        <Input
                            id="crm-identifier"
                            placeholder="enterprise.owner@company.com"
                            value={identifier}
                            onChange={(event) => setIdentifier(event.target.value)}
                            required
                        />
                    </div>
                    <div className="space-y-2">
                        <div className="flex items-center justify-between">
                            <Label htmlFor="crm-password">Password</Label>
                            <button
                                type="button"
                                className="text-xs text-primary hover:underline"
                                onClick={() => setPassword('')}
                            >
                                Clear
                            </button>
                        </div>
                        <Input
                            id="crm-password"
                            type="password"
                            placeholder="••••••••"
                            value={password}
                            onChange={(event) => setPassword(event.target.value)}
                            required
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="crm-scope">Requested scopes</Label>
                        <Textarea
                            id="crm-scope"
                            value={scope}
                            rows={2}
                            onChange={(event) => setScope(event.target.value)}
                            placeholder="crm:read crm:write licensing:manage"
                        />
                        <p className="text-xs text-muted-foreground">
                            Space-separated scopes aligned with your tenant policy.
                        </p>
                    </div>
                    <div className="space-y-2">
                        <div className="flex items-center justify-between">
                            <Label htmlFor="crm-device">Device fingerprint</Label>
                            <span className="text-xs text-muted-foreground">Optional</span>
                        </div>
                        <Input
                            id="crm-device"
                            value={deviceId}
                            onChange={(event) => setDeviceId(event.target.value)}
                            placeholder="device-laptop-seattle"
                        />
                    </div>
                    <Button
                        type="submit"
                        className="w-full rounded-2xl bg-primary text-primary-foreground"
                        disabled={submitting || isLoading}
                    >
                        <LogIn className="mr-2 h-4 w-4" />
                        {submitting ? 'Authorizing…' : 'Unlock CRM workspace'}
                    </Button>
                </form>
            </CardContent>
        </Card>
    );
}

interface CRMGuardProps {
    children: ReactNode;
    title?: string;
    description?: string;
    allowAdminBypass?: boolean;
}

export function CRMGuard({ children, title, description, allowAdminBypass = false }: CRMGuardProps) {
    const { isAuthenticated, isLoading } = useCRM();
    const { isAuthenticated: isAdminAuthenticated, isLoading: authLoading } = useAuth();

    const crmReady = isAuthenticated;
    const adminBypassReady = allowAdminBypass && isAdminAuthenticated;
    const stillLoading = (!crmReady && isLoading) || (allowAdminBypass && !adminBypassReady && authLoading);

    if (!crmReady && !adminBypassReady) {
        if (stillLoading) {
            return (
                <div className="space-y-4">
                    <div className="flex gap-4">
                        <Skeleton className="h-16 flex-1 rounded-3xl" />
                        <Skeleton className="h-16 flex-1 rounded-3xl" />
                    </div>
                    <Skeleton className="h-[300px] w-full rounded-3xl" />
                </div>
            );
        }
        return (
            <div className="flex w-full items-center justify-center py-16">
                <CRMLoginPanel title={title} description={description} />
            </div>
        );
    }

    return <>{children}</>;
}
