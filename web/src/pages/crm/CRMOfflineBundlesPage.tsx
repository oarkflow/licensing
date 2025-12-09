import { useState } from 'react';
import type { FormEvent } from 'react';
import { useMutation } from '@tanstack/react-query';
import { FileLock, Loader2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';
import { CRMGuard } from '@/components/crm/CRMAuthGate';
import useCRM from '@/hooks/useCRM';
import crmService from '@/services/crm';
import type { CRMOfflineBundle } from '@/types/crm';

export function CRMOfflineBundlesPage() {
    const { session } = useCRM();
    const { toast } = useToast();
    const [bundle, setBundle] = useState<CRMOfflineBundle | null>(null);

    const mutation = useMutation({
        mutationFn: crmService.fetchOfflineBundle.bind(crmService),
        onSuccess: (data) => {
            setBundle(data);
            toast({
                title: 'Offline bundle ready',
                description: `Bundle v${data.version} signed successfully.`,
            });
        },
        onError: (error: unknown) => {
            toast({
                title: 'Bundle generation failed',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    if (!session) {
        return (
            <CRMGuard
                title="Authenticate to mint bundles"
                description="Licensing manage scope required for offline payloads."
            >
                {null}
            </CRMGuard>
        );
    }

    const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const formData = new FormData(event.currentTarget);
        const licenseId = String(formData.get('license_id') || '').trim();
        if (!licenseId) {
            toast({
                title: 'License required',
                description: 'Provide the license identifier to package.',
                variant: 'destructive',
            });
            return;
        }
        mutation.mutate(licenseId);
    };

    const copyToClipboard = (value: string, label: string) => {
        if (typeof navigator !== 'undefined' && navigator.clipboard) {
            navigator.clipboard.writeText(value);
            toast({ title: `${label} copied` });
        }
    };

    return (
        <CRMGuard
            title="Authenticate to mint bundles"
            description="Licensing manage scope required for offline payloads."
        >
            <div className="space-y-8">
                <div className="space-y-3">
                    <Badge variant="secondary" className="rounded-full border bg-muted px-4 py-1 text-xs uppercase tracking-[0.4em]">
                        CRM
                    </Badge>
                    <h1 className="text-4xl font-semibold">Offline bundles</h1>
                    <p className="text-muted-foreground">
                        Generate transportable, signed payloads for air-gapped deployments in seconds.
                    </p>
                </div>

                <Card className="rounded-3xl border bg-card/70">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <FileLock className="h-5 w-5 text-primary" />
                            Bundle generator
                        </CardTitle>
                        <CardDescription>Enter the license id you want to export.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form className="space-y-4" onSubmit={handleSubmit}>
                            <Input name="license_id" placeholder="License ID" className="rounded-2xl" required />
                            <Button type="submit" className="rounded-2xl" disabled={mutation.isPending}>
                                {mutation.isPending ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Bundling…
                                    </>
                                ) : (
                                    'Generate bundle'
                                )}
                            </Button>
                        </form>
                    </CardContent>
                </Card>

                {bundle && (
                    <Card className="rounded-3xl border bg-card/60">
                        <CardHeader>
                            <CardTitle>Signed payload</CardTitle>
                            <CardDescription>Copy and deliver the payload to offline agents.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4 text-sm">
                            <div className="grid gap-4 md:grid-cols-2">
                                <div>
                                    <div className="text-muted-foreground text-xs uppercase tracking-widest">License</div>
                                    <div className="font-mono text-xs">{bundle.license_id}</div>
                                </div>
                                <div>
                                    <div className="text-muted-foreground text-xs uppercase tracking-widest">Revocation epoch</div>
                                    <div>{bundle.revocation_epoch}</div>
                                </div>
                                <div>
                                    <div className="text-muted-foreground text-xs uppercase tracking-widest">Issued at</div>
                                    <div>{new Date(bundle.issued_at).toLocaleString()}</div>
                                </div>
                                <div>
                                    <div className="text-muted-foreground text-xs uppercase tracking-widest">Expires at</div>
                                    <div>{new Date(bundle.expires_at).toLocaleString()}</div>
                                </div>
                            </div>
                            <div>
                                <div className="flex items-center justify-between text-xs uppercase tracking-widest text-muted-foreground">
                                    Bundle
                                    <Button size="sm" variant="ghost" onClick={() => copyToClipboard(bundle.bundle, 'Bundle')}>
                                        Copy
                                    </Button>
                                </div>
                                <Textarea readOnly rows={6} value={bundle.bundle} className="mt-2 font-mono text-xs" />
                            </div>
                            <div>
                                <div className="flex items-center justify-between text-xs uppercase tracking-widest text-muted-foreground">
                                    Signature
                                    <Button size="sm" variant="ghost" onClick={() => copyToClipboard(bundle.signature, 'Signature')}>
                                        Copy
                                    </Button>
                                </div>
                                <Textarea readOnly rows={3} value={bundle.signature} className="mt-2 font-mono text-xs" />
                            </div>
                        </CardContent>
                    </Card>
                )}
            </div>
        </CRMGuard>
    );
}

export default CRMOfflineBundlesPage;
