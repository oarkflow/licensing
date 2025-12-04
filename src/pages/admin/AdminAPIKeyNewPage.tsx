import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Key, Copy, AlertTriangle } from 'lucide-react';
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
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import type { CreateAPIKeyRequest } from '@/types/api';

export function AdminAPIKeyNewPage() {
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { toast } = useToast();

    const [formData, setFormData] = useState<CreateAPIKeyRequest>({
        name: '',
        expiresAt: '',
    });

    const [showKeyDialog, setShowKeyDialog] = useState(false);
    const [newKeyValue, setNewKeyValue] = useState('');

    const createMutation = useMutation({
        mutationFn: (data: CreateAPIKeyRequest) => api.createAPIKey(data),
        onSuccess: (response) => {
            queryClient.invalidateQueries({ queryKey: ['api-keys'] });
            if (response.data?.rawKey) {
                setNewKeyValue(response.data.rawKey);
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

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        createMutation.mutate(formData);
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
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">New API Key</h1>
                    <p className="text-muted-foreground">
                        Create a new API key for programmatic access
                    </p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Key className="h-5 w-5" />
                        API Key Details
                    </CardTitle>
                    <CardDescription>Configure the API key settings</CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="name">Name *</Label>
                            <Input
                                id="name"
                                value={formData.name}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, name: e.target.value }))
                                }
                                placeholder="Production API Key"
                                required
                            />
                            <p className="text-xs text-muted-foreground">
                                A descriptive name to identify this key
                            </p>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="expiresAt">Expiration Date</Label>
                            <Input
                                id="expiresAt"
                                type="date"
                                value={formData.expiresAt || ''}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, expiresAt: e.target.value }))
                                }
                            />
                            <p className="text-xs text-muted-foreground">
                                Leave empty for a non-expiring key
                            </p>
                        </div>

                        <div className="flex gap-4">
                            <Button
                                type="submit"
                                disabled={createMutation.isPending || !formData.name}
                            >
                                {createMutation.isPending ? 'Creating...' : 'Create API Key'}
                            </Button>
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => navigate(-1)}
                            >
                                Cancel
                            </Button>
                        </div>
                    </form>
                </CardContent>
            </Card>

            <Dialog open={showKeyDialog} onOpenChange={handleDialogClose}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>API Key Created</DialogTitle>
                        <DialogDescription>
                            Copy your API key now. You won't be able to see it again!
                        </DialogDescription>
                    </DialogHeader>
                    <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertTitle>Important</AlertTitle>
                        <AlertDescription>
                            Store this key securely. This is the only time it will be displayed.
                        </AlertDescription>
                    </Alert>
                    <div className="flex items-center gap-2">
                        <Input value={newKeyValue} readOnly className="font-mono text-sm" />
                        <Button
                            variant="outline"
                            size="icon"
                            onClick={() => copyToClipboard(newKeyValue)}
                        >
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
