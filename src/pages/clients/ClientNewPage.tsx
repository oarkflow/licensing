import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Users } from 'lucide-react';
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
import { useToast } from '@/hooks/use-toast';
import type { CreateClientRequest } from '@/types/api';

export function ClientNewPage() {
    const navigate = useNavigate();
    const { toast } = useToast();

    const [formData, setFormData] = useState<CreateClientRequest>({
        email: '',
        username: '',
        password: '',
    });

    const createMutation = useMutation({
        mutationFn: (data: CreateClientRequest) => api.createClient(data),
        onSuccess: (response) => {
            toast({ title: 'Client created successfully' });
            if (response.data?.id) {
                navigate(`/clients/${response.data.id}`);
            } else {
                navigate('/clients');
            }
        },
        onError: (error) => {
            toast({
                title: 'Failed to create client',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        createMutation.mutate(formData);
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">New Client</h1>
                    <p className="text-muted-foreground">Add a new client to the system</p>
                </div>
            </div>

            <Card className="max-w-2xl">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Users className="h-5 w-5" />
                        Client Details
                    </CardTitle>
                    <CardDescription>Enter the client information</CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="email">Email *</Label>
                            <Input
                                id="email"
                                type="email"
                                value={formData.email}
                                onChange={(e) =>
                                    setFormData((prev) => ({ ...prev, email: e.target.value }))
                                }
                                placeholder="client@example.com"
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="username">Username</Label>
                            <Input
                                id="username"
                                value={formData.username}
                                onChange={(e) => setFormData((prev) => ({ ...prev, username: e.target.value }))}
                                placeholder="client-username"
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="password">Password</Label>
                            <Input
                                id="password"
                                type="password"
                                value={formData.password}
                                onChange={(e) => setFormData((prev) => ({ ...prev, password: e.target.value }))}
                                placeholder="Set a password (optional)"
                            />
                        </div>

                        <div className="flex gap-4">
                            <Button
                                type="submit"
                                disabled={
                                    createMutation.isPending || !formData.email
                                }
                            >
                                {createMutation.isPending ? 'Creating...' : 'Create Client'}
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
        </div>
    );
}
