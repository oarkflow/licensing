import { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Key, Loader2, CheckCircle } from 'lucide-react';
import api from '@/services/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/contexts/AuthContext';

export function SetupPage() {
    const navigate = useNavigate();
    const { isLoading: authLoading, refreshSession } = useAuth();

    const [username, setUsername] = useState('admin');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [success, setSuccess] = useState(false);

    const { data: setupResponse, isLoading: checkingSetup } = useQuery({
        queryKey: ['setup-required'],
        queryFn: () => api.checkSetupRequired(),
    });

    if (authLoading || checkingSetup) {
        return (
            <div className="flex h-screen items-center justify-center bg-background">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
        );
    }

    if (!setupResponse?.data?.required) {
        return <Navigate to="/login" replace />;
    }

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (password.length < 8) {
            setError('Password must be at least 8 characters');
            return;
        }

        setIsLoading(true);

        try {
            const result = await api.setup({ username, password });
            if (result.success) {
                setSuccess(true);
                await refreshSession();
                setTimeout(() => navigate('/'), 2000);
            } else {
                setError(result.error || 'Setup failed');
            }
        } catch {
            setError('An error occurred. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    if (success) {
        return (
            <div className="flex min-h-screen items-center justify-center bg-background px-4">
                <div className="w-full max-w-sm border-y py-8 text-center">
                    <CheckCircle className="mx-auto h-10 w-10 text-primary" />
                    <h2 className="mt-4 text-xl font-semibold">Setup Complete</h2>
                    <p className="mt-2 text-sm text-muted-foreground">
                        Your administrator account has been created. Redirecting to the dashboard.
                    </p>
                    <Loader2 className="mx-auto mt-5 h-5 w-5 animate-spin text-muted-foreground" />
                </div>
            </div>
        );
    }

    return (
        <div className="grid min-h-screen bg-background lg:grid-cols-[minmax(320px,0.9fr)_1fr]">
            <section className="hidden border-r bg-sidebar px-8 py-10 text-sidebar-foreground lg:flex lg:flex-col">
                <div className="flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
                        <Key className="h-4 w-4" />
                    </div>
                    <div>
                        <p className="text-sm font-semibold">Licensing Admin</p>
                        <p className="text-xs text-sidebar-foreground/65">Initial setup</p>
                    </div>
                </div>
                <div className="mt-auto max-w-md border-t pt-6">
                    <h1 className="text-2xl font-semibold">Create the first administrator account.</h1>
                    <p className="mt-3 text-sm leading-6 text-sidebar-foreground/70">
                        This account will manage licensing, catalog, messaging, and administrative configuration.
                    </p>
                </div>
            </section>

            <main className="flex items-center justify-center px-4 py-10">
                <div className="w-full max-w-sm">
                    <div className="mb-6 border-b pb-4">
                        <div className="mb-4 flex items-center gap-2 lg:hidden">
                            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
                                <Key className="h-4 w-4" />
                            </div>
                            <span className="text-sm font-semibold">Licensing Admin</span>
                        </div>
                        <p className="text-xs font-medium uppercase text-muted-foreground">Setup</p>
                        <h1 className="mt-1 text-xl font-semibold">Initial administrator</h1>
                        <p className="mt-1 text-xs text-muted-foreground">Create the first console user.</p>
                    </div>

                    <form onSubmit={handleSubmit} className="space-y-4">
                        {error && (
                            <div className="border-l-2 border-destructive bg-muted px-3 py-2 text-xs text-destructive">
                                {error}
                            </div>
                        )}

                        <div className="space-y-1.5">
                            <Label htmlFor="username">Username</Label>
                            <Input
                                id="username"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                placeholder="admin"
                                required
                                autoFocus
                            />
                        </div>

                        <div className="space-y-1.5">
                            <Label htmlFor="password">Password</Label>
                            <Input
                                id="password"
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Enter password"
                                required
                            />
                            <p className="text-xs text-muted-foreground">Minimum 8 characters.</p>
                        </div>

                        <div className="space-y-1.5">
                            <Label htmlFor="confirmPassword">Confirm Password</Label>
                            <Input
                                id="confirmPassword"
                                type="password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                placeholder="Confirm password"
                                required
                            />
                        </div>

                        <Button type="submit" className="w-full" disabled={isLoading}>
                            {isLoading ? (
                                <>
                                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                    Creating Account...
                                </>
                            ) : (
                                'Create Admin Account'
                            )}
                        </Button>
                    </form>
                </div>
            </main>
        </div>
    );
}
