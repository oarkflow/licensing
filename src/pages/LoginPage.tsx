import { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { Key, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/contexts/AuthContext';

export function LoginPage() {
    const navigate = useNavigate();
    const { login, isAuthenticated, isLoading: authLoading } = useAuth();

    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    if (authLoading) {
        return (
            <div className="flex h-screen items-center justify-center bg-background">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
        );
    }

    if (isAuthenticated) {
        return <Navigate to="/" replace />;
    }

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);

        try {
            const result = await login({ username, password });
            if (result.success) {
                navigate('/');
            } else {
                setError(result.error || 'Invalid credentials');
            }
        } catch {
            setError('An error occurred. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="grid min-h-screen bg-background lg:grid-cols-[minmax(320px,0.9fr)_1fr]">
            <section className="hidden border-r bg-sidebar px-8 py-10 text-sidebar-foreground lg:flex lg:flex-col">
                <div className="flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
                        <Key className="h-4 w-4" />
                    </div>
                    <div>
                        <p className="text-sm font-semibold">Licensing Admin</p>
                        <p className="text-xs text-sidebar-foreground/65">Operations console</p>
                    </div>
                </div>

                <div className="mt-auto max-w-md border-t pt-6">
                    <h1 className="text-2xl font-semibold">Manage licenses with clear operational controls.</h1>
                    <p className="mt-3 text-sm leading-6 text-sidebar-foreground/70">
                        Sign in to issue licenses, review clients, manage products, and maintain administrative access.
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
                        <p className="text-xs font-medium uppercase text-muted-foreground">Access</p>
                        <h1 className="mt-1 text-xl font-semibold">Sign in</h1>
                        <p className="mt-1 text-xs text-muted-foreground">Use your administrator credentials.</p>
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
                                autoComplete="username"
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
                                autoComplete="current-password"
                            />
                        </div>

                        <Button type="submit" className="w-full" disabled={isLoading}>
                            {isLoading ? (
                                <>
                                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                    Signing in...
                                </>
                            ) : (
                                'Sign In'
                            )}
                        </Button>
                    </form>
                </div>
            </main>
        </div>
    );
}
