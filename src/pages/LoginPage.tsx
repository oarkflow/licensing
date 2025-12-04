import { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { Key, Loader2, ShieldCheck, Sparkles } from 'lucide-react';
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
import { useAuth } from '@/contexts/AuthContext';
import { Badge } from '@/components/ui/badge';

export function LoginPage() {
    const navigate = useNavigate();
    const { login, isAuthenticated, isLoading: authLoading } = useAuth();

    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    if (authLoading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
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
        <div className="relative flex min-h-screen items-center justify-center px-4 py-10">
            <div className="absolute inset-0 -z-10">
                <div className="absolute inset-0 bg-gradient-to-br from-primary/20 via-transparent to-secondary/10" />
                <div className="absolute left-10 top-10 h-64 w-64 rounded-full bg-secondary/20 blur-3xl" />
                <div className="absolute bottom-10 right-10 h-72 w-72 rounded-full bg-primary/30 blur-[140px]" />
            </div>

            <div className="glass-panel grid w-full max-w-5xl overflow-hidden rounded-[32px] border border-white/10 bg-card/60 backdrop-blur-2xl md:grid-cols-[1.1fr_0.9fr]">
                <div className="relative hidden flex-col justify-between bg-gradient-to-b from-primary/10 via-primary/5 to-transparent p-10 text-white md:flex">
                    <div className="space-y-5">
                        <Badge variant="secondary" className="rounded-full border border-white/30 bg-white/20 px-4 py-1 text-xs uppercase tracking-[0.4em] text-white">
                            Licensing OS
                        </Badge>
                        <div className="flex items-center gap-3 text-2xl font-semibold">
                            <Key className="h-8 w-8 text-primary" />
                            License Mission Control
                        </div>
                        <p className="text-lg text-white/80">
                            Secure admin surface for issuing, revoking and auditing software entitlements.
                        </p>
                    </div>
                    <div className="space-y-4 rounded-3xl border border-white/20 bg-white/10 p-6">
                        <div className="flex items-center gap-3">
                            <ShieldCheck className="h-10 w-10 rounded-2xl bg-white/20 p-2" />
                            <div>
                                <p className="text-xs uppercase tracking-[0.3em] text-white/70">Signal</p>
                                <p className="text-xl font-semibold">99.92% uptime</p>
                            </div>
                        </div>
                        <div className="flex items-start gap-3 text-sm text-white/80">
                            <Sparkles className="mt-1 h-4 w-4" />
                            Trusted by every product surface of your licensing stack.
                        </div>
                    </div>
                </div>

                <Card className="rounded-none border-0 bg-card/60 text-card-foreground">
                    <CardHeader className="space-y-2 text-center">
                        <Badge variant="secondary" className="mx-auto mb-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs uppercase tracking-[0.4em] text-muted-foreground">
                            Access
                        </Badge>
                        <CardTitle className="text-3xl">Welcome back</CardTitle>
                        <CardDescription>Authenticate to enter the control room</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleSubmit} className="space-y-5">
                            {error && (
                                <div className="rounded-2xl border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
                                    {error}
                                </div>
                            )}

                            <div className="space-y-2">
                                <Label htmlFor="username">Username</Label>
                                <Input
                                    id="username"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    placeholder="admin"
                                    required
                                    autoComplete="username"
                                    autoFocus
                                    className="h-11 rounded-2xl border-white/10 bg-white/5"
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="password">Password</Label>
                                <Input
                                    id="password"
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="••••••••"
                                    required
                                    autoComplete="current-password"
                                    className="h-11 rounded-2xl border-white/10 bg-white/5"
                                />
                            </div>

                            <Button
                                type="submit"
                                className="h-11 w-full rounded-2xl bg-primary text-primary-foreground shadow-lg shadow-primary/40"
                                disabled={isLoading}
                            >
                                {isLoading ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Signing in...
                                    </>
                                ) : (
                                    'Sign In'
                                )}
                            </Button>
                        </form>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
