import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { User, Lock, ShieldCheck } from 'lucide-react';
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
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { Badge } from '@/components/ui/badge';

export function ProfilePage() {
    const { toast } = useToast();
    const { user, refreshSession } = useAuth();

    const [username, setUsername] = useState(user?.username || '');
    const [currentPassword, setCurrentPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');

    const updateMutation = useMutation({
        mutationFn: (data: { username: string }) => api.updateProfile(data),
        onSuccess: () => {
            refreshSession();
            toast({ title: 'Profile updated successfully' });
        },
        onError: (error) => {
            toast({
                title: 'Failed to update profile',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const changePasswordMutation = useMutation({
        mutationFn: ({
            current,
            newPass,
        }: {
            current: string;
            newPass: string;
        }) => api.changePassword(current, newPass),
        onSuccess: () => {
            toast({ title: 'Password changed successfully' });
            setCurrentPassword('');
            setNewPassword('');
            setConfirmPassword('');
        },
        onError: (error) => {
            toast({
                title: 'Failed to change password',
                description: error instanceof Error ? error.message : 'Unknown error',
                variant: 'destructive',
            });
        },
    });

    const handleUpdateProfile = (e: React.FormEvent) => {
        e.preventDefault();
        updateMutation.mutate({ username });
    };

    const handleChangePassword = (e: React.FormEvent) => {
        e.preventDefault();
        if (newPassword !== confirmPassword) {
            toast({
                title: 'Passwords do not match',
                variant: 'destructive',
            });
            return;
        }
        changePasswordMutation.mutate({
            current: currentPassword,
            newPass: newPassword,
        });
    };

    return (
        <div className="space-y-8">
            <div className="space-y-3">
                <Badge variant="secondary" className="rounded-full border bg-muted px-4 py-1 text-xs uppercase tracking-[0.4em] text-muted-foreground">
                    Operator profile
                </Badge>
                <div>
                    <h1 className="text-4xl font-semibold tracking-tight">Identity & Security</h1>
                    <p className="text-muted-foreground">
                        Keep your mission control credentials crisp and compliant.
                    </p>
                </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
                <Card className="glass-panel rounded-3xl border">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-2xl">
                            <User className="h-5 w-5 text-primary" />
                            Account Details
                        </CardTitle>
                        <CardDescription>
                            Update the operator handle displayed across the dashboard
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleUpdateProfile} className="space-y-5">
                            <div className="space-y-2">
                                <Label htmlFor="username">Username</Label>
                                <Input
                                    id="username"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    required
                                    className="h-11 rounded-2xl border bg-muted"
                                />
                            </div>
                            <Button
                                type="submit"
                                disabled={updateMutation.isPending}
                                className="rounded-2xl"
                            >
                                {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
                            </Button>
                        </form>
                    </CardContent>
                </Card>

                <Card className="glass-panel rounded-3xl border">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-2xl">
                            <Lock className="h-5 w-5 text-secondary" />
                            Change Password
                        </CardTitle>
                        <CardDescription>
                            Rotate secrets frequently to keep the command center hardened
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleChangePassword} className="space-y-4">
                            <div className="space-y-2">
                                <Label htmlFor="currentPassword">Current Password</Label>
                                <Input
                                    id="currentPassword"
                                    type="password"
                                    value={currentPassword}
                                    onChange={(e) => setCurrentPassword(e.target.value)}
                                    required
                                    className="h-11 rounded-2xl border bg-muted"
                                />
                            </div>

                            <Separator className="bg-border" />

                            <div className="space-y-2">
                                <Label htmlFor="newPassword">New Password</Label>
                                <Input
                                    id="newPassword"
                                    type="password"
                                    value={newPassword}
                                    onChange={(e) => setNewPassword(e.target.value)}
                                    required
                                    className="h-11 rounded-2xl border bg-muted"
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="confirmPassword">Confirm New Password</Label>
                                <Input
                                    id="confirmPassword"
                                    type="password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    required
                                    className="h-11 rounded-2xl border bg-muted"
                                />
                            </div>

                            <Button
                                type="submit"
                                disabled={changePasswordMutation.isPending}
                                className="rounded-2xl"
                            >
                                {changePasswordMutation.isPending
                                    ? 'Changing...'
                                    : 'Change Password'}
                            </Button>
                        </form>
                    </CardContent>
                </Card>
            </div>

            <Card className="glass-panel rounded-3xl border">
                <CardHeader className="flex flex-col gap-2 text-sm text-muted-foreground">
                    <CardTitle className="flex items-center gap-2 text-lg">
                        <ShieldCheck className="h-5 w-5 text-primary" />
                        Session integrity
                    </CardTitle>
                    <CardDescription>
                        {user?.username} · Logged in device fingerprint refreshed {new Date().toLocaleTimeString()}
                    </CardDescription>
                </CardHeader>
            </Card>
        </div>
    );
}
