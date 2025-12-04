import { Outlet, Navigate } from 'react-router-dom';
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar';
import { AppSidebar } from './AppSidebar';
import { AppNavbar } from './AppNavbar';
import { useAuth } from '@/contexts/AuthContext';
import { Loader2 } from 'lucide-react';

export function AppLayout() {
    const { isAuthenticated, isLoading } = useAuth();

    if (isLoading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        );
    }

    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }

    return (
        <SidebarProvider>
            <div className="relative flex min-h-screen w-full overflow-hidden">
                {/* Ambient glows */}
                <div className="pointer-events-none absolute inset-0 -z-10">
                    <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-secondary/5" />
                    <div className="absolute -top-32 right-10 h-64 w-64 rounded-full bg-primary/20 blur-3xl" />
                    <div className="absolute bottom-0 left-10 h-72 w-72 rounded-full bg-secondary/20 blur-[120px]" />
                </div>

                <AppSidebar />
                <SidebarInset className="bg-background/20">
                    <AppNavbar />
                    <main className="flex-1 overflow-auto px-4 pb-10 pt-6 lg:px-10">
                        <div className="mx-auto flex w-full max-w-7xl flex-col gap-8">
                            <Outlet />
                        </div>
                    </main>
                </SidebarInset>
            </div>
        </SidebarProvider>
    );
}
