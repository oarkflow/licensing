import { LogOut, User, Search, Bell, Plus, ShieldCheck } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { SidebarTrigger } from '@/components/ui/sidebar';
import { Link, useNavigate } from 'react-router-dom';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ThemeToggle } from '@/components/ThemeToggle';

export function AppNavbar() {
    const { user, logout } = useAuth();
    const navigate = useNavigate();

    const handleLogout = async () => {
        await logout();
        navigate('/login');
    };

    return (
        <header className="sticky top-0 z-40 border-b bg-background/70 backdrop-blur-xl">
            <div className="flex h-20 items-center gap-4 px-4 lg:px-8">
                <SidebarTrigger className="rounded-2xl border bg-muted text-muted-foreground hover:bg-accent" />

                <div className="hidden flex-col md:flex">
                    <span className="text-[0.6rem] uppercase tracking-[0.4em] text-muted-foreground">License mesh</span>
                    <div className="flex items-center gap-2">
                        <p className="text-lg font-semibold">Mission Control</p>
                        <Badge variant="secondary">
                            Secure
                        </Badge>
                    </div>
                </div>

                <div className="flex flex-1 items-center gap-3">
                    <div className="relative hidden flex-1 items-center md:flex">
                        <Search className="pointer-events-none absolute left-4 h-4 w-4 text-muted-foreground" />
                        <Input
                            placeholder="Search licenses, products, clients"
                            className="h-11 w-full rounded-2xl border bg-muted pl-11 text-sm placeholder:text-muted-foreground"
                        />
                    </div>

                    <Button
                        variant="ghost"
                        size="icon"
                        className="rounded-2xl border bg-muted hover:bg-accent"
                    >
                        <Bell className="h-4 w-4" />
                        <span className="sr-only">Alerts</span>
                    </Button>

                    <Button
                        asChild
                        size="sm"
                        className="hidden rounded-2xl bg-primary px-4 text-primary-foreground shadow-lg shadow-primary/30 sm:inline-flex"
                    >
                        <Link to="/licenses/new">
                            <Plus className="mr-2 h-4 w-4" />
                            New License
                        </Link>
                    </Button>

                    <ThemeToggle />

                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm" className="gap-2 rounded-2xl border bg-muted hover:bg-accent">
                                <User className="h-4 w-4" />
                                <span className="hidden sm:inline">{user?.username || 'User'}</span>
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-56 rounded-2xl bg-card/90 text-foreground backdrop-blur">
                            <DropdownMenuLabel className="flex flex-col gap-1">
                                <span className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Operator</span>
                                <span className="text-base font-semibold">{user?.username || 'User'}</span>
                            </DropdownMenuLabel>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem asChild>
                                <Link to="/profile" className="cursor-pointer">
                                    <User className="mr-2 h-4 w-4" />
                                    Profile
                                </Link>
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onClick={handleLogout} className="cursor-pointer text-destructive">
                                <LogOut className="mr-2 h-4 w-4" />
                                Logout
                            </DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                </div>
            </div>
        </header>
    );
}
