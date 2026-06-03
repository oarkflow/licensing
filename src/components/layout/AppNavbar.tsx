import { LogOut, User, Search, Plus } from 'lucide-react';
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
import { ThemeToggle } from '@/components/ThemeToggle';

export function AppNavbar() {
    const { user, logout } = useAuth();
    const navigate = useNavigate();

    const handleLogout = async () => {
        await logout();
        navigate('/login');
    };

    return (
        <header className="sticky top-0 z-40 border-b bg-background">
            <div className="flex h-12 items-center gap-3 px-3 lg:px-5">
                <SidebarTrigger className="h-8 w-8 rounded-md border bg-background text-muted-foreground hover:bg-muted" />

                <div className="hidden min-w-44 flex-col md:flex">
                    <span className="text-[0.65rem] font-medium uppercase text-muted-foreground">Licensing Admin</span>
                    <span className="text-xs text-muted-foreground">Operations console</span>
                </div>

                <div className="relative hidden flex-1 items-center md:flex">
                    <Search className="pointer-events-none absolute left-2.5 h-3.5 w-3.5 text-muted-foreground" />
                    <Input
                        placeholder="Search licenses, clients, products"
                        className="h-8 w-full border bg-background pl-8 text-xs"
                    />
                </div>

                <Button asChild size="sm" className="hidden sm:inline-flex">
                    <Link to="/licenses/new">
                        <Plus className="h-3.5 w-3.5" />
                        New License
                    </Link>
                </Button>

                <ThemeToggle />

                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm" className="gap-2">
                            <User className="h-3.5 w-3.5" />
                            <span className="hidden sm:inline">{user?.username || 'User'}</span>
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-52">
                        <DropdownMenuLabel className="flex flex-col gap-0.5">
                            <span className="text-[0.65rem] font-medium uppercase text-muted-foreground">Signed in as</span>
                            <span className="text-sm font-semibold">{user?.username || 'User'}</span>
                        </DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem asChild>
                            <Link to="/profile" className="cursor-pointer">
                                <User className="mr-2 h-3.5 w-3.5" />
                                Profile
                            </Link>
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onClick={handleLogout} className="cursor-pointer text-destructive">
                            <LogOut className="mr-2 h-3.5 w-3.5" />
                            Logout
                        </DropdownMenuItem>
                    </DropdownMenuContent>
                </DropdownMenu>
            </div>
        </header>
    );
}
