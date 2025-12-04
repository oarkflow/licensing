import { Link, useLocation } from 'react-router-dom';
import {
    LayoutDashboard,
    Key,
    Users,
    Package,
    Shield,
    Settings,
    ChevronDown,
    Sparkles,
    ShieldCheck,
    Terminal,
    Mail,
    FileText,
    Send,
} from 'lucide-react';
import {
    Sidebar,
    SidebarContent,
    SidebarGroup,
    SidebarGroupContent,
    SidebarGroupLabel,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    SidebarMenuSub,
    SidebarMenuSubItem,
    SidebarMenuSubButton,
} from '@/components/ui/sidebar';
import {
    Collapsible,
    CollapsibleContent,
    CollapsibleTrigger,
} from '@/components/ui/collapsible';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

const mainNavItems = [
    {
        title: 'Dashboard',
        url: '/',
        icon: LayoutDashboard,
    },
    {
        title: 'Licenses',
        url: '/licenses',
        icon: Key,
    },
    {
        title: 'Clients',
        url: '/clients',
        icon: Users,
    },
    {
        title: 'Products',
        url: '/products',
        icon: Package,
    },
];

const adminNavItems = [
    {
        title: 'Admin Users',
        url: '/admin/users',
    },
    {
        title: 'API Keys',
        url: '/admin/api-keys',
    },
];

const messagingNavItems = [
    {
        title: 'Providers',
        url: '/messaging/providers',
        icon: Mail,
    },
    {
        title: 'Templates',
        url: '/messaging/templates',
        icon: FileText,
    },
    {
        title: 'Compose',
        url: '/messaging/compose',
        icon: Send,
    },
];

const settingsNavItems = [
    {
        title: 'Profile',
        url: '/profile',
    },
];

export function AppSidebar() {
    const location = useLocation();

    const isActive = (url: string) => {
        if (url === '/') {
            return location.pathname === '/';
        }
        return location.pathname.startsWith(url);
    };

    return (
        <Sidebar className="bg-sidebar">
            <SidebarContent className="gap-6 p-4">
                <div className="glass-panel gradient-border rounded-3xl p-4 text-sm text-sidebar-foreground">
                    <Link to="/" className="flex items-center gap-3">
                        <div className="rounded-2xl bg-primary/20 p-2 text-primary">
                            <Key className="h-5 w-5" />
                        </div>
                        <div>
                            <p className="text-[0.65rem] uppercase tracking-[0.3em] text-sidebar-foreground/60">License Cloud</p>
                            <p className="text-lg font-semibold">Command Center</p>
                        </div>
                    </Link>
                    <p className="mt-3 text-[0.85rem] text-sidebar-foreground/70">
                        Issue, revoke and monitor every entitlement in one secure cockpit.
                    </p>
                    <div className="mt-4 flex flex-wrap gap-2">
                        <Badge variant="secondary" className="bg-white/10 text-xs uppercase tracking-wide text-white">
                            Live sync
                        </Badge>
                        <Badge variant="outline" className="border-white/20 text-xs text-white">
                            SOC2 ready
                        </Badge>
                    </div>
                </div>

                <SidebarGroup>
                    <SidebarGroupLabel className="text-[0.7rem] uppercase tracking-[0.4em] text-sidebar-foreground/60">
                        Monitor
                    </SidebarGroupLabel>
                    <SidebarGroupContent>
                        <SidebarMenu>
                            {mainNavItems.map((item) => (
                                <SidebarMenuItem key={item.title}>
                                    <SidebarMenuButton
                                        asChild
                                        isActive={isActive(item.url)}
                                        className="rounded-2xl border border-white/5 bg-white/5 text-sm font-medium text-sidebar-foreground/90 transition hover:border-white/20 hover:bg-white/10"
                                    >
                                        <Link to={item.url}>
                                            <item.icon className="h-4 w-4 text-primary" />
                                            <span>{item.title}</span>
                                        </Link>
                                    </SidebarMenuButton>
                                </SidebarMenuItem>
                            ))}
                        </SidebarMenu>
                    </SidebarGroupContent>
                </SidebarGroup>

                <SidebarGroup>
                    <Collapsible defaultOpen className="group/collapsible">
                        <SidebarGroupLabel asChild>
                            <CollapsibleTrigger className="flex w-full items-center justify-between rounded-2xl border border-white/5 bg-white/5 px-3 py-2 text-sm text-sidebar-foreground/80">
                                <div className="flex items-center gap-2">
                                    <Mail className="h-4 w-4 text-primary" />
                                    <span>Messaging</span>
                                </div>
                                <ChevronDown className="h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                            </CollapsibleTrigger>
                        </SidebarGroupLabel>
                        <CollapsibleContent>
                            <SidebarGroupContent className="mt-2">
                                <SidebarMenu>
                                    <SidebarMenuItem>
                                        <SidebarMenuSub>
                                            {messagingNavItems.map((item) => (
                                                <SidebarMenuSubItem key={item.title}>
                                                    <SidebarMenuSubButton
                                                        asChild
                                                        isActive={isActive(item.url)}
                                                        className="rounded-xl border border-white/5 bg-transparent text-sidebar-foreground/80 hover:border-white/20"
                                                    >
                                                        <Link to={item.url} className="flex items-center gap-2">
                                                            <item.icon className="h-3.5 w-3.5 text-primary" />
                                                            <span>{item.title}</span>
                                                        </Link>
                                                    </SidebarMenuSubButton>
                                                </SidebarMenuSubItem>
                                            ))}
                                        </SidebarMenuSub>
                                    </SidebarMenuItem>
                                </SidebarMenu>
                            </SidebarGroupContent>
                        </CollapsibleContent>
                    </Collapsible>
                </SidebarGroup>

                <SidebarGroup>
                    <Collapsible defaultOpen className="group/collapsible">
                        <SidebarGroupLabel asChild>
                            <CollapsibleTrigger className="flex w-full items-center justify-between rounded-2xl border border-white/5 bg-white/5 px-3 py-2 text-sm text-sidebar-foreground/80">
                                <div className="flex items-center gap-2">
                                    <Shield className="h-4 w-4 text-secondary" />
                                    <span>Admin</span>
                                </div>
                                <ChevronDown className="h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                            </CollapsibleTrigger>
                        </SidebarGroupLabel>
                        <CollapsibleContent>
                            <SidebarGroupContent className="mt-2">
                                <SidebarMenu>
                                    <SidebarMenuItem>
                                        <SidebarMenuSub>
                                            {adminNavItems.map((item) => (
                                                <SidebarMenuSubItem key={item.title}>
                                                    <SidebarMenuSubButton
                                                        asChild
                                                        isActive={isActive(item.url)}
                                                        className="rounded-xl border border-white/5 bg-transparent text-sidebar-foreground/80 hover:border-white/20"
                                                    >
                                                        <Link to={item.url}>{item.title}</Link>
                                                    </SidebarMenuSubButton>
                                                </SidebarMenuSubItem>
                                            ))}
                                        </SidebarMenuSub>
                                    </SidebarMenuItem>
                                </SidebarMenu>
                            </SidebarGroupContent>
                        </CollapsibleContent>
                    </Collapsible>
                </SidebarGroup>

                <SidebarGroup>
                    <Collapsible defaultOpen className="group/collapsible">
                        <SidebarGroupLabel asChild>
                            <CollapsibleTrigger className="flex w-full items-center justify-between rounded-2xl border border-white/5 bg-white/5 px-3 py-2 text-sm text-sidebar-foreground/80">
                                <div className="flex items-center gap-2">
                                    <Settings className="h-4 w-4 text-secondary" />
                                    <span>Settings</span>
                                </div>
                                <ChevronDown className="h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                            </CollapsibleTrigger>
                        </SidebarGroupLabel>
                        <CollapsibleContent>
                            <SidebarGroupContent className="mt-2">
                                <SidebarMenu>
                                    <SidebarMenuItem>
                                        <SidebarMenuSub>
                                            {settingsNavItems.map((item) => (
                                                <SidebarMenuSubItem key={item.title}>
                                                    <SidebarMenuSubButton
                                                        asChild
                                                        isActive={isActive(item.url)}
                                                        className="rounded-xl border border-white/5 bg-transparent text-sidebar-foreground/80 hover:border-white/20"
                                                    >
                                                        <Link to={item.url}>{item.title}</Link>
                                                    </SidebarMenuSubButton>
                                                </SidebarMenuSubItem>
                                            ))}
                                        </SidebarMenuSub>
                                    </SidebarMenuItem>
                                </SidebarMenu>
                            </SidebarGroupContent>
                        </CollapsibleContent>
                    </Collapsible>
                </SidebarGroup>

                <div className="mt-auto space-y-4 rounded-3xl border border-white/5 bg-gradient-to-b from-white/5 to-transparent p-4 text-xs text-sidebar-foreground/70">
                    <div className="flex items-center gap-3 rounded-2xl border border-white/5 bg-white/5 p-3">
                        <Sparkles className="h-4 w-4 text-primary" />
                        <div className="flex-1">
                            <p className="text-[0.65rem] uppercase tracking-[0.4em] text-sidebar-foreground/50">
                                License health
                            </p>
                            <p className="text-sm font-semibold text-white">98% trusted footprint</p>
                        </div>
                        <ShieldCheck className="h-4 w-4 text-emerald-400" />
                    </div>
                    <div className="space-y-2 text-sm">
                        <div className="flex items-center justify-between text-emerald-300">
                            <span className="status-dot">Active</span>
                            <span className="font-semibold">82%</span>
                        </div>
                        <div className="flex items-center justify-between text-amber-200">
                            <span className="status-dot">Expiring</span>
                            <span className="font-semibold">12%</span>
                        </div>
                        <div className="flex items-center justify-between text-rose-300">
                            <span className="status-dot">Revoked</span>
                            <span className="font-semibold">6%</span>
                        </div>
                    </div>
                    <Button
                        asChild
                        size="sm"
                        className="w-full rounded-xl bg-primary text-primary-foreground shadow-lg shadow-primary/30"
                    >
                        <Link to="/licenses/new" className="flex items-center justify-center">
                            <Terminal className="mr-2 h-4 w-4" />
                            Issue License
                        </Link>
                    </Button>
                </div>
            </SidebarContent>
        </Sidebar>
    );
}
