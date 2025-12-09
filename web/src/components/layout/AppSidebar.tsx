import { Link, useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
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
    Building2,
    Fingerprint,
    Bot,
    FileLock,
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
import api from '@/services/api';
import type { DashboardStats } from '@/types/api';

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

const crmNavItems = [
    {
        title: 'Overview',
        url: '/crm',
        icon: Shield,
    },
    {
        title: 'Provision',
        url: '/crm/tenants/new',
        icon: Building2,
    },
    {
        title: 'Entitlements',
        url: '/crm/entitlements',
        icon: Key,
    },
    {
        title: 'Devices',
        url: '/crm/devices',
        icon: Fingerprint,
    },
    {
        title: 'Service Accounts',
        url: '/crm/service-accounts',
        icon: Bot,
    },
    {
        title: 'Offline Bundles',
        url: '/crm/offline-bundles',
        icon: FileLock,
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

    const { data: statsResponse } = useQuery({
        queryKey: ['dashboard-stats'],
        queryFn: () => api.getDashboardStats(),
    });

    const stats: DashboardStats = statsResponse?.data || {
        total_licenses: 0,
        active_licenses: 0,
        revoked_licenses: 0,
        expired_licenses: 0,
        total_clients: 0,
        active_clients: 0,
        banned_clients: 0,
        total_products: 0,
        total_admins: 0,
        recent_licenses: [],
    };

    const isActive = (url: string) => {
        if (url === '/') {
            return location.pathname === '/';
        }
        return location.pathname.startsWith(url);
    };

    return (
        <Sidebar className="bg-sidebar">
            <SidebarContent className="gap-0 p-3">
                <div className="rounded-2xl border bg-gradient-to-br from-primary/5 to-transparent p-3 mb-2">
                    <Link to="/" className="flex items-center gap-2">
                        <div className="rounded-lg bg-primary/20 p-1.5 text-primary">
                            <Key className="h-4 w-4" />
                        </div>
                        <div className="min-w-0 flex-1">
                            <p className="text-[0.6rem] font-medium uppercase tracking-wider text-sidebar-foreground/70">License Cloud</p>
                            <p className="text-sm font-semibold text-sidebar-foreground truncate">Command Center</p>
                        </div>
                    </Link>
                    <div className="mt-2 flex items-center gap-1.5">
                        <Badge variant="secondary" className="bg-sidebar-accent/50 text-[0.6rem] px-1.5 py-0.5">
                            Live
                        </Badge>
                        <Badge variant="outline" className="border-sidebar-border/50 text-[0.6rem] px-1.5 py-0.5">
                            SOC2
                        </Badge>
                    </div>
                </div>

                <SidebarGroup>
                    <SidebarGroupLabel className="text-[0.65rem] uppercase tracking-wider text-sidebar-foreground/60 px-2 py-1">
                        Monitor
                    </SidebarGroupLabel>
                    <SidebarGroupContent className="mt-1">
                        <SidebarMenu className='gap-0.5'>
                            {mainNavItems.map((item) => (
                                <SidebarMenuItem key={item.title}>
                                    <SidebarMenuButton
                                        asChild
                                        isActive={isActive(item.url)}
                                        className="rounded-xl text-sm h-8 px-3"
                                    >
                                        <Link to={item.url}>
                                            <item.icon className="h-4 w-4" />
                                            <span className="text-sm">{item.title}</span>
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
                            <CollapsibleTrigger className="flex w-full items-center justify-between rounded-lg px-2 py-1.5 text-[0.65rem] hover:bg-sidebar-accent/50 transition-colors">
                                <div className="flex items-center gap-2">
                                    <Building2 className="h-3.5 w-3.5" />
                                    <span>Tenant Ops</span>
                                </div>
                                <ChevronDown className="h-3 w-3 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                            </CollapsibleTrigger>
                        </SidebarGroupLabel>
                        <CollapsibleContent>
                            <SidebarGroupContent>
                                <SidebarMenu className="space-y-0.5">
                                    <SidebarMenuItem>
                                        <SidebarMenuSub>
                                            {crmNavItems.map((item) => (
                                                <SidebarMenuSubItem key={item.title}>
                                                    <SidebarMenuSubButton
                                                        asChild
                                                        isActive={isActive(item.url)}
                                                        className="rounded-lg h-7 px-2 text-xs"
                                                    >
                                                        <Link to={item.url} className="flex items-center gap-2">
                                                            <item.icon className="h-3 w-3" />
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
                            <CollapsibleTrigger className="flex w-full items-center justify-between rounded-lg px-2 py-1.5 text-[0.65rem] hover:bg-sidebar-accent/50 transition-colors">
                                <div className="flex items-center gap-2">
                                    <Mail className="h-3.5 w-3.5" />
                                    <span>Messaging</span>
                                </div>
                                <ChevronDown className="h-3 w-3 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                            </CollapsibleTrigger>
                        </SidebarGroupLabel>
                        <CollapsibleContent>
                            <SidebarGroupContent>
                                <SidebarMenu className="space-y-0.5">
                                    <SidebarMenuItem>
                                        <SidebarMenuSub>
                                            {messagingNavItems.map((item) => (
                                                <SidebarMenuSubItem key={item.title}>
                                                    <SidebarMenuSubButton
                                                        asChild
                                                        isActive={isActive(item.url)}
                                                        className="rounded-lg h-7 px-2 text-xs"
                                                    >
                                                        <Link to={item.url} className="flex items-center gap-2">
                                                            <item.icon className="h-3 w-3" />
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
                            <CollapsibleTrigger className="flex w-full items-center justify-between rounded-lg px-2 py-1.5 text-[0.65rem] hover:bg-sidebar-accent/50 transition-colors">
                                <div className="flex items-center gap-2">
                                    <Shield className="h-3.5 w-3.5" />
                                    <span>Admin</span>
                                </div>
                                <ChevronDown className="h-3 w-3 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                            </CollapsibleTrigger>
                        </SidebarGroupLabel>
                        <CollapsibleContent>
                            <SidebarGroupContent>
                                <SidebarMenu className="space-y-0.5">
                                    <SidebarMenuItem>
                                        <SidebarMenuSub>
                                            {adminNavItems.map((item) => (
                                                <SidebarMenuSubItem key={item.title}>
                                                    <SidebarMenuSubButton
                                                        asChild
                                                        isActive={isActive(item.url)}
                                                        className="rounded-lg h-7 px-2 text-xs"
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
                            <CollapsibleTrigger className="flex w-full items-center justify-between rounded-lg px-2 py-1.5 text-[0.65rem] hover:bg-sidebar-accent/50 transition-colors">
                                <div className="flex items-center gap-2">
                                    <Settings className="h-3.5 w-3.5" />
                                    <span>Settings</span>
                                </div>
                                <ChevronDown className="h-3 w-3 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                            </CollapsibleTrigger>
                        </SidebarGroupLabel>
                        <CollapsibleContent>
                            <SidebarGroupContent>
                                <SidebarMenu className="space-y-0.5">
                                    <SidebarMenuItem>
                                        <SidebarMenuSub>
                                            {settingsNavItems.map((item) => (
                                                <SidebarMenuSubItem key={item.title}>
                                                    <SidebarMenuSubButton
                                                        asChild
                                                        isActive={isActive(item.url)}
                                                        className="rounded-lg h-7 px-2 text-xs"
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

                <div className="mt-auto space-y-3">
                    <div className="rounded-xl border bg-gradient-to-r from-primary/5 to-transparent p-3">
                        <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-1.5">
                                <Sparkles className="h-3.5 w-3.5 text-primary" />
                                <span className="text-[0.6rem] font-medium uppercase tracking-wider text-sidebar-foreground/70">System Health</span>
                            </div>
                            <ShieldCheck className="h-3.5 w-3.5 text-primary" />
                        </div>
                        <div className="grid grid-cols-3 gap-2 text-center">
                            <div className="rounded-lg bg-primary/10 p-1.5">
                                <div className="text-[0.6rem] text-primary font-medium">Active</div>
                                <div className="text-xs font-bold text-primary">
                                    {stats.total_licenses > 0 ? Math.round((stats.active_licenses / stats.total_licenses) * 100) : 0}%
                                </div>
                            </div>
                            <div className="rounded-lg bg-secondary/10 p-1.5">
                                <div className="text-[0.6rem] text-secondary font-medium">Expiring</div>
                                <div className="text-xs font-bold text-secondary">
                                    {stats.total_licenses > 0 ? Math.round((stats.expired_licenses / stats.total_licenses) * 100) : 0}%
                                </div>
                            </div>
                            <div className="rounded-lg bg-destructive/10 p-1.5">
                                <div className="text-[0.6rem] text-destructive font-medium">Revoked</div>
                                <div className="text-xs font-bold text-destructive">
                                    {stats.total_licenses > 0 ? Math.round((stats.revoked_licenses / stats.total_licenses) * 100) : 0}%
                                </div>
                            </div>
                        </div>
                    </div>
                    <Button
                        asChild
                        size="sm"
                        className="w-full rounded-lg bg-primary text-primary-foreground shadow-md h-8 text-xs"
                    >
                        <Link to="/licenses/new" className="flex items-center justify-center gap-1.5">
                            <Terminal className="h-3.5 w-3.5" />
                            <span>Issue License</span>
                        </Link>
                    </Button>
                </div>
            </SidebarContent>
        </Sidebar>
    );
}
