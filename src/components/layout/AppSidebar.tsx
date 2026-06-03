import { Link, useLocation } from 'react-router-dom';
import type { ElementType, ReactNode } from 'react';
import {
    LayoutDashboard,
    Key,
    Users,
    Package,
    Shield,
    Settings,
    ChevronDown,
    Mail,
    FileText,
    Send,
    Tags,
    CreditCard,
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
import { Button } from '@/components/ui/button';

const overviewItems = [
    { title: 'Dashboard', url: '/', icon: LayoutDashboard },
];

const licensingItems = [
    { title: 'Licenses', url: '/licenses', icon: Key },
    { title: 'Clients', url: '/clients', icon: Users },
];

const catalogItems = [
    { title: 'Products', url: '/products', icon: Package },
    { title: 'Coupons', url: '/admin/coupons', icon: Tags },
];

const messagingItems = [
    { title: 'Providers', url: '/messaging/providers', icon: Mail },
    { title: 'Templates', url: '/messaging/templates', icon: FileText },
    { title: 'Compose', url: '/messaging/compose', icon: Send },
];

const administrationItems = [
    { title: 'Admin Users', url: '/admin/users' },
    { title: 'API Keys', url: '/admin/api-keys' },
    { title: 'Signing Keys', url: '/admin/signing-keys' },
];

const accountItems = [
    { title: 'Profile', url: '/profile' },
];

function NavGroup({
    label,
    icon: Icon,
    children,
}: {
    label: string;
    icon?: ElementType;
    children: ReactNode;
}) {
    return (
        <SidebarGroup>
            <Collapsible defaultOpen className="group/collapsible">
                <SidebarGroupLabel asChild>
                    <CollapsibleTrigger className="flex w-full items-center justify-between px-2 py-1.5 text-[0.65rem] font-medium uppercase text-sidebar-foreground/65 hover:bg-sidebar-accent">
                        <span className="flex items-center gap-2">
                            {Icon && <Icon className="h-3.5 w-3.5" />}
                            {label}
                        </span>
                        <ChevronDown className="h-3 w-3 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                    </CollapsibleTrigger>
                </SidebarGroupLabel>
                <CollapsibleContent>
                    <SidebarGroupContent>{children}</SidebarGroupContent>
                </CollapsibleContent>
            </Collapsible>
        </SidebarGroup>
    );
}

export function AppSidebar() {
    const location = useLocation();

    const isActive = (url: string) => {
        if (url === '/') {
            return location.pathname === '/';
        }
        return location.pathname.startsWith(url);
    };

    return (
        <Sidebar className="border-r bg-sidebar">
            <SidebarContent className="gap-1 p-2">
                <Link to="/" className="mb-2 flex items-center gap-2 border-b px-2 pb-3 pt-1">
                    <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
                        <Key className="h-3.5 w-3.5" />
                    </div>
                    <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-sidebar-foreground">Licensing Admin</p>
                        <p className="truncate text-[0.68rem] text-sidebar-foreground/65">Operations</p>
                    </div>
                </Link>

                <SidebarGroup>
                    <SidebarGroupLabel className="px-2 py-1 text-[0.65rem] font-medium uppercase text-sidebar-foreground/65">
                        Overview
                    </SidebarGroupLabel>
                    <SidebarGroupContent>
                        <SidebarMenu className="gap-0.5">
                            {overviewItems.map((item) => (
                                <SidebarMenuItem key={item.title}>
                                    <SidebarMenuButton asChild isActive={isActive(item.url)} className="h-8 px-2 text-xs">
                                        <Link to={item.url}>
                                            <item.icon className="h-3.5 w-3.5" />
                                            <span>{item.title}</span>
                                        </Link>
                                    </SidebarMenuButton>
                                </SidebarMenuItem>
                            ))}
                        </SidebarMenu>
                    </SidebarGroupContent>
                </SidebarGroup>

                <SidebarGroup>
                    <SidebarGroupLabel className="px-2 py-1 text-[0.65rem] font-medium uppercase text-sidebar-foreground/65">
                        Licensing
                    </SidebarGroupLabel>
                    <SidebarGroupContent>
                        <SidebarMenu className="gap-0.5">
                            {licensingItems.map((item) => (
                                <SidebarMenuItem key={item.title}>
                                    <SidebarMenuButton asChild isActive={isActive(item.url)} className="h-8 px-2 text-xs">
                                        <Link to={item.url}>
                                            <item.icon className="h-3.5 w-3.5" />
                                            <span>{item.title}</span>
                                        </Link>
                                    </SidebarMenuButton>
                                </SidebarMenuItem>
                            ))}
                        </SidebarMenu>
                    </SidebarGroupContent>
                </SidebarGroup>

                <SidebarGroup>
                    <SidebarGroupLabel className="px-2 py-1 text-[0.65rem] font-medium uppercase text-sidebar-foreground/65">
                        Catalog
                    </SidebarGroupLabel>
                    <SidebarGroupContent>
                        <SidebarMenu className="gap-0.5">
                            {catalogItems.map((item) => (
                                <SidebarMenuItem key={item.title}>
                                    <SidebarMenuButton asChild isActive={isActive(item.url)} className="h-8 px-2 text-xs">
                                        <Link to={item.url}>
                                            <item.icon className="h-3.5 w-3.5" />
                                            <span>{item.title}</span>
                                        </Link>
                                    </SidebarMenuButton>
                                </SidebarMenuItem>
                            ))}
                        </SidebarMenu>
                    </SidebarGroupContent>
                </SidebarGroup>

                <NavGroup label="Messaging" icon={Mail}>
                    <SidebarMenu className="gap-0.5">
                        <SidebarMenuItem>
                            <SidebarMenuSub>
                                {messagingItems.map((item) => (
                                    <SidebarMenuSubItem key={item.title}>
                                        <SidebarMenuSubButton asChild isActive={isActive(item.url)} className="h-7 px-2 text-xs">
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
                </NavGroup>

                <NavGroup label="Administration" icon={Shield}>
                    <SidebarMenu className="gap-0.5">
                        <SidebarMenuItem>
                            <SidebarMenuSub>
                                {administrationItems.map((item) => (
                                    <SidebarMenuSubItem key={item.title}>
                                        <SidebarMenuSubButton asChild isActive={isActive(item.url)} className="h-7 px-2 text-xs">
                                            <Link to={item.url}>{item.title}</Link>
                                        </SidebarMenuSubButton>
                                    </SidebarMenuSubItem>
                                ))}
                            </SidebarMenuSub>
                        </SidebarMenuItem>
                    </SidebarMenu>
                </NavGroup>

                <NavGroup label="Account" icon={Settings}>
                    <SidebarMenu className="gap-0.5">
                        <SidebarMenuItem>
                            <SidebarMenuSub>
                                {accountItems.map((item) => (
                                    <SidebarMenuSubItem key={item.title}>
                                        <SidebarMenuSubButton asChild isActive={isActive(item.url)} className="h-7 px-2 text-xs">
                                            <Link to={item.url}>{item.title}</Link>
                                        </SidebarMenuSubButton>
                                    </SidebarMenuSubItem>
                                ))}
                            </SidebarMenuSub>
                        </SidebarMenuItem>
                    </SidebarMenu>
                </NavGroup>

                <div className="mt-auto border-t pt-2">
                    <Button asChild size="sm" className="w-full justify-start">
                        <Link to="/licenses/new">
                            <CreditCard className="h-3.5 w-3.5" />
                            Issue License
                        </Link>
                    </Button>
                </div>
            </SidebarContent>
        </Sidebar>
    );
}
