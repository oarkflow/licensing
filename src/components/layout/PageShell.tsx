import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Inbox } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

export function PageHeader({
    eyebrow,
    title,
    description,
    backTo,
    backLabel = 'Back',
    actions,
}: {
    eyebrow?: string;
    title: string;
    description?: string;
    backTo?: string;
    backLabel?: string;
    actions?: ReactNode;
}) {
    return (
        <div className="flex flex-wrap items-end justify-between gap-3 border-b pb-3">
            <div className="min-w-0 space-y-1">
                {backTo && (
                    <Button asChild variant="ghost" size="sm" className="-ml-2 h-7">
                        <Link to={backTo}>
                            <ArrowLeft className="h-3.5 w-3.5" />
                            {backLabel}
                        </Link>
                    </Button>
                )}
                {eyebrow && (
                    <p className="text-[0.68rem] font-semibold uppercase text-muted-foreground">
                        {eyebrow}
                    </p>
                )}
                <h1 className="truncate text-xl font-semibold text-foreground">{title}</h1>
                {description && (
                    <p className="max-w-3xl text-xs text-muted-foreground">{description}</p>
                )}
            </div>
            {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
    );
}

export function Toolbar({ children, className }: { children: ReactNode; className?: string }) {
    return (
        <div className={cn('flex flex-wrap items-center gap-2 border-y bg-background py-2', className)}>
            {children}
        </div>
    );
}

export function DataPanel({
    children,
    className,
}: {
    children: ReactNode;
    className?: string;
}) {
    return <section className={cn('border-y bg-background', className)}>{children}</section>;
}

export function MetricTile({
    label,
    value,
    description,
    tone = 'default',
}: {
    label: string;
    value: ReactNode;
    description?: ReactNode;
    tone?: 'default' | 'primary' | 'secondary' | 'accent' | 'danger';
}) {
    const toneClass = {
        default: 'text-foreground',
        primary: 'text-primary',
        secondary: 'text-secondary',
        accent: 'text-accent',
        danger: 'text-destructive',
    }[tone];

    return (
        <div className="border-l px-3 py-2 first:border-l-0">
            <p className="text-[0.68rem] font-medium uppercase text-muted-foreground">{label}</p>
            <div className={cn('mt-1 text-lg font-semibold tabular-nums', toneClass)}>{value}</div>
            {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
        </div>
    );
}

export function EmptyState({
    title,
    description,
    action,
}: {
    title: string;
    description?: string;
    action?: ReactNode;
}) {
    return (
        <div className="flex flex-col items-center justify-center border-y border-dashed bg-muted px-4 py-8 text-center">
            <Inbox className="h-8 w-8 text-muted-foreground" />
            <h3 className="mt-3 text-sm font-semibold">{title}</h3>
            {description && <p className="mt-1 max-w-md text-xs text-muted-foreground">{description}</p>}
            {action && <div className="mt-3">{action}</div>}
        </div>
    );
}

export function FormPanel({
    title,
    description,
    children,
    className,
}: {
    title: string;
    description?: string;
    children: ReactNode;
    className?: string;
}) {
    return (
        <section className={cn('border-y bg-background', className)}>
            <div className="border-b px-4 py-3">
                <h2 className="text-sm font-semibold">{title}</h2>
                {description && <p className="mt-1 text-xs text-muted-foreground">{description}</p>}
            </div>
            <div className="p-4">{children}</div>
        </section>
    );
}

export function ActionFooter({ children }: { children: ReactNode }) {
    return (
        <div className="sticky bottom-0 z-10 mt-4 flex justify-end gap-2 border-t bg-background px-4 py-3 ">
            {children}
        </div>
    );
}
