import { memo, useCallback, useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { ShieldCheck, Ban, RefreshCw, Search, X, ChevronDown, ChevronUp } from 'lucide-react';
import type { FeatureScopeSelection, ScopePermissionValue, ScopeSelection } from '@/types/api';
import { cliScopes, guiScopes, apiScopes, type CategorizedScopes, type ScopeDefinition } from '@/data/menuData';
import { slugToLabel } from '@/lib/entitlements';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';

type FeatureCategory = 'cli' | 'gui' | 'api' | 'other';

const categoryLabels: Record<FeatureCategory, string> = {
    cli: 'CLI',
    gui: 'GUI',
    api: 'API',
    other: 'Other',
};

const emptyCopy: Record<FeatureCategory, string> = {
    cli: 'No CLI features available for this license yet.',
    gui: 'No GUI features available for this license yet.',
    api: 'No API features available for this license yet.',
    other: 'No uncategorized features available yet.',
};

const catalogByFeatureSlug: Record<'cli' | 'gui' | 'api', CategorizedScopes> = {
    cli: cliScopes,
    gui: guiScopes,
    api: apiScopes,
};

interface ScopeGroupEntry {
    selection: ScopeSelection;
    definition?: ScopeDefinition;
}

interface ScopeGroup {
    title: string;
    scopes: ScopeGroupEntry[];
}

type CategorizedFeatureMap = Record<FeatureCategory, FeatureScopeSelection[]>;

const tabOrder: FeatureCategory[] = ['cli', 'gui', 'api'];

function featureCategoryFromSlug(slug: string): FeatureCategory {
    const normalized = slug?.toLowerCase();
    if (normalized === 'cli' || normalized === 'gui' || normalized === 'api') {
        return normalized;
    }
    return 'other';
}

function buildScopeGroups(featureSlug: string, scopes?: ScopeSelection[]): ScopeGroup[] {
    if (!scopes || scopes.length === 0) {
        return [];
    }

    const catalog = catalogByFeatureSlug[featureSlug as keyof typeof catalogByFeatureSlug];
    if (!catalog) {
        return [
            {
                title: 'Scopes',
                scopes: scopes.map((selection) => ({ selection })),
            },
        ];
    }

    const scopeMap = new Map(scopes.map((scope) => [scope.scope_slug, scope]));
    const consumed = new Set<string>();
    const groups: ScopeGroup[] = [];

    Object.entries(catalog).forEach(([groupTitle, definitions]) => {
        const matches: ScopeGroupEntry[] = [];
        definitions.forEach((definition) => {
            const selection = scopeMap.get(definition.slug);
            if (selection) {
                consumed.add(selection.scope_slug);
                matches.push({ selection, definition });
            }
        });
        if (matches.length > 0) {
            groups.push({ title: groupTitle, scopes: matches });
        }
    });

    const remainder = scopes.filter((scope) => !consumed.has(scope.scope_slug));
    if (remainder.length > 0) {
        groups.push({ title: 'Other', scopes: remainder.map((selection) => ({ selection })) });
    }

    return groups;
}

function buildCategorizedFeatures(selections: FeatureScopeSelection[]): CategorizedFeatureMap {
    return selections.reduce<CategorizedFeatureMap>(
        (acc, feature) => {
            const bucket = featureCategoryFromSlug(feature.feature_slug);
            acc[bucket].push(feature);
            return acc;
        },
        {
            cli: [],
            gui: [],
            api: [],
            other: [],
        }
    );
}

function getDefaultTab(categories: CategorizedFeatureMap): FeatureCategory {
    for (const key of tabOrder) {
        if (categories[key].length > 0) {
            return key;
        }
    }
    return categories.other.length > 0 ? 'other' : 'cli';
}

function filterGroupsAndScopes(groups: ScopeGroup[], searchTerm: string): ScopeGroup[] {
    if (!searchTerm.trim()) {
        return groups;
    }
    const query = searchTerm.toLowerCase();
    return groups
        .map((group) => {
            const groupMatches = group.title.toLowerCase().includes(query);
            if (groupMatches) {
                return group;
            }
            const filteredScopes = group.scopes.filter(({ selection, definition }) => {
                const scopeName = (definition?.name ?? slugToLabel(selection.scope_slug)).toLowerCase();
                const scopeSlug = selection.scope_slug.toLowerCase();
                const scopeDesc = definition?.description?.toLowerCase() ?? '';
                return scopeName.includes(query) || scopeSlug.includes(query) || scopeDesc.includes(query);
            });
            if (filteredScopes.length > 0) {
                return { ...group, scopes: filteredScopes };
            }
            return null;
        })
        .filter((g): g is ScopeGroup => g !== null);
}

interface FeatureScopeSelectorProps {
    selections: FeatureScopeSelection[];
    initialSelections?: FeatureScopeSelection[];
    onChange: (selections: FeatureScopeSelection[]) => void;
    loading?: boolean;
    disabled?: boolean;
    onReset?: () => void;
    title?: string;
    description?: string;
}

export const FeatureScopeSelector = memo(function FeatureScopeSelector({
    selections,
    initialSelections,
    onChange,
    loading,
    disabled,
    onReset,
    title = 'Feature Matrix',
    description = 'Fine-tune which capabilities this license should inherit.',
}: FeatureScopeSelectorProps) {
    const categorizedFeatures = useMemo(() => buildCategorizedFeatures(selections), [selections]);
    const [activeTab, setActiveTab] = useState<FeatureCategory>(() => getDefaultTab(categorizedFeatures));
    const [hasUserInteracted, setHasUserInteracted] = useState(false);
    const [searchTerms, setSearchTerms] = useState<Record<FeatureCategory, string>>({
        cli: '',
        gui: '',
        api: '',
        other: '',
    });
    const [summaryCollapsed, setSummaryCollapsed] = useState(false);

    const changesDetail = useMemo(() => {
        if (!initialSelections || initialSelections.length === 0) {
            return [];
        }

        const changes: Array<{
            featureSlug: string;
            featureName: string;
            scopeSlug: string;
            scopeName: string;
            oldPermission: string;
            newPermission: string;
        }> = [];

        const initialMap = new Map(
            initialSelections.flatMap((feature) =>
                (feature.scopes || []).map((scope) => [{
                    key: `${feature.feature_slug}:${scope.scope_slug}`,
                    featureSlug: feature.feature_slug,
                    scopeSlug: scope.scope_slug,
                    permission: scope.permission,
                }])
            ).flat().map(item => [item.key, item])
        );

        selections.forEach((feature) => {
            (feature.scopes || []).forEach((scope) => {
                const key = `${feature.feature_slug}:${scope.scope_slug}`;
                const initial = initialMap.get(key);
                if (initial && initial.permission !== scope.permission) {
                    changes.push({
                        featureSlug: feature.feature_slug,
                        featureName: slugToLabel(feature.feature_slug),
                        scopeSlug: scope.scope_slug,
                        scopeName: slugToLabel(scope.scope_slug),
                        oldPermission: initial.permission,
                        newPermission: scope.permission,
                    });
                }
            });
        });

        return changes;
    }, [selections, initialSelections]);

    useEffect(() => {
        if (hasUserInteracted) {
            return;
        }
        const nextDefault = getDefaultTab(categorizedFeatures);
        if (nextDefault !== activeTab) {
            setActiveTab(nextDefault);
        }
    }, [activeTab, categorizedFeatures, hasUserInteracted]);

    useEffect(() => {
        if (selections.length === 0) {
            setHasUserInteracted(false);
        }
    }, [selections.length]);

    const handleFeatureToggle = useCallback((slug: string, enabled: boolean) => {
        onChange(
            selections.map<FeatureScopeSelection>((feature) => {
                if (feature.feature_slug !== slug) {
                    return feature;
                }
                const scopes = (feature.scopes || []).map<ScopeSelection>((scope) => ({
                    ...scope,
                    permission: enabled
                        ? (scope.permission === 'limit' ? 'limit' : 'allow')
                        : 'deny',
                }));
                return { ...feature, enabled, scopes };
            })
        );
    }, [selections, onChange]);

    const handleScopeToggle = useCallback((featureSlug: string, scopeSlug: string, allow: boolean) => {
        onChange(
            selections.map((feature) => {
                if (feature.feature_slug !== featureSlug) {
                    return feature;
                }
                const scopes = (feature.scopes || []).map((scope) => {
                    if (scope.scope_slug !== scopeSlug) {
                        return scope;
                    }
                    const nextPermission: ScopePermissionValue = allow
                        ? scope.permission === 'limit'
                            ? 'limit'
                            : 'allow'
                        : 'deny';
                    return { ...scope, permission: nextPermission };
                });
                const anyAllowed = scopes.some((scope) => scope.permission !== 'deny');
                return { ...feature, enabled: anyAllowed, scopes };
            })
        );
    }, [selections, onChange]);

    const handleTabChange = useCallback((value: string) => {
        setHasUserInteracted(true);
        setActiveTab(value as FeatureCategory);
    }, []);

    const renderFeatureGrid = useCallback((featuresForTab: FeatureScopeSelection[], tab: FeatureCategory) => {
        const searchTerm = searchTerms[tab];

        if (featuresForTab.length === 0) {
            return (
                <Card className="rounded-md border-dashed border-border bg-muted">
                    <CardContent className="py-10 text-center text-sm text-muted-foreground">
                        {emptyCopy[tab]}
                    </CardContent>
                </Card>
            );
        }

        return (
            <div className="grid gap-4">
                {featuresForTab.map((feature) => {
                    const allGroupedScopes = buildScopeGroups(feature.feature_slug, feature.scopes);
                    const groupedScopes = filterGroupsAndScopes(allGroupedScopes, searchTerm);
                    return (
                        <Card key={feature.feature_slug} className="rounded-md border bg-card shadow-none">
                            <CardContent className="space-y-4 p-5">
                                <div className="flex items-center gap-2">
                                    <Badge variant={feature.enabled ? 'default' : 'secondary'} className="rounded-full px-3 py-1 text-xs">
                                        {feature.enabled ? 'Allowed' : 'Denied'}
                                    </Badge>
                                    <span className="font-medium tracking-tight">{slugToLabel(feature.feature_slug)}</span>
                                </div>
                                <div className="flex flex-wrap gap-2">
                                    <Button
                                        type="button"
                                        variant={feature.enabled ? 'default' : 'outline'}
                                        size="sm"
                                        className="rounded-md"
                                        onClick={() => handleFeatureToggle(feature.feature_slug, true)}
                                        disabled={disabled}
                                    >
                                        <ShieldCheck className="mr-2 h-4 w-4" /> Allow All
                                    </Button>
                                    <Button
                                        type="button"
                                        variant={feature.enabled ? 'outline' : 'destructive'}
                                        size="sm"
                                        className="rounded-md"
                                        onClick={() => handleFeatureToggle(feature.feature_slug, false)}
                                        disabled={disabled}
                                    >
                                        <Ban className="mr-2 h-4 w-4" /> Deny All
                                    </Button>
                                </div>
                                {groupedScopes.length === 0 ? (
                                    <p className="text-sm italic text-muted-foreground">No scopes defined for this feature yet.</p>
                                ) : (
                                    <div className="grid gap-3">
                                        {groupedScopes.map((group) => (
                                            <div
                                                key={`${feature.feature_slug}-${group.title}`}
                                                className="space-y-2 border-y border-border bg-muted px-3 py-3"
                                            >
                                                <div className="flex items-center justify-between text-xs uppercase tracking-[0.3em] text-muted-foreground">
                                                    <span>{group.title}</span>
                                                    <Badge variant="outline" className="rounded-full px-2 py-0.5 text-[10px]">
                                                        {group.scopes.length}
                                                    </Badge>
                                                </div>
                                                <div className="grid gap-2 lg:grid-cols-2 2xl:grid-cols-3">
                                                    {group.scopes.map(({ selection, definition }) => (
                                                        <div
                                                            key={`${feature.feature_slug}-${selection.scope_slug}`}
                                                            className="flex min-w-0 items-center justify-between gap-3 border-y border-border bg-background px-3 py-2"
                                                        >
                                                            <div className="space-y-1">
                                                                <p className="text-sm font-medium">
                                                                    {definition?.name ?? slugToLabel(selection.scope_slug)}
                                                                </p>
                                                                {definition?.description ? (
                                                                    <p className="text-xs text-muted-foreground">{definition.description}</p>
                                                                ) : null}
                                                                <div className="flex flex-wrap gap-2">
                                                                    {selection.permission === 'limit' && selection.limit ? (
                                                                        <Badge variant="outline" className="text-[10px]">
                                                                            Limit {selection.limit}
                                                                        </Badge>
                                                                    ) : null}
                                                                    {definition?.minPlan ? (
                                                                        <Badge variant="outline" className="text-[10px] uppercase tracking-tight">
                                                                            Min {definition.minPlan}
                                                                        </Badge>
                                                                    ) : null}
                                                                </div>
                                                            </div>
                                                            <Switch
                                                                checked={selection.permission !== 'deny'}
                                                                onCheckedChange={(checked) =>
                                                                    handleScopeToggle(feature.feature_slug, selection.scope_slug, checked)
                                                                }
                                                                disabled={disabled}
                                                            />
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </CardContent>
                        </Card>
                    );
                })}
            </div>
        );
    }, [searchTerms, handleFeatureToggle, handleScopeToggle, disabled]);

    if (loading) {
        return <Skeleton className="h-48 w-full rounded-md" />;
    }

    const tabsToRender: FeatureCategory[] = [...tabOrder, 'other'];

    const getFeaturesForTab = (tab: FeatureCategory) => categorizedFeatures[tab];

    if (!loading && selections.length === 0) {
        return (
            <Card className="rounded-md border-dashed bg-muted">
                <CardContent className="flex flex-col items-center justify-center gap-3 py-10 text-center">
                    <ShieldCheck className="h-10 w-10 text-primary" />
                    <p className="text-sm text-muted-foreground">No feature scopes available for this plan yet.</p>
                </CardContent>
            </Card>
        );
    }

    return (
        <div className="space-y-4 border-y border-border bg-background py-4">
            <div className="flex flex-wrap items-center gap-3">
                <div>
                    <p className="text-xs uppercase tracking-[0.4em] text-muted-foreground">{title}</p>
                    <p className="text-sm text-muted-foreground">{description}</p>
                </div>
                {onReset && (
                    <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="ml-auto rounded-md"
                        onClick={onReset}
                        disabled={disabled}
                    >
                        <RefreshCw className="mr-2 h-4 w-4" /> Reset to plan defaults
                    </Button>
                )}
            </div>
            <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-4">
                <TabsList className="flex flex-wrap gap-2 rounded-md bg-muted p-1">
                    {tabsToRender.map((tab) => (
                        <TabsTrigger
                            key={tab}
                            value={tab}
                            className="rounded-md px-4 py-2 text-xs font-semibold uppercase tracking-[0.3em]"
                        >
                            <span>{categoryLabels[tab]}</span>
                            <span className="ml-2 rounded-full bg-background/60 px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
                                {getFeaturesForTab(tab).length}
                            </span>
                        </TabsTrigger>
                    ))}
                </TabsList>
                {tabsToRender.map((tab) => (
                    <TabsContent key={tab} value={tab} className="mt-0 space-y-4">
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                            <Input
                                placeholder={`Search ${categoryLabels[tab]} groups, features, or scopes...`}
                                value={searchTerms[tab]}
                                onChange={(e) => setSearchTerms((prev) => ({ ...prev, [tab]: e.target.value }))}
                                className="rounded-md pl-9 pr-4"
                            />
                        </div>
                        {renderFeatureGrid(getFeaturesForTab(tab), tab)}
                    </TabsContent>
                ))}
            </Tabs>
            {changesDetail.length > 0 && createPortal(
                <div className="fixed bottom-6 right-6 z-[9999] max-w-md">
                    <Card className="rounded-md border-primary bg-background shadow-2xl ">
                        <CardContent className="p-0">
                            <div className="flex items-center justify-between border-b border-border px-4 py-3">
                                <div className="flex items-center gap-2">
                                    <Badge variant="default" className="rounded-full px-3 py-1">
                                        {changesDetail.length} {changesDetail.length === 1 ? 'change' : 'changes'}
                                    </Badge>
                                    <span className="text-sm font-medium">Modifications</span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-7 w-7 rounded-full"
                                        onClick={() => setSummaryCollapsed(!summaryCollapsed)}
                                    >
                                        {summaryCollapsed ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
                                    </Button>
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-7 w-7 rounded-full"
                                        onClick={() => onReset?.()}
                                    >
                                        <X className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>
                            {!summaryCollapsed && (
                                <div className="max-h-[60vh] space-y-2 overflow-y-auto p-4 scrollbar-thin scrollbar-thumb-muted-foreground/30 scrollbar-track-transparent">
                                    {changesDetail.map((change, idx) => {
                                        const isAllowed = change.newPermission !== 'deny';
                                        return (
                                            <div
                                                key={`${change.featureSlug}-${change.scopeSlug}-${idx}`}
                                                className="flex items-start gap-3 rounded-md border border-border bg-muted p-3 text-sm"
                                            >
                                                <div className="mt-0.5">
                                                    {isAllowed ? (
                                                        <ShieldCheck className="h-4 w-4 text-green-600 dark:text-green-400" />
                                                    ) : (
                                                        <Ban className="h-4 w-4 text-destructive" />
                                                    )}
                                                </div>
                                                <div className="flex-1 space-y-1">
                                                    <div className="font-medium">
                                                        {change.featureName} → {change.scopeName}
                                                    </div>
                                                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                                        <Badge variant="outline" className="text-[10px] uppercase">
                                                            {change.oldPermission}
                                                        </Badge>
                                                        <span>→</span>
                                                        <Badge
                                                            variant={isAllowed ? 'default' : 'destructive'}
                                                            className="text-[10px] uppercase"
                                                        >
                                                            {change.newPermission}
                                                        </Badge>
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </div>,
                document.body
            )}
        </div>
    );
});
