import type { FeatureScopeSelection, LicenseEntitlements, ScopeSelection, ScopePermissionValue } from '@/types/api';
import { cliScopes, guiScopes, apiScopes, type CategorizedScopes, type ScopeDefinition } from '@/data/menuData';

const WORD_BOUNDARY = /[-_]/g;

export function slugToLabel(slug: string): string {
    if (!slug) return '';
    return slug
        .replace(WORD_BOUNDARY, ' ')
        .split(' ')
        .filter(Boolean)
        .map(segment => segment.length ? segment[0].toUpperCase() + segment.slice(1) : segment)
        .join(' ');
}

export function entitlementsToSelections(entitlements?: LicenseEntitlements | null): FeatureScopeSelection[] {
    if (!entitlements?.features) {
        return [];
    }
    return Object.entries(entitlements.features).map(([slug, feature]) => {
        const scopes: ScopeSelection[] = feature.scopes
            ? Object.entries(feature.scopes).map(([scopeSlug, scope]) => ({
                scope_id: scope.scope_id,
                scope_slug: scopeSlug,
                permission: normalizePermission(scope.permission),
                limit: scope.limit,
            }))
            : [];
        return {
            feature_id: feature.feature_id,
            feature_slug: slug,
            enabled: feature.enabled ?? true,
            scopes,
        };
    });
}

export function normalizePermission(permission?: ScopePermissionValue): ScopePermissionValue {
    if (permission === 'deny' || permission === 'limit') {
        return permission;
    }
    return 'allow';
}

// Build grouped scopes for a feature using the catalog (cli/gui/api)
export function groupScopesForFeature(featureSlug: string, scopes?: ScopeSelection[]) {
    if (!scopes || scopes.length === 0) return [] as { title: string; scopes: Array<{ selection: ScopeSelection; definition?: ScopeDefinition }> }[];
    const catalogMap: Record<string, CategorizedScopes | undefined> = {
        cli: cliScopes,
        gui: guiScopes,
        api: apiScopes,
    };
    const cat = featureSlug?.toLowerCase();
    const catalog = (cat === 'cli' || cat === 'gui' || cat === 'api') ? catalogMap[cat] : undefined;
    if (!catalog) {
        return [
            {
                title: 'Scopes',
                scopes: scopes.map((selection) => ({ selection })),
            },
        ];
    }
    const scopeMap = new Map(scopes.map((s) => [s.scope_slug, s]));
    const consumed = new Set<string>();
    const groups: { title: string; scopes: Array<{ selection: ScopeSelection; definition?: ScopeDefinition }> }[] = [];
    Object.entries(catalog).forEach(([groupTitle, defs]) => {
        const matches: Array<{ selection: ScopeSelection; definition?: ScopeDefinition }> = [];
        defs.forEach((def) => {
            const sel = scopeMap.get(def.slug);
            if (sel) {
                consumed.add(sel.scope_slug);
                matches.push({ selection: sel, definition: def });
            }
        });
        if (matches.length > 0) {
            groups.push({ title: groupTitle, scopes: matches });
        }
    });
    const remainder = scopes.filter((s) => !consumed.has(s.scope_slug));
    if (remainder.length > 0) {
        groups.push({ title: 'Other', scopes: remainder.map((s) => ({ selection: s })) });
    }
    return groups;
}

// Categorize selections into cli/gui/api/other
export function categorizeSelections(selections: FeatureScopeSelection[]) {
    const result: Record<'cli' | 'gui' | 'api' | 'other', FeatureScopeSelection[]> = { cli: [], gui: [], api: [], other: [] };
    selections.forEach((f) => {
        const cat = (f.feature_slug || '').toLowerCase();
        if (cat === 'cli' || cat === 'gui' || cat === 'api') {
            result[cat].push(f);
        } else {
            result.other.push(f);
        }
    });
    return result;
}
