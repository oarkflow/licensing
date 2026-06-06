import type { FeatureScopeSelection, LicenseEntitlements, ScopeSelection, ScopePermissionValue } from '@/types/api';

const WORD_BOUNDARY = /[-_]/g;
type ScopeGroup = { title: string; scopes: Array<{ selection: ScopeSelection }> };

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
                metadata: scope.metadata,
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

export function groupScopesForFeature(featureSlug: string, scopes?: ScopeSelection[]): ScopeGroup[] {
	if (!scopes || scopes.length === 0) return [];
	return [{ title: slugToLabel(featureSlug) || 'Scopes', scopes: scopes.map((selection) => ({ selection })) }];
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
