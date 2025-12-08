import type { FeatureScopeSelection, LicenseEntitlements, ScopeSelection, ScopePermissionValue } from '@/types/api';

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
