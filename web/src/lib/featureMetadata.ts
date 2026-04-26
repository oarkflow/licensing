export type MetadataMap = Record<string, string>;

export interface UsageSummary {
    name: string;
    limit?: number;
    windowSeconds?: number;
    current?: number;
    resetAt?: string;
    strategy?: string;
    metadata: MetadataMap;
}

export interface MetadataSummary {
    flags: Record<string, boolean>;
    settings: MetadataMap;
    limits: Record<string, number>;
    usage: UsageSummary[];
    other: MetadataMap;
}

export function parseMetadataText(text: string): MetadataMap {
    const result: MetadataMap = {};
    text
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .forEach((line) => {
            const separatorIndex = line.indexOf('=');
            if (separatorIndex === -1) {
                return;
            }
            const key = line.slice(0, separatorIndex).trim();
            const value = line.slice(separatorIndex + 1).trim();
            if (key) {
                result[key] = value;
            }
        });
    return result;
}

export function stringifyMetadata(metadata?: MetadataMap): string {
    if (!metadata || Object.keys(metadata).length === 0) {
        return '';
    }
    return Object.entries(metadata)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');
}

export function mergeMetadata(
    base: MetadataMap,
    patch: MetadataMap,
    keysToOmit: string[] = []
): MetadataMap {
    const next = { ...base };
    keysToOmit.forEach((key) => {
        delete next[key];
    });
    Object.entries(patch).forEach(([key, value]) => {
        next[key] = value;
    });
    return next;
}

export function summarizeMetadata(metadata?: MetadataMap): MetadataSummary {
    const summary: MetadataSummary = {
        flags: {},
        settings: {},
        limits: {},
        usage: [],
        other: {},
    };

    if (!metadata) {
        return summary;
    }

    const usageMap = new Map<string, UsageSummary>();

    Object.entries(metadata).forEach(([key, value]) => {
        if (key.startsWith('flag:')) {
            summary.flags[key.slice(5)] = parseBoolean(value);
            return;
        }
        if (key.startsWith('setting:')) {
            summary.settings[key.slice(8)] = value;
            return;
        }
        if (key.startsWith('limit:')) {
            const n = Number(value);
            if (Number.isFinite(n)) {
                summary.limits[key.slice(6)] = n;
            }
            return;
        }
        if (key.startsWith('usage:')) {
            const [name, field] = key.slice(6).split(':');
            if (!name || !field) {
                summary.other[key] = value;
                return;
            }
            const existing = usageMap.get(name) ?? {
                name,
                metadata: {},
            };
            if (field === 'limit') {
                const n = Number(value);
                if (Number.isFinite(n)) existing.limit = n;
            } else if (field === 'window_seconds') {
                const n = Number(value);
                if (Number.isFinite(n)) existing.windowSeconds = n;
            } else if (field === 'current') {
                const n = Number(value);
                if (Number.isFinite(n)) existing.current = n;
            } else if (field === 'reset_at') {
                existing.resetAt = value;
            } else if (field === 'strategy') {
                existing.strategy = value;
            } else {
                existing.metadata[field] = value;
            }
            usageMap.set(name, existing);
            return;
        }
        summary.other[key] = value;
    });

    summary.usage = Array.from(usageMap.values()).sort((a, b) => a.name.localeCompare(b.name));
    return summary;
}

function parseBoolean(value: string): boolean {
    switch (value.trim().toLowerCase()) {
        case '0':
        case 'false':
        case 'off':
        case 'no':
        case 'disabled':
            return false;
        default:
            return true;
    }
}
