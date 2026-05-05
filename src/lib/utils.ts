import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}

export function formatCurrency(amount: number, currency = "USD", locale = "en-US") {
    return new Intl.NumberFormat(locale, {
        style: "currency",
        currency,
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
    }).format(amount);
}

export function formatCurrencyFromCents(amountCents?: number, currency = "USD", locale = "en-US") {
    if (!amountCents || amountCents === 0) {
        return "";
    }
    return formatCurrency(amountCents / 100, currency, locale);
}

export interface SlugifyOptions {
    /** Character used to separate words */
    separator?: string;
    /** Convert result to lowercase */
    lowercase?: boolean;
    /** Fallback value if slug becomes empty */
    fallback?: string;
}

export function slugify(
    input: string,
    options: SlugifyOptions = {}
): string {
    if (typeof input !== 'string') {
        throw new TypeError('slugify: input must be a string');
    }

    const {
        separator = '-',
        lowercase = true,
        fallback = 'n-a',
    } = options;

    let slug = input
        // Normalize accented characters (é → e, ü → u)
        .normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '')

        // Split camelCase & PascalCase words
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
        .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')

        // Replace characters that are not alphanumeric, dash, or underscore with spaces
        .replace(/[^A-Za-z0-9_-]+/g, ' ')

        // Trim & collapse whitespace into separator
        .trim()
        .replace(/\s+/g, separator)

        // Remove leading/trailing separators
        .replace(new RegExp(`^${separator}+|${separator}+$`, 'g'), '');

    if (lowercase) {
        slug = slug.toLowerCase();
    }

    return slug || fallback;
}



// normalizeSlug converts a string into a URL-friendly slug.
// Behavior:
// - lowercases
// - trims whitespace
// - replaces spaces with dashes
// - preserves dashes and underscores; removes other characters
// - collapses multiple dashes
// - trims leading/trailing dashes
export function normalizeSlug(value: string) {
    return slugify(value, { separator: '-', lowercase: true, fallback: 'n-a' });
}
