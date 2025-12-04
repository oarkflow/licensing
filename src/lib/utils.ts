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
