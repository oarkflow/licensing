import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import crmService from '@/services/crm';
import type { CRMLoginRequest, CRMLoginResponse, CRMSessionResponse } from '@/types/crm';

interface CRMContextValue {
    session: CRMSessionResponse | null;
    isLoading: boolean;
    isAuthenticated: boolean;
    login: (payload: CRMLoginRequest) => Promise<{ success: boolean; error?: string }>;
    logout: () => Promise<void>;
    refreshSession: () => Promise<void>;
}

const CRMContext = createContext<CRMContextValue | undefined>(undefined);

const deriveSessionFromLogin = (payload: CRMLoginResponse): CRMSessionResponse => {
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + payload.expires_in * 1000);
    return {
        user: payload.user,
        tenant: payload.tenant,
        products: payload.products,
        scope: payload.scope,
        issued_at: issuedAt.toISOString(),
        expires_at: expiresAt.toISOString(),
    };
};

export function CRMProvider({ children }: { children: ReactNode }) {
    const [session, setSession] = useState<CRMSessionResponse | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    const refreshSession = useCallback(async () => {
        if (!crmService.hasTokens()) {
            setSession(null);
            setIsLoading(false);
            return;
        }
        setIsLoading(true);
        try {
            const profile = await crmService.getSession();
            setSession(profile);
        } catch (error) {
            console.error('Failed to refresh CRM session', error);
            setSession(null);
        } finally {
            setIsLoading(false);
        }
    }, []);

    useEffect(() => {
        refreshSession();
    }, [refreshSession]);

    const login = useCallback(async (payload: CRMLoginRequest) => {
        try {
            const response = await crmService.login(payload);
            setSession(deriveSessionFromLogin(response));
            return { success: true };
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Login failed';
            return { success: false, error: message };
        }
    }, []);

    const logout = useCallback(async () => {
        try {
            await crmService.logout();
        } finally {
            setSession(null);
        }
    }, []);

    const value = useMemo<CRMContextValue>(
        () => ({
            session,
            isLoading,
            isAuthenticated: Boolean(session),
            login,
            logout,
            refreshSession,
        }),
        [session, isLoading, login, logout, refreshSession]
    );

    return <CRMContext.Provider value={value}>{children}</CRMContext.Provider>;
}

export function useCRMContext() {
    const context = useContext(CRMContext);
    if (!context) {
        throw new Error('useCRMContext must be used within a CRMProvider');
    }
    return context;
}
