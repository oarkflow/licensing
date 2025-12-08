import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import type { User, LoginRequest } from '@/types/api';
import api from '@/services/api';

interface AuthContextType {
    user: User | null;
    isLoading: boolean;
    isAuthenticated: boolean;
    login: (credentials: LoginRequest) => Promise<{ success: boolean; error?: string }>;
    logout: () => Promise<void>;
    refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
    const [user, setUser] = useState<User | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    const refreshSession = useCallback(async () => {
        try {
            const response = await api.getSession();
            if (response.success && response.data) {
                setUser(response.data);
            } else {
                setUser(null);
            }
        } catch {
            setUser(null);
        } finally {
            setIsLoading(false);
        }
    }, []);

    useEffect(() => {
        refreshSession();
    }, [refreshSession]);

    const login = async (credentials: LoginRequest) => {
        setIsLoading(true);
        try {
            const response = await api.login(credentials);
            if (response.success && response.data) {
                setUser(response.data);
                return { success: true };
            }
            return { success: false, error: response.error || 'Login failed' };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Login failed'
            };
        } finally {
            setIsLoading(false);
        }
    };

    const logout = async () => {
        try {
            await api.logout();
        } finally {
            setUser(null);
        }
    };

    return (
        <AuthContext.Provider
            value={{
                user,
                isLoading,
                isAuthenticated: !!user,
                login,
                logout,
                refreshSession,
            }}
        >
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}

export default AuthContext;
