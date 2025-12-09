import { API_BASE_URL } from './api';
import type {
    CRMDeviceLedgerRecord,
    CRMEntitlementAssignmentPayload,
    CRMEntitlementResponse,
    CRMLoginRequest,
    CRMLoginResponse,
    CRMOfflineBundle,
    CRMProductAccess,
    CRMServiceAccountRequest,
    CRMServiceAccountResponse,
    CRMSessionResponse,
    CRMTenantProductsResponse,
    CRMTenantProvisionRequest,
    CRMTenantView,
} from '@/types/crm';

const ACCESS_TOKEN_KEY = 'crm.access_token';
const REFRESH_TOKEN_KEY = 'crm.refresh_token';
const SCOPE_KEY = 'crm.scope';
const DEVICE_ID_KEY = 'crm.device_id';

type RequestConfig = RequestInit & {
    skipAuth?: boolean;
    retry?: boolean;
};

const getStorage = () => {
    if (typeof window === 'undefined') {
        return null;
    }
    try {
        return window.localStorage;
    } catch {
        return null;
    }
};

class CRMService {
    private accessToken: string | null;
    private refreshToken: string | null;
    private scope: string | null;
    private deviceId: string | null;
    private refreshPromise: Promise<boolean> | null = null;

    constructor() {
        const storage = getStorage();
        this.accessToken = storage?.getItem(ACCESS_TOKEN_KEY) || null;
        this.refreshToken = storage?.getItem(REFRESH_TOKEN_KEY) || null;
        this.scope = storage?.getItem(SCOPE_KEY) || null;
        this.deviceId = storage?.getItem(DEVICE_ID_KEY) || null;
    }

    hasTokens() {
        return Boolean(this.accessToken && this.refreshToken);
    }

    getAccessToken() {
        return this.accessToken;
    }

    private persistTokens() {
        const storage = getStorage();
        if (!storage) return;
        if (this.accessToken) {
            storage.setItem(ACCESS_TOKEN_KEY, this.accessToken);
        } else {
            storage.removeItem(ACCESS_TOKEN_KEY);
        }
        if (this.refreshToken) {
            storage.setItem(REFRESH_TOKEN_KEY, this.refreshToken);
        } else {
            storage.removeItem(REFRESH_TOKEN_KEY);
        }
        if (this.scope) {
            storage.setItem(SCOPE_KEY, this.scope);
        } else {
            storage.removeItem(SCOPE_KEY);
        }
        if (this.deviceId) {
            storage.setItem(DEVICE_ID_KEY, this.deviceId);
        } else {
            storage.removeItem(DEVICE_ID_KEY);
        }
    }

    private setTokens(accessToken: string, refreshToken: string, scope?: string) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        if (scope) {
            this.scope = scope;
        }
        this.persistTokens();
    }

    private clearTokens() {
        this.accessToken = null;
        this.refreshToken = null;
        this.persistTokens();
    }

    private async request<T>(endpoint: string, options: RequestConfig = {}): Promise<T> {
        const { skipAuth, retry, headers, ...rest } = options;
        const url = `${API_BASE_URL}${endpoint}`;
        const nextHeaders: Record<string, string> = {
            'Content-Type': 'application/json',
            ...(headers as Record<string, string>),
        };
        if (!skipAuth && this.accessToken) {
            nextHeaders.Authorization = `Bearer ${this.accessToken}`;
        }

        const response = await fetch(url, {
            credentials: 'include',
            ...rest,
            headers: nextHeaders,
        });

        if (response.status === 401 && !skipAuth && !retry && this.refreshToken) {
            const refreshed = await this.tryRefreshToken();
            if (refreshed) {
                return this.request(endpoint, { ...options, retry: true });
            }
        }

        const text = await response.text();
        let data: unknown = null;
        if (text) {
            try {
                data = JSON.parse(text);
            } catch {
                data = text;
            }
        }

        if (!response.ok) {
            const message = typeof data === 'string'
                ? data
                : (data as { error?: string; message?: string })?.error || (data as { error?: string; message?: string })?.message || 'Request failed';
            throw new Error(message);
        }

        return data as T;
    }

    private async tryRefreshToken(): Promise<boolean> {
        if (!this.refreshToken) {
            this.clearTokens();
            return false;
        }
        if (this.refreshPromise) {
            return this.refreshPromise;
        }
        this.refreshPromise = (async () => {
            try {
                const payload = await this.request<CRMLoginResponse>(
                    '/api/crm/token/refresh',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            refresh_token: this.refreshToken,
                            scope: this.scope,
                            device_id: this.deviceId,
                        }),
                        skipAuth: true,
                    }
                );
                this.setTokens(payload.access_token, payload.refresh_token, payload.scope);
                return true;
            } catch (error) {
                console.error('CRM token refresh failed', error);
                this.clearTokens();
                return false;
            } finally {
                this.refreshPromise = null;
            }
        })();
        return this.refreshPromise;
    }

    async login(request: CRMLoginRequest) {
        if (request.device_id) {
            this.deviceId = request.device_id;
        }
        const payload = await this.request<CRMLoginResponse>('/api/crm/login', {
            method: 'POST',
            body: JSON.stringify(request),
            skipAuth: true,
        });
        this.setTokens(payload.access_token, payload.refresh_token, payload.scope);
        return payload;
    }

    async logout(refreshToken?: string) {
        try {
            await this.request('/api/crm/logout', {
                method: 'POST',
                body: JSON.stringify({
                    refresh_token: refreshToken || this.refreshToken,
                    device_id: this.deviceId || undefined,
                }),
            });
        } finally {
            this.clearTokens();
        }
    }

    async getSession(): Promise<CRMSessionResponse> {
        return this.request<CRMSessionResponse>('/api/crm/session');
    }

    async provisionTenant(payload: CRMTenantProvisionRequest) {
        return this.request<CRMTenantView>('/api/crm/tenants', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
    }

    async listTenantProducts(tenantId: string): Promise<CRMProductAccess[]> {
        const data = await this.request<CRMTenantProductsResponse>(`/api/crm/tenants/${tenantId}/products`);
        return data.products;
    }

    async assignEntitlement(payload: CRMEntitlementAssignmentPayload): Promise<CRMEntitlementResponse> {
        return this.request<CRMEntitlementResponse>('/api/crm/entitlements', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
    }

    async getDeviceLedger(fingerprint: string, tenantId?: string): Promise<CRMDeviceLedgerRecord> {
        const query = tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : '';
        return this.request<CRMDeviceLedgerRecord>(`/api/crm/devices/${encodeURIComponent(fingerprint)}${query}`);
    }

    async createServiceAccount(payload: CRMServiceAccountRequest): Promise<CRMServiceAccountResponse> {
        return this.request<CRMServiceAccountResponse>('/api/crm/service-accounts', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
    }

    async fetchOfflineBundle(licenseId: string): Promise<CRMOfflineBundle> {
        return this.request<CRMOfflineBundle>(`/api/licensing/offline/bundles/${encodeURIComponent(licenseId)}`);
    }
}

const crmService = new CRMService();

export default crmService;
