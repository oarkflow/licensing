import type {
    AdminUser,
    APIKey,
    Activation,
    ApiResponse,
    Client,
    CreateAdminUserRequest,
    CreateClientRequest,
    CreateFeatureRequest,
    CreateLicenseRequest,
    CreatePlanRequest,
    CreateProductRequest,
    CreateScopeRequest,
    DashboardStats,
    EmailComposeRequest,
    EmailComposeResponse,
    EmailProvider,
    EmailProviderTestRequest,
    EmailProviderTestResponse,
    EmailTemplate,
    Feature,
    FeatureScope,
    FeatureScopeSelection,
    License,
    LicenseEntitlements,
    LoginRequest,
    Plan,
    PlanFeature,
    Product,
    ProductStats,
    SaveEmailProviderRequest,
    SaveEmailTemplateRequest,
    User,
} from '@/types/api';

const DEFAULT_DEV_API = 'http://localhost:6601';

const resolveAPIBaseURL = (): string => {
    const configured = (import.meta.env.VITE_API_URL || '').trim().replace(/\/+$/, '');
    if (configured) {
        return configured;
    }

    if (typeof window !== 'undefined') {
        if (import.meta.env.DEV) {
            return DEFAULT_DEV_API;
        }
        return window.location.origin;
    }

    return '';
};

export const API_BASE_URL = resolveAPIBaseURL();

// Request queue for intelligent rate limiting
interface QueuedRequest {
    execute: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (error: unknown) => void;
}

class RequestQueue {
    private queue: QueuedRequest[] = [];
    private processing = false;
    private lastRequestTime = 0;
    private minInterval = 100; // Minimum 100ms between requests
    private retryDelay = 1000; // 1 second retry delay on 429

    async add<T>(execute: () => Promise<T>): Promise<T> {
        return new Promise((resolve, reject) => {
            this.queue.push({
                execute,
                resolve: resolve as (value: unknown) => void,
                reject,
            });
            this.processQueue();
        });
    }

    private async processQueue() {
        if (this.processing || this.queue.length === 0) return;

        this.processing = true;

        while (this.queue.length > 0) {
            const timeSinceLastRequest = Date.now() - this.lastRequestTime;
            if (timeSinceLastRequest < this.minInterval) {
                await this.sleep(this.minInterval - timeSinceLastRequest);
            }

            const request = this.queue.shift();
            if (!request) continue;

            try {
                this.lastRequestTime = Date.now();
                const result = await request.execute();
                request.resolve(result);
            } catch (error) {
                request.reject(error);
            }
        }

        this.processing = false;
    }

    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    setRetryDelay(delay: number) {
        this.retryDelay = delay;
    }

    getRetryDelay() {
        return this.retryDelay;
    }
}

const requestQueue = new RequestQueue();

class ApiService {
    private pendingRequests = new Map<string, Promise<ApiResponse<unknown>>>();

    private async request<T>(
        endpoint: string,
        options: RequestInit = {}
    ): Promise<ApiResponse<T>> {
        // Create a cache key for GET requests to deduplicate
        const method = options.method || 'GET';
        const cacheKey = method === 'GET' ? `${method}:${endpoint}` : null;

        // For GET requests, check if there's already a pending request
        if (cacheKey && this.pendingRequests.has(cacheKey)) {
            return this.pendingRequests.get(cacheKey) as Promise<ApiResponse<T>>;
        }

        const executeRequest = async (): Promise<ApiResponse<T>> => {
            const url = `${API_BASE_URL}${endpoint}`;
            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
                ...((options.headers as Record<string, string>) || {}),
            };

            try {
                const response = await fetch(url, {
                    ...options,
                    headers,
                    credentials: 'include',
                    redirect: 'follow',
                });
                if (response.status === 401) {
                    const currentPath = window.location.pathname;
                    if (currentPath !== '/login' && currentPath !== '/setup') {
                        window.location.href = '/login';
                    }
                    return { success: false, error: 'Unauthorized' };
                }

                // Handle rate limiting gracefully
                if (response.status === 429) {
                    const retryAfter = response.headers.get('Retry-After');
                    const delay = retryAfter ? parseInt(retryAfter) * 1000 : requestQueue.getRetryDelay();
                    console.warn(`Rate limited, retrying after ${delay}ms`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                    // Retry the request
                    return this.request<T>(endpoint, options);
                }

                const text = await response.text();
                if (!text) {
                    if (!response.ok) {
                        return { success: false, error: 'Request failed' };
                    }
                    return { success: true, data: undefined as T };
                }

                const data = JSON.parse(text);

                if (!response.ok) {
                    // Special handling for setup required
                    if (data.error === "Require Setup before login" || data.error?.message === "Require Setup before login") {
                        window.location.href = '/setup';
                        return { success: false, error: 'Setup required' };
                    }

                    return {
                        success: false,
                        error: data.error || data.message || 'Request failed',
                    };
                }

                return { success: true, data };
            } catch (error) {
                console.error('API request failed:', error);
                return {
                    success: false,
                    error: error instanceof Error ? error.message : 'Network error',
                };
            }
        };

        // Queue the request for rate limiting
        const promise = requestQueue.add(executeRequest);

        // Store pending GET requests for deduplication
        if (cacheKey) {
            this.pendingRequests.set(cacheKey, promise as Promise<ApiResponse<unknown>>);
            promise.finally(() => {
                this.pendingRequests.delete(cacheKey);
            });
        }

        return promise;
    }

    // Auth
    async login(credentials: LoginRequest): Promise<ApiResponse<User>> {
        return this.request<User>('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials),
        });
    }

    async logout(): Promise<ApiResponse<void>> {
        return this.request<void>('/api/auth/logout', { method: 'POST' });
    }

    async getSession(): Promise<ApiResponse<User>> {
        return this.request<User>('/api/auth/session');
    }

    async setup(credentials: LoginRequest): Promise<ApiResponse<User>> {
        return this.request<User>('/api/auth/setup', {
            method: 'POST',
            body: JSON.stringify(credentials),
        });
    }

    async checkSetupRequired(): Promise<ApiResponse<{ required: boolean }>> {
        return this.request<{ required: boolean }>('/api/auth/setup-required');
    }

    // Dashboard
    async getDashboardStats(): Promise<ApiResponse<DashboardStats>> {
        return this.request<DashboardStats>('/api/dashboard/stats');
    }

    // Licenses
    async listLicenses(filter?: string): Promise<ApiResponse<License[]>> {
        const query = filter ? `?filter=${filter}` : '';
        return this.request<License[]>(`/api/licenses${query}`);
    }

    async getLicense(id: string): Promise<ApiResponse<License>> {
        return this.request<License>(`/api/licenses/${id}`);
    }

    async createLicense(data: CreateLicenseRequest): Promise<ApiResponse<License>> {
        return this.request<License>('/api/licenses', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async revokeLicense(id: string, reason: string): Promise<ApiResponse<License>> {
        return this.request<License>(`/api/licenses/${id}/revoke`, {
            method: 'POST',
            body: JSON.stringify({ reason }),
        });
    }

    async reinstateLicense(id: string): Promise<ApiResponse<License>> {
        return this.request<License>(`/api/licenses/${id}/reinstate`, {
            method: 'POST',
        });
    }

    async deactivateDevice(
        licenseId: string,
        fingerprint: string
    ): Promise<ApiResponse<void>> {
        return this.request<void>(`/api/licenses/${licenseId}/deactivate-device`, {
            method: 'POST',
            body: JSON.stringify({ fingerprint }),
        });
    }

    async updateLicenseEntitlements(
        licenseId: string,
        featureScopes: FeatureScopeSelection[]
    ): Promise<ApiResponse<License>> {
        return this.request<License>(`/api/licenses/${licenseId}/entitlements`, {
            method: 'PUT',
            body: JSON.stringify({ feature_scopes: featureScopes }),
        });
    }

    async getLicenseActivations(licenseId: string): Promise<ApiResponse<Activation[]>> {
        return this.request<Activation[]>(`/api/licenses/${licenseId}/activations`);
    }

    // Clients
    async listClients(filter?: string): Promise<ApiResponse<Client[]>> {
        const query = filter ? `?filter=${filter}` : '';
        return this.request<Client[]>(`/api/clients${query}`);
    }

    async getClient(id: string): Promise<ApiResponse<Client>> {
        return this.request<Client>(`/api/clients/${id}`);
    }

    async createClient(data: CreateClientRequest): Promise<ApiResponse<Client>> {
        return this.request<Client>('/api/clients', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async banClient(id: string, reason: string): Promise<ApiResponse<Client>> {
        return this.request<Client>(`/api/clients/${id}/ban`, {
            method: 'POST',
            body: JSON.stringify({ reason }),
        });
    }

    async unbanClient(id: string): Promise<ApiResponse<Client>> {
        return this.request<Client>(`/api/clients/${id}/unban`, {
            method: 'POST',
        });
    }

    async getClientLicenses(clientId: string): Promise<ApiResponse<License[]>> {
        return this.request<License[]>(`/api/clients/${clientId}/licenses`);
    }

    // Products
    async listProducts(): Promise<ApiResponse<Product[]>> {
        return this.request<Product[]>('/api/products');
    }

    async getProduct(id: string): Promise<ApiResponse<Product>> {
        return this.request<Product>(`/api/products/${id}`);
    }

    async createProduct(data: CreateProductRequest): Promise<ApiResponse<Product>> {
        return this.request<Product>('/api/products', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async updateProduct(
        id: string,
        data: Partial<CreateProductRequest>
    ): Promise<ApiResponse<Product>> {
        return this.request<Product>(`/api/products/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async deleteProduct(id: string): Promise<ApiResponse<void>> {
        return this.request<void>(`/api/products/${id}`, {
            method: 'DELETE',
        });
    }

    async getProductStats(id: string): Promise<ApiResponse<ProductStats>> {
        return this.request<ProductStats>(`/api/products/${id}/stats`);
    }

    // Plans
    async listPlans(productId: string): Promise<ApiResponse<Plan[]>> {
        return this.request<Plan[]>(`/api/products/${productId}/plans`);
    }

    async getPlan(productId: string, planId: string): Promise<ApiResponse<Plan>> {
        return this.request<Plan>(`/api/products/${productId}/plans/${planId}`);
    }

    async createPlan(productId: string, data: Omit<CreatePlanRequest, 'productId'>): Promise<ApiResponse<Plan>> {
        return this.request<Plan>(`/api/products/${productId}/plans`, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async updatePlan(
        productId: string,
        planId: string,
        data: Partial<CreatePlanRequest>
    ): Promise<ApiResponse<Plan>> {
        return this.request<Plan>(`/api/products/${productId}/plans/${planId}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async deletePlan(productId: string, planId: string): Promise<ApiResponse<void>> {
        return this.request<void>(`/api/products/${productId}/plans/${planId}`, {
            method: 'DELETE',
        });
    }

    async getPlanFeatures(productId: string, planId: string): Promise<ApiResponse<PlanFeature[]>> {
        return this.request<PlanFeature[]>(`/api/products/${productId}/plans/${planId}/features`);
    }

    async getPlanEntitlements(
        productId: string,
        planId: string
    ): Promise<ApiResponse<LicenseEntitlements>> {
        const query = `?product_id=${productId}&plan_id=${planId}`;
        return this.request<LicenseEntitlements>(`/api/entitlements${query}`);
    }

    async addFeatureToPlan(
        productId: string,
        planId: string,
        featureId: string,
        options?: { enabled?: boolean; scope_overrides?: Record<string, { permission: string; limit?: number }> }
    ): Promise<ApiResponse<PlanFeature>> {
        return this.request<PlanFeature>(`/api/products/${productId}/plans/${planId}/features`, {
            method: 'POST',
            body: JSON.stringify({ feature_id: featureId, enabled: options?.enabled ?? true, scope_overrides: options?.scope_overrides }),
        });
    }

    async updatePlanFeature(
        productId: string,
        planId: string,
        featureId: string,
        data: { enabled?: boolean; scope_overrides?: Record<string, { permission: string; limit?: number }> }
    ): Promise<ApiResponse<PlanFeature>> {
        return this.request<PlanFeature>(`/api/products/${productId}/plans/${planId}/features/${featureId}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async removeFeatureFromPlan(
        productId: string,
        planId: string,
        featureId: string
    ): Promise<ApiResponse<void>> {
        return this.request<void>(
            `/api/products/${productId}/plans/${planId}/features/${featureId}`,
            { method: 'DELETE' }
        );
    }

    // Features
    async listFeatures(productId: string): Promise<ApiResponse<Feature[]>> {
        return this.request<Feature[]>(`/api/products/${productId}/features`);
    }

    async getFeature(productId: string, featureId: string): Promise<ApiResponse<Feature>> {
        return this.request<Feature>(`/api/products/${productId}/features/${featureId}`);
    }

    async createFeature(
        productId: string,
        data: Omit<CreateFeatureRequest, 'productId'>
    ): Promise<ApiResponse<Feature>> {
        return this.request<Feature>(`/api/products/${productId}/features`, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async updateFeature(
        productId: string,
        featureId: string,
        data: Partial<CreateFeatureRequest>
    ): Promise<ApiResponse<Feature>> {
        return this.request<Feature>(`/api/products/${productId}/features/${featureId}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async deleteFeature(productId: string, featureId: string): Promise<ApiResponse<void>> {
        return this.request<void>(`/api/products/${productId}/features/${featureId}`, {
            method: 'DELETE',
        });
    }

    // Scopes
    async listScopes(productId: string, featureId: string): Promise<ApiResponse<FeatureScope[]>> {
        return this.request<FeatureScope[]>(
            `/api/products/${productId}/features/${featureId}/scopes`
        );
    }

    async createScope(
        productId: string,
        featureId: string,
        data: Omit<CreateScopeRequest, 'featureId'>
    ): Promise<ApiResponse<FeatureScope>> {
        return this.request<FeatureScope>(
            `/api/products/${productId}/features/${featureId}/scopes`,
            {
                method: 'POST',
                body: JSON.stringify(data),
            }
        );
    }

    async updateScope(
        productId: string,
        featureId: string,
        scopeId: string,
        data: Partial<CreateScopeRequest>
    ): Promise<ApiResponse<FeatureScope>> {
        return this.request<FeatureScope>(
            `/api/products/${productId}/features/${featureId}/scopes/${scopeId}`,
            {
                method: 'PUT',
                body: JSON.stringify(data),
            }
        );
    }

    async deleteScope(
        productId: string,
        featureId: string,
        scopeId: string
    ): Promise<ApiResponse<void>> {
        return this.request<void>(
            `/api/products/${productId}/features/${featureId}/scopes/${scopeId}`,
            { method: 'DELETE' }
        );
    }

    // Admin Users
    async listAdminUsers(): Promise<ApiResponse<AdminUser[]>> {
        return this.request<AdminUser[]>('/api/admin/users');
    }

    async getAdminUser(id: string): Promise<ApiResponse<AdminUser>> {
        return this.request<AdminUser>(`/api/admin/users/${id}`);
    }

    async createAdminUser(data: CreateAdminUserRequest): Promise<ApiResponse<AdminUser>> {
        return this.request<AdminUser>('/api/admin/users', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async updateAdminUser(
        id: string,
        data: { username: string }
    ): Promise<ApiResponse<AdminUser>> {
        return this.request<AdminUser>(`/api/admin/users/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async deleteAdminUser(id: string): Promise<ApiResponse<void>> {
        return this.request<void>(`/api/admin/users/${id}`, {
            method: 'DELETE',
        });
    }

    async changeAdminPassword(
        id: string,
        currentPassword: string,
        newPassword: string
    ): Promise<ApiResponse<void>> {
        return this.request<void>(`/api/admin/users/${id}/password`, {
            method: 'POST',
            body: JSON.stringify({ currentPassword, newPassword }),
        });
    }

    // API Keys
    async listAPIKeys(userId: string): Promise<ApiResponse<APIKey[]>> {
        return this.request<APIKey[]>(`/api/admin/api-keys?user_id=${userId}`);
    }

    async createAPIKey(userId: string): Promise<ApiResponse<{ token: string; metadata: APIKey }>> {
        return this.request<{ token: string; metadata: APIKey }>('/api/admin/api-keys', {
            method: 'POST',
            body: JSON.stringify({ user_id: userId }),
        });
    }

    async deleteAPIKey(id: string): Promise<ApiResponse<void>> {
        return this.request<void>(`/api/admin/api-keys/${id}`, {
            method: 'DELETE',
        });
    }

    // Profile
    async updateProfile(data: { username: string }): Promise<ApiResponse<AdminUser>> {
        return this.request<AdminUser>('/api/profile', {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async changePassword(
        currentPassword: string,
        newPassword: string
    ): Promise<ApiResponse<void>> {
        return this.request<void>('/api/profile/password', {
            method: 'POST',
            body: JSON.stringify({ currentPassword, newPassword }),
        });
    }

    // Messaging - Providers
    async listEmailProviders(options?: { includeDisabled?: boolean }): Promise<ApiResponse<EmailProvider[]>> {
        const includeDisabled = options?.includeDisabled ? '1' : '0';
        const query = `?include_disabled=${includeDisabled}`;
        return this.request<EmailProvider[]>(`/api/email/providers${query}`);
    }

    async getEmailProvider(id: string): Promise<ApiResponse<EmailProvider>> {
        return this.request<EmailProvider>(`/api/email/providers/${id}`);
    }

    async createEmailProvider(data: SaveEmailProviderRequest): Promise<ApiResponse<EmailProvider>> {
        return this.request<EmailProvider>('/api/email/providers', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async updateEmailProvider(id: string, data: SaveEmailProviderRequest): Promise<ApiResponse<EmailProvider>> {
        return this.request<EmailProvider>(`/api/email/providers/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async deleteEmailProvider(id: string): Promise<ApiResponse<void>> {
        return this.request<void>(`/api/email/providers/${id}`, {
            method: 'DELETE',
        });
    }

    async testEmailProvider(payload: EmailProviderTestRequest): Promise<ApiResponse<EmailProviderTestResponse>> {
        return this.request<EmailProviderTestResponse>('/api/email/providers/test', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
    }

    async setDefaultEmailProvider(id: string): Promise<ApiResponse<EmailProvider>> {
        return this.request<EmailProvider>(`/api/email/providers/${id}/default`, {
            method: 'POST',
        });
    }

    async toggleEmailProvider(id: string, enabled: boolean): Promise<ApiResponse<EmailProvider>> {
        return this.request<EmailProvider>(`/api/email/providers/${id}/toggle`, {
            method: 'POST',
            body: JSON.stringify({ enabled }),
        });
    }

    // Messaging - Templates
    async listEmailTemplates(): Promise<ApiResponse<EmailTemplate[]>> {
        return this.request<EmailTemplate[]>('/api/email/templates');
    }

    async getEmailTemplate(id: string): Promise<ApiResponse<EmailTemplate>> {
        return this.request<EmailTemplate>(`/api/email/templates/${id}`);
    }

    async createEmailTemplate(data: SaveEmailTemplateRequest): Promise<ApiResponse<EmailTemplate>> {
        return this.request<EmailTemplate>('/api/email/templates', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async updateEmailTemplate(id: string, data: SaveEmailTemplateRequest): Promise<ApiResponse<EmailTemplate>> {
        return this.request<EmailTemplate>(`/api/email/templates/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async deleteEmailTemplate(id: string): Promise<ApiResponse<void>> {
        return this.request<void>(`/api/email/templates/${id}`, {
            method: 'DELETE',
        });
    }

    // Messaging - Compose
    async previewEmailCompose(data: EmailComposeRequest): Promise<ApiResponse<EmailComposeResponse>> {
        return this.request<EmailComposeResponse>('/api/email/compose/preview', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async sendEmailCompose(data: EmailComposeRequest): Promise<ApiResponse<EmailComposeResponse>> {
        return this.request<EmailComposeResponse>('/api/email/compose/send', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }
}

export const api = new ApiService();
export default api;
