# Enhanced Licensing Server: Authentication & CRM System Design

## Overview

This document outlines the comprehensive design for enhancing the licensing server to support:
1. Client authentication via CRM API endpoints
2. Offline license validation
3. Hybrid authentication/validation approach
4. Complete CRM and product management system

## Current System Analysis

### Strengths
- Robust admin authentication system (username/password + API keys)
- Comprehensive license management
- Product, plan, and feature management
- Email notification system
- Rate limiting and security headers

### Gaps
- No client authentication for product access
- Clients identified only by email, no credentials
- No offline license validation mechanism
- Limited CRM capabilities
- No product access control for clients

## Proposed Architecture

### 1. Authentication System with API Endpoints

#### Client Authentication Model

```mermaid
classDiagram
    class Client {
        +id: string
        +email: string
        +password_hash: string
        +salt: string
        +status: string
        +created_at: datetime
        +updated_at: datetime
        +last_login: datetime
        +login_attempts: int
        +account_locked_until: datetime
        +mfa_secret: string
        +mfa_enabled: boolean
        +api_key_hash: string
        +refresh_tokens: string[]
    }

    class ClientSession {
        +id: string
        +client_id: string
        +session_token: string
        +refresh_token: string
        +ip_address: string
        +user_agent: string
        +created_at: datetime
        +expires_at: datetime
        +is_revoked: boolean
    }

    class ClientAPIKey {
        +id: string
        +client_id: string
        +key_hash: string
        +prefix: string
        +created_at: datetime
        +last_used: datetime
        +expires_at: datetime
        +is_revoked: boolean
    }
```

#### New API Endpoints

**Authentication Endpoints:**
- `POST /api/client/auth/login` - Client login with email/password
- `POST /api/client/auth/logout` - Client logout
- `POST /api/client/auth/refresh` - Refresh access token
- `POST /api/client/auth/forgot-password` - Password reset request
- `POST /api/client/auth/reset-password` - Password reset completion
- `POST /api/client/auth/mfa/setup` - MFA setup
- `POST /api/client/auth/mfa/verify` - MFA verification
- `GET /api/client/auth/session` - Get current session info

**Client Management Endpoints:**
- `POST /api/client/auth/register` - Client self-registration
- `GET /api/client/profile` - Get client profile
- `PUT /api/client/profile` - Update client profile
- `POST /api/client/api-keys` - Generate API key for client
- `DELETE /api/client/api-keys/{id}` - Revoke client API key
- `GET /api/client/api-keys` - List client API keys

### 2. Offline License Validation System

#### Offline Validation Model

```mermaid
classDiagram
    class OfflineLicense {
        +license_key: string
        +client_id: string
        +product_id: string
        +plan_slug: string
        +issued_at: datetime
        +expires_at: datetime
        +max_devices: int
        +device_fingerprint: string
        +signature: string
        +public_key: string
        +offline_validation_token: string
        +validation_salt: string
    }

    class OfflineValidationToken {
        +token: string
        +license_key: string
        +client_id: string
        +device_fingerprint: string
        +valid_until: datetime
        +usage_count: int
        +max_uses: int
        +is_revoked: boolean
        +created_at: datetime
    }
```

#### Offline Validation Process

1. **Token Generation**: Client requests offline validation token from server
2. **Token Storage**: Token is stored securely on client device
3. **Offline Validation**: Client validates license using stored token
4. **Periodic Sync**: Client syncs with server when online to refresh tokens

**New API Endpoints:**
- `POST /api/licenses/{license_key}/offline-token` - Generate offline validation token
- `POST /api/licenses/offline-validate` - Validate license offline (returns signed validation result)
- `GET /api/licenses/{license_key}/offline-status` - Check offline validation status
- `POST /api/licenses/{license_key}/offline-sync` - Sync offline usage data

### 3. Hybrid Authentication/Validation Approach

```mermaid
sequenceDiagram
    participant ClientApp
    participant LicenseServer
    participant OfflineCache

    ClientApp->>LicenseServer: Attempt online authentication
    alt Online available
        LicenseServer-->>ClientApp: Authentication successful
        ClientApp->>LicenseServer: Request offline token
        LicenseServer-->>ClientApp: Offline validation token
        ClientApp->>OfflineCache: Store token
    else Offline
        ClientApp->>OfflineCache: Retrieve stored token
        alt Token valid
            OfflineCache-->>ClientApp: Validation successful
        else Token invalid/expired
            ClientApp->>ClientApp: Show limited functionality
            ClientApp->>ClientApp: Queue sync for later
        end
    end
```

### 4. Complete CRM and Product Management System

#### Enhanced Client Model

```typescript
interface EnhancedClient {
    id: string;
    email: string;
    password_hash: string;
    salt: string;
    status: 'active' | 'banned' | 'suspended' | 'pending';
    created_at: string;
    updated_at: string;
    last_login: string;
    login_attempts: number;
    account_locked_until?: string;
    mfa_secret?: string;
    mfa_enabled: boolean;
    api_keys: ClientAPIKey[];
    sessions: ClientSession[];
    profile: ClientProfile;
    subscriptions: ClientSubscription[];
    licenses: ClientLicense[];
    devices: ClientDevice[];
    notes: ClientNote[];
    tags: string[];
    metadata: Record<string, string>;
}

interface ClientProfile {
    first_name: string;
    last_name: string;
    company_name?: string;
    phone?: string;
    address?: {
        street: string;
        city: string;
        state: string;
        country: string;
        postal_code: string;
    };
    preferences: {
        language: string;
        timezone: string;
        notification_preferences: {
            email: boolean;
            sms: boolean;
            push: boolean;
        };
    };
}

interface ClientSubscription {
    id: string;
    product_id: string;
    plan_id: string;
    status: 'active' | 'cancelled' | 'paused' | 'expired';
    start_date: string;
    end_date: string;
    billing_cycle: string;
    payment_method?: string;
    auto_renew: boolean;
    created_at: string;
    updated_at: string;
}

interface ClientDevice {
    id: string;
    device_id: string;
    device_name: string;
    device_type: string;
    os: string;
    os_version: string;
    app_version: string;
    ip_address: string;
    last_seen: string;
    is_active: boolean;
    created_at: string;
}
```

#### New CRM API Endpoints

**Client Management:**
- `GET /api/crm/clients` - List all clients with filtering
- `GET /api/crm/clients/{id}` - Get client details
- `POST /api/crm/clients` - Create new client
- `PUT /api/crm/clients/{id}` - Update client
- `POST /api/crm/clients/{id}/ban` - Ban client
- `POST /api/crm/clients/{id}/unban` - Unban client
- `GET /api/crm/clients/{id}/activity` - Get client activity log

**Product Access:**
- `GET /api/crm/clients/{id}/products` - List client's products
- `POST /api/crm/clients/{id}/products/{product_id}/grant` - Grant product access
- `POST /api/crm/clients/{id}/products/{product_id}/revoke` - Revoke product access
- `GET /api/crm/clients/{id}/products/{product_id}/usage` - Get product usage stats

**Subscription Management:**
- `GET /api/crm/clients/{id}/subscriptions` - List client subscriptions
- `POST /api/crm/clients/{id}/subscriptions` - Create subscription
- `PUT /api/crm/clients/{id}/subscriptions/{subscription_id}` - Update subscription
- `POST /api/crm/clients/{id}/subscriptions/{subscription_id}/cancel` - Cancel subscription

**Device Management:**
- `GET /api/crm/clients/{id}/devices` - List client devices
- `POST /api/crm/clients/{id}/devices` - Register new device
- `DELETE /api/crm/clients/{id}/devices/{device_id}` - Remove device
- `POST /api/crm/clients/{id}/devices/{device_id}/deactivate` - Deactivate device

### 5. Security Enhancements

#### Password Security
- bcrypt password hashing with work factor 12
- Unique salt per client
- Account lockout after 5 failed attempts
- Password complexity requirements
- Password expiration policy (optional)

#### Token Security
- JWT with short expiration (15-30 minutes)
- Refresh tokens with longer expiration (7-30 days)
- Token revocation mechanism
- IP and user agent binding for sensitive operations
- Rate limiting on authentication endpoints

#### Data Protection
- Encryption of sensitive client data at rest
- Secure session management
- CSRF protection
- CORS restrictions
- Security headers

### 6. Database Schema Extensions

```sql
-- Client authentication tables
CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    salt TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    last_login TIMESTAMP,
    login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP,
    mfa_secret TEXT,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    metadata JSON
);

CREATE TABLE client_sessions (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id),
    session_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    UNIQUE(client_id, session_token),
    UNIQUE(refresh_token)
);

CREATE TABLE client_api_keys (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id),
    key_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_used TIMESTAMP,
    expires_at TIMESTAMP,
    is_revoked BOOLEAN DEFAULT FALSE,
    UNIQUE(prefix)
);

-- Offline validation tables
CREATE TABLE offline_validation_tokens (
    token TEXT PRIMARY KEY,
    license_key TEXT NOT NULL,
    client_id TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    usage_count INTEGER DEFAULT 0,
    max_uses INTEGER NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (license_key) REFERENCES licenses(license_key),
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE offline_validation_logs (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    license_key TEXT NOT NULL,
    client_id TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL,
    validation_time TIMESTAMP NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (token) REFERENCES offline_validation_tokens(token),
    FOREIGN KEY (license_key) REFERENCES licenses(license_key),
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

-- CRM tables
CREATE TABLE client_profiles (
    client_id TEXT PRIMARY KEY REFERENCES clients(id),
    first_name TEXT,
    last_name TEXT,
    company_name TEXT,
    phone TEXT,
    address JSON,
    preferences JSON,
    last_updated TIMESTAMP NOT NULL
);

CREATE TABLE client_subscriptions (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id),
    product_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL,
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP NOT NULL,
    billing_cycle TEXT NOT NULL,
    payment_method TEXT,
    auto_renew BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (plan_id) REFERENCES plans(id)
);

CREATE TABLE client_devices (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id),
    device_id TEXT NOT NULL,
    device_name TEXT,
    device_type TEXT,
    os TEXT,
    os_version TEXT,
    app_version TEXT,
    ip_address TEXT,
    last_seen TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL,
    UNIQUE(client_id, device_id)
);

CREATE TABLE client_activity_log (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id),
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    metadata JSON,
    created_at TIMESTAMP NOT NULL
);
```

### 7. Implementation Roadmap

#### Phase 1: Core Authentication
1. Implement client authentication tables and models
2. Add password hashing and security utilities
3. Implement login/logout endpoints
4. Add session management
5. Implement token generation and validation

#### Phase 2: Offline Validation
1. Implement offline token generation
2. Add offline validation endpoints
3. Create validation token storage
4. Implement client-side validation logic
5. Add sync mechanism

#### Phase 3: Hybrid System
1. Implement fallback logic for offline mode
2. Add token caching on client side
3. Implement periodic sync
4. Add conflict resolution for offline changes

#### Phase 4: CRM Enhancements
1. Extend client model with profile data
2. Implement subscription management
3. Add device management
4. Create activity logging
5. Build reporting endpoints

### 8. API Documentation Examples

**Client Login:**
```bash
POST /api/client/auth/login
Content-Type: application/json

{
    "email": "client@example.com",
    "password": "securePassword123!",
    "device_info": {
        "device_id": "device-123",
        "device_name": "My Workstation",
        "device_type": "desktop",
        "os": "Windows",
        "os_version": "11"
    }
}

Response:
{
    "success": true,
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "refresh-token-123...",
    "expires_in": 1800,
    "client": {
        "id": "client-123",
        "email": "client@example.com",
        "status": "active"
    }
}
```

**Generate Offline Token:**
```bash
POST /api/licenses/LICENSE-123/offline-token
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
    "device_fingerprint": "device-fp-123",
    "max_uses": 30,
    "validity_days": 30
}

Response:
{
    "success": true,
    "offline_token": "offline-token-123...",
    "valid_until": "2024-12-09T16:00:00Z",
    "max_uses": 30,
    "current_uses": 0
}
```

**Offline Validation:**
```bash
POST /api/licenses/offline-validate
Content-Type: application/json

{
    "license_key": "LICENSE-123",
    "offline_token": "offline-token-123...",
    "device_fingerprint": "device-fp-123",
    "validation_data": {
        "timestamp": "2024-11-09T16:00:00Z",
        "app_version": "1.0.0"
    }
}

Response:
{
    "success": true,
    "valid": true,
    "license": {
        "license_key": "LICENSE-123",
        "client_id": "client-123",
        "product_id": "product-123",
        "expires_at": "2025-12-09T16:00:00Z",
        "max_devices": 5,
        "current_device_count": 1
    },
    "signature": "digital-signature-123...",
    // Note: signatures now cover both the encrypted license blob and the device fingerprint
    // (SHA256(encrypted_license || device_fingerprint)) to prevent tampering of the
    // device binding field in stored license files.
    "validation_time": "2024-11-09T16:00:00Z"
}
```

### 9. Client-Side Implementation Guide

#### Authentication Flow
```javascript
// Client authentication service
class ClientAuthService {
    async login(email, password, deviceInfo) {
        const response = await api.post('/api/client/auth/login', {
            email,
            password,
            device_info: deviceInfo
        });

        if (response.success) {
            localStorage.setItem('access_token', response.access_token);
            localStorage.setItem('refresh_token', response.refresh_token);
            localStorage.setItem('client_id', response.client.id);
            return true;
        }
        return false;
    }

    async logout() {
        await api.post('/api/client/auth/logout');
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('client_id');
    }

    async refreshToken() {
        const refreshToken = localStorage.getItem('refresh_token');
        const response = await api.post('/api/client/auth/refresh', {
            refresh_token: refreshToken
        });

        if (response.success) {
            localStorage.setItem('access_token', response.access_token);
            return true;
        }
        return false;
    }
}
```

#### Offline Validation Flow
```javascript
// Offline validation service
class OfflineValidationService {
    constructor() {
        this.offlineTokens = JSON.parse(localStorage.getItem('offline_tokens') || '{}');
    }

    async requestOfflineToken(licenseKey, deviceFingerprint, maxUses = 30, validityDays = 30) {
        try {
            const response = await api.post(`/api/licenses/${licenseKey}/offline-token`, {
                device_fingerprint: deviceFingerprint,
                max_uses: maxUses,
                validity_days: validityDays
            });

            if (response.success) {
                this.offlineTokens[licenseKey] = response;
                localStorage.setItem('offline_tokens', JSON.stringify(this.offlineTokens));
                return response.offline_token;
            }
        } catch (error) {
            // If offline, try to use existing token
            if (this.offlineTokens[licenseKey]) {
                return this.offlineTokens[licenseKey].offline_token;
            }
        }
        return null;
    }

    async validateOffline(licenseKey, deviceFingerprint) {
        const tokenData = this.offlineTokens[licenseKey];
        if (!tokenData) {
            return { success: false, error: 'No offline token available' };
        }

        if (tokenData.current_uses >= tokenData.max_uses) {
            return { success: false, error: 'Offline token exhausted' };
        }

        if (new Date(tokenData.valid_until) < new Date()) {
            return { success: false, error: 'Offline token expired' };
        }

        try {
            // Try online validation first if possible
            const onlineResponse = await api.post('/api/licenses/offline-validate', {
                license_key: licenseKey,
                offline_token: tokenData.offline_token,
                device_fingerprint: deviceFingerprint,
                validation_data: {
                    timestamp: new Date().toISOString(),
                    app_version: '1.0.0'
                }
            });

            if (onlineResponse.success) {
                // Update token usage count
                tokenData.current_uses = onlineResponse.current_uses;
                localStorage.setItem('offline_tokens', JSON.stringify(this.offlineTokens));
                return onlineResponse;
            }
        } catch (error) {
            // Fallback to offline validation logic
            return this.performLocalValidation(licenseKey, tokenData, deviceFingerprint);
        }

        return { success: false, error: 'Validation failed' };
    }

    performLocalValidation(licenseKey, tokenData, deviceFingerprint) {
        // Implement local validation logic using:
        // - Stored license data
        // - Token signature verification
        // - Device fingerprint matching
        // - Usage count tracking

        return {
            success: true,
            valid: true,
            license: {
                license_key: licenseKey,
                // ... other license data from local storage
            },
            offline: true,
            last_sync: tokenData.last_sync || tokenData.created_at
        };
    }
}
```

### 10. Security Best Practices

1. **Password Storage**: Use bcrypt with appropriate work factor
2. **Token Management**: Short-lived access tokens, longer-lived refresh tokens
3. **Rate Limiting**: Protect authentication endpoints from brute force
4. **Input Validation**: Validate all user inputs thoroughly
5. **Error Handling**: Don't leak sensitive information in error messages
6. **Logging**: Comprehensive logging for security events
7. **Monitoring**: Monitor for suspicious activity patterns
8. **Regular Audits**: Security audits and penetration testing

### 11. Performance Considerations

1. **Caching**: Cache frequently accessed client data
2. **Database Indexing**: Proper indexes on authentication tables
3. **Connection Pooling**: Efficient database connection management
4. **Asynchronous Processing**: For non-critical operations like logging
5. **Load Balancing**: For high-traffic authentication endpoints

### 12. Future Enhancements

1. **Single Sign-On (SSO)**: Integration with OAuth/OIDC providers
2. **Biometric Authentication**: Fingerprint/face recognition support
3. **Hardware Security Modules**: For enhanced key management
4. **Blockchain-based Licensing**: For tamper-proof license records
5. **AI-based Anomaly Detection**: For fraud prevention
6. **Multi-tenant Support**: For white-label solutions

## Conclusion

This design provides a comprehensive blueprint for enhancing the licensing server with:
- Secure client authentication via API endpoints
- Robust offline license validation
- Hybrid online/offline operation
- Complete CRM and product management capabilities
- Scalable and extensible architecture

The solution maintains backward compatibility while adding powerful new features that transform the licensing server into a complete customer relationship and product access management platform.
