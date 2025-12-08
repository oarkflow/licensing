# Security Implementation Guide

## Quick Start

This guide shows how to integrate all security components into your licensing system.

## 1. Initialize Security Components

```go
package main

import (
    "context"
    "database/sql"
    "log"
    "time"

    "your-project/backend/pkg/audit"
    "your-project/backend/pkg/auth"
    "your-project/backend/pkg/crypto"
    "your-project/backend/pkg/integrity"
)

type SecureServer struct {
    // Cryptography
    signer    crypto.Signer
    encryptor crypto.Encryptor

    // Audit
    auditLogger *audit.AuditLogger

    // Access Control
    accessControl *auth.AccessControl
    rateLimiter   *auth.RateLimiter

    // Integrity
    integrityVerifier *integrity.Verifier
    tamperDetector    *integrity.TamperDetector
}

func NewSecureServer(db *sql.DB) (*SecureServer, error) {
    // 1. Initialize cryptographic components
    signer, err := crypto.NewEd25519Signer("primary-key-v1")
    if err != nil {
        return nil, err
    }

    encryptionKey, err := crypto.GenerateKey()
    if err != nil {
        return nil, err
    }

    encryptor, err := crypto.NewAESGCMEncryptor(encryptionKey)
    if err != nil {
        return nil, err
    }

    // 2. Initialize audit logging
    auditStorage, err := audit.NewSQLiteStorage(db)
    if err != nil {
        return nil, err
    }

    auditLogger, err := audit.NewAuditLogger(&audit.AuditLoggerConfig{
        Storage:        auditStorage,
        Signer:         &cryptoSignerAdapter{signer},
        Async:          true,
        BufferSize:     1000,
        EnableChaining: true, // Enable tamper-proof event chaining
    })
    if err != nil {
        return nil, err
    }

    // 3. Initialize access control
    accessControl := auth.NewAccessControl()

    // 4. Initialize rate limiter (100 requests per minute)
    rateLimiter := auth.NewRateLimiter(100, time.Minute)

    // 5. Initialize integrity checking
    integrityVerifier := integrity.NewVerifier()
    tamperDetector := integrity.NewTamperDetector()

    return &SecureServer{
        signer:            signer,
        encryptor:         encryptor,
        auditLogger:       auditLogger,
        accessControl:     accessControl,
        rateLimiter:       rateLimiter,
        integrityVerifier: integrityVerifier,
        tamperDetector:    tamperDetector,
    }, nil
}

// cryptoSignerAdapter adapts crypto.Signer to audit.Signer
type cryptoSignerAdapter struct {
    signer crypto.Signer
}

func (a *cryptoSignerAdapter) Sign(data []byte) (string, error) {
    sig, err := a.signer.Sign(data)
    if err != nil {
        return "", err
    }
    return string(sig), nil
}

func (a *cryptoSignerAdapter) KeyID() string {
    return a.signer.KeyID()
}
```

## 2. Secure License Creation

```go
func (s *SecureServer) CreateLicense(ctx context.Context, req *CreateLicenseRequest) (*License, error) {
    // 1. Check permissions
    if err := s.accessControl.CheckPermission(req.UserID, auth.PermissionLicenseCreate); err != nil {
        // Log unauthorized attempt
        event := audit.NewEvent(
            audit.EventSecurityUnauthorized,
            audit.SeverityWarning,
            "create_license",
            "Unauthorized license creation attempt",
        ).WithActor(req.UserID, "user", req.IP).
            WithResult("failure").
            WithError("UNAUTHORIZED", err.Error())

        s.auditLogger.Log(ctx, event)
        return nil, err
    }

    // 2. Rate limit check
    if !s.rateLimiter.Allow(req.UserID) {
        event := audit.NewEvent(
            audit.EventAPIRateLimited,
            audit.SeverityWarning,
            "create_license",
            "Rate limit exceeded",
        ).WithActor(req.UserID, "user", req.IP).WithResult("failure")

        s.auditLogger.Log(ctx, event)
        return nil, errors.New("rate limit exceeded")
    }

    // 3. Create license data
    license := &License{
        ID:        generateID(),
        ProductID: req.ProductID,
        PlanID:    req.PlanID,
        // ... other fields
        CreatedAt: time.Now().UTC(),
    }

    // 4. Sign the license
    licenseData, err := json.Marshal(license)
    if err != nil {
        return nil, err
    }

    signedData, err := crypto.CreateSignedData(s.signer, licenseData)
    if err != nil {
        return nil, err
    }

    license.Signature = signedData.Signature
    license.SignatureAlgorithm = string(signedData.Algorithm)
    license.KeyID = signedData.KeyID

    // 5. Encrypt sensitive fields (if needed)
    if license.CustomerEmail != "" {
        encrypted, err := crypto.CreateEncryptedData(
            s.encryptor,
            []byte(license.CustomerEmail),
            "email-key-v1",
        )
        if err != nil {
            return nil, err
        }
        license.CustomerEmailEncrypted = encrypted.Ciphertext
    }

    // 6. Store in database (with encrypted fields)
    if err := s.storeLicense(ctx, license); err != nil {
        return nil, err
    }

    // 7. Log successful creation
    event := audit.LogLicenseCreated(
        license.ID,
        req.UserID,
        req.IP,
        map[string]interface{}{
            "product_id": req.ProductID,
            "plan_id":    req.PlanID,
        },
    )
    s.auditLogger.Log(ctx, event)

    return license, nil
}
```

## 3. Secure License Verification

```go
func (s *SecureServer) VerifyLicense(ctx context.Context, req *VerifyLicenseRequest) (*VerificationResult, error) {
    // 1. Rate limiting (prevent brute force)
    if !s.rateLimiter.Allow(req.ClientIP) {
        event := audit.NewEvent(
            audit.EventSecurityBruteForce,
            audit.SeverityCritical,
            "verify_license",
            "Potential brute force attack detected",
        ).WithActor("unknown", "client", req.ClientIP).WithResult("blocked")

        s.auditLogger.Log(ctx, event)
        return nil, errors.New("rate limit exceeded")
    }

    // 2. Run integrity checks
    tamperResult, err := s.tamperDetector.RunChecks()
    if err != nil {
        log.Printf("Integrity check error: %v", err)
    }

    if tamperResult != nil && tamperResult.TamperingDetected {
        event := audit.LogTamperingDetected(
            req.LicenseKey,
            "license",
            "Tampering detected during verification",
        )
        s.auditLogger.Log(ctx, event)
        return nil, errors.New("system integrity violation detected")
    }

    // 3. Retrieve license from database
    license, err := s.getLicense(ctx, req.LicenseKey)
    if err != nil {
        event := audit.LogVerificationFailed(req.LicenseKey, "license not found", req.ClientIP)
        s.auditLogger.Log(ctx, event)
        return nil, err
    }

    // 4. Multi-layer verification
    verification := integrity.NewMultiLayerVerification()

    // Layer 1: Signature verification
    licenseData, _ := json.Marshal(license)
    err = s.signer.Verify(licenseData, []byte(license.Signature))
    verification.AddLayer(
        "signature",
        "Verify cryptographic signature",
        err == nil,
        err,
    )

    // Layer 2: Expiration check
    notExpired := license.ExpiresAt.After(time.Now())
    verification.AddLayer(
        "expiration",
        "Check license expiration",
        notExpired,
        nil,
    )

    // Layer 3: Fingerprint check (if applicable)
    fingerprintMatch := true // Implement actual fingerprint matching
    verification.AddLayer(
        "fingerprint",
        "Verify device fingerprint",
        fingerprintMatch,
        nil,
    )

    // Layer 4: Checksum verification
    expectedChecksum := crypto.HashData(licenseData)
    checksumValid := true // Compare with stored checksum
    verification.AddLayer(
        "checksum",
        "Verify data integrity",
        checksumValid,
        nil,
    )

    // 5. Log verification attempt
    if verification.IsValid() {
        event := audit.NewEvent(
            audit.EventVerificationSucceeded,
            audit.SeverityInfo,
            "verify_license",
            "License verified successfully",
        ).WithActor("system", "system", req.ClientIP).
            WithResource(license.ID, "license").
            WithResult("success").
            WithMetadata("score", verification.Score)

        s.auditLogger.Log(ctx, event)
    } else {
        event := audit.LogVerificationFailed(
            license.ID,
            fmt.Sprintf("Verification failed with score: %.2f", verification.Score),
            req.ClientIP,
        )
        s.auditLogger.Log(ctx, event)
    }

    return &VerificationResult{
        Valid:        verification.IsValid(),
        Score:        verification.Score,
        Verification: verification,
    }, nil
}
```

## 4. Continuous Monitoring

```go
func (s *SecureServer) StartSecurityMonitoring() {
    // Start continuous tamper detection
    monitor := integrity.NewContinuousMonitor(5 * time.Minute)
    monitor.Start()

    // Handle alerts
    go func() {
        for alert := range monitor.GetAlerts() {
            // Log critical security event
            event := audit.NewEvent(
                audit.EventSecurityTampering,
                audit.SeverityCritical,
                "tampering_detected",
                fmt.Sprintf("Tampering detected: %d checks failed", alert.FailedChecks),
            ).WithResult("detected")

            for _, check := range alert.Checks {
                if !check.Passed {
                    event.WithMetadata(check.Name, check.Error)
                }
            }

            s.auditLogger.Log(context.Background(), event)

            // Send alert to administrators
            s.sendSecurityAlert(alert)
        }
    }()
}
```

## 5. Compliance Reporting

```go
func (s *SecureServer) GenerateComplianceReport(ctx context.Context, compliance string, startTime, endTime time.Time) (*audit.ComplianceReport, error) {
    // Generate report
    report, err := s.auditLogger.GenerateComplianceReport(ctx, compliance, startTime, endTime)
    if err != nil {
        return nil, err
    }

    // Log report generation
    event := audit.NewEvent(
        audit.EventAdminAction,
        audit.SeverityInfo,
        "generate_compliance_report",
        fmt.Sprintf("Generated %s compliance report", compliance),
    ).WithResult("success").
        WithMetadata("compliance", compliance).
        WithMetadata("start_time", startTime).
        WithMetadata("end_time", endTime).
        WithMetadata("total_events", report.TotalEvents)

    s.auditLogger.Log(ctx, event)

    return report, nil
}
```

## 6. Configuration File

```yaml
# config/security.yaml
security:
  # Cryptography
  signing:
    algorithm: "Ed25519"  # or "RSA-PSS"
    key_id: "primary-key-v1"
    key_rotation_days: 90
    hsm_enabled: false    # Set to true for hardware security module

  encryption:
    algorithm: "AES-256-GCM"
    key_rotation_days: 90
    kms_provider: "local" # or "aws", "azure", "vault"

  # Audit
  audit:
    enabled: true
    async: true
    buffer_size: 1000
    enable_chaining: true  # Enable tamper-proof event chaining
    retention_days: 2555   # 7 years
    siem_integration: false

  # Authentication
  authentication:
    session_timeout_minutes: 60
    refresh_token_days: 30
    mfa_required: false    # Require MFA for all users
    password_min_length: 12

  # Rate Limiting
  rate_limiting:
    enabled: true
    requests_per_minute: 100
    burst_size: 200

  # Integrity
  integrity:
    enable_tamper_detection: true
    check_interval_minutes: 5
    enable_anti_debug: false  # Enable in production

  # Compliance
  compliance:
    soc2: true
    gdpr: true
    hipaa: false
    pci_dss: false
```

## 7. Middleware Integration

```go
// Middleware for HTTP handlers
func (s *SecureServer) AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 1. Extract authentication token
        token := extractToken(r)
        if token == "" {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // 2. Validate token and get user
        user, err := s.validateToken(token)
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // 3. Add user to context
        ctx := context.WithValue(r.Context(), "user", user)

        // 4. Continue
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func (s *SecureServer) PermissionMiddleware(permission auth.Permission) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := r.Context().Value("user").(*auth.User)

            if !user.HasPermission(permission) {
                // Log unauthorized attempt
                event := audit.NewEvent(
                    audit.EventSecurityUnauthorized,
                    audit.SeverityWarning,
                    "permission_check",
                    fmt.Sprintf("User lacks permission: %s", permission),
                ).WithActor(user.ID, "user", r.RemoteAddr).
                    WithResult("denied")

                s.auditLogger.Log(r.Context(), event)

                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

func (s *SecureServer) RateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        key := r.RemoteAddr

        if !s.rateLimiter.Allow(key) {
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

## 8. Testing Security

```go
func TestSecureLicenseCreation(t *testing.T) {
    server := setupTestServer(t)

    // Test 1: Unauthorized access
    req := &CreateLicenseRequest{
        UserID: "unauthorized-user",
        // ...
    }
    _, err := server.CreateLicense(context.Background(), req)
    assert.Error(t, err)

    // Test 2: Rate limiting
    for i := 0; i < 150; i++ {
        _, err := server.CreateLicense(context.Background(), req)
        if i >= 100 {
            assert.Error(t, err) // Should be rate limited
        }
    }

    // Test 3: Signature verification
    license, err := server.CreateLicense(context.Background(), req)
    assert.NoError(t, err)

    // Tamper with license
    license.ExpiresAt = time.Now().Add(365 * 24 * time.Hour)

    // Verification should fail
    result, err := server.VerifyLicense(context.Background(), &VerifyLicenseRequest{
        LicenseKey: license.Key,
    })
    assert.False(t, result.Valid)
}
```

## Next Steps

1. **Key Management**: Set up proper key storage (HSM/KMS)
2. **SIEM Integration**: Connect audit logs to your SIEM
3. **Monitoring**: Set up alerts for security events
4. **Penetration Testing**: Conduct regular security assessments
5. **Compliance**: Implement compliance-specific controls
6. **Backup**: Set up encrypted backup procedures
7. **Incident Response**: Create incident response playbooks
8. **Documentation**: Document security procedures

## Security Checklist

- [ ] All signing keys stored securely (HSM/KMS)
- [ ] Encryption keys rotated regularly
- [ ] Audit logging enabled and monitored
- [ ] Rate limiting configured
- [ ] Tamper detection active
- [ ] All API endpoints require authentication
- [ ] RBAC implemented for all operations
- [ ] MFA enabled for admin accounts
- [ ] TLS 1.3 enforced
- [ ] Regular security testing scheduled
- [ ] Compliance reports generated monthly
- [ ] Incident response plan documented
- [ ] Security training completed
