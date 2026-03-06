# Production Deployment Security Checklist

## Pre-Deployment Security Audit

### 1. Cryptography ✓

- [ ] All signing keys generated securely
- [ ] Private keys stored in HSM or secure key management system
- [ ] Key rotation policy implemented (90 days recommended)
- [ ] Encryption keys are 256-bit or higher
- [ ] All cryptographic operations use approved algorithms:
  - Signing: Ed25519 or RSA-PSS (4096-bit)
  - Encryption: AES-256-GCM
  - Hashing: SHA-256 or SHA-512
- [ ] No hardcoded keys in source code
- [ ] Key backup and recovery procedures documented
- [ ] Key access logs enabled and monitored

**Verification Commands:**
```bash
# Check for hardcoded keys
git grep -i "private.*key" --and --not -e "test" --not -e "example"
git grep -i "secret" --and --not -e "test" --not -e "example"

# Verify key permissions
ls -la /path/to/keys/
# Should be 400 or 600, owned by application user
```

### 2. Audit Logging ✓

- [ ] Audit logging enabled for all environments
- [ ] Immutable storage configured
- [ ] Event chaining enabled for tamper detection
- [ ] Logs include all security-relevant events:
  - Authentication attempts
  - Authorization failures
  - License operations
  - Configuration changes
  - Security incidents
- [ ] Log retention policy implemented (7 years for compliance)
- [ ] SIEM integration configured
- [ ] Real-time alerting for critical events
- [ ] Log backup and archival automated
- [ ] Log access restricted to authorized personnel

**Verification Commands:**
```bash
# Test audit logging
curl -X POST https://api.example.com/test-audit
# Check database for audit entry
sqlite3 audit.db "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 1;"

# Verify log permissions
ls -la /var/log/licensing/
```

### 3. Authentication & Authorization ✓

- [ ] Strong password policy enforced (min 12 characters)
- [ ] Multi-factor authentication (MFA) enabled for admin accounts
- [ ] API keys use secure random generation
- [ ] API key rotation policy implemented
- [ ] Role-based access control (RBAC) configured
- [ ] Principle of least privilege applied
- [ ] Session timeouts configured (60 minutes recommended)
- [ ] Refresh token rotation implemented
- [ ] Account lockout after failed attempts (5 attempts)
- [ ] Password hashing uses Argon2id
- [ ] No default credentials in production

**Verification Commands:**
```bash
# Test password policy
curl -X POST https://api.example.com/auth/register \
  -d '{"password":"weak"}'
# Should reject

# Test rate limiting
for i in {1..150}; do
  curl -X POST https://api.example.com/auth/login \
    -d '{"username":"test","password":"wrong"}'
done
# Should rate limit after 100 requests
```

### 4. Network Security ✓

- [ ] TLS 1.3 enforced (TLS 1.2 minimum)
- [ ] Strong cipher suites configured
- [ ] Certificate pinning implemented in clients
- [ ] HSTS header configured
- [ ] Certificate auto-renewal configured
- [ ] OCSP stapling enabled
- [ ] Perfect forward secrecy enabled
- [ ] mTLS configured for server-to-server communication
- [ ] API endpoints use HTTPS only
- [ ] Firewall rules configured (allow only necessary ports)

**Verification Commands:**
```bash
# Test TLS configuration
nmap --script ssl-enum-ciphers -p 443 api.example.com

# Test SSL/TLS
testssl.sh https://api.example.com

# Verify HSTS
curl -I https://api.example.com | grep -i strict-transport-security
```

### 5. Database Security ✓

- [ ] Database encryption at rest enabled
- [ ] Field-level encryption for sensitive data
- [ ] Database access restricted (no public access)
- [ ] Strong database passwords (min 20 characters)
- [ ] Database user privileges minimized
- [ ] SQL injection prevention verified
- [ ] Prepared statements used for all queries
- [ ] Database backups encrypted
- [ ] Backup restoration tested
- [ ] Database audit logging enabled

**Verification Commands:**
```bash
# Check database permissions
sudo -u postgres psql -c "\du"

# Test SQL injection
sqlmap -u "https://api.example.com/licenses?id=1" --batch --random-agent

# Verify encryption
sqlite3 data.db "PRAGMA cipher_version;"
```

### 6. API Security ✓

- [ ] Rate limiting implemented (100 req/min recommended)
- [ ] Request size limits enforced
- [ ] Input validation on all endpoints
- [ ] Output sanitization implemented
- [ ] CORS policy configured correctly
- [ ] API versioning implemented
- [ ] Deprecated endpoints removed
- [ ] Error messages don't leak sensitive information
- [ ] Request/response logging enabled
- [ ] API documentation access controlled

**Verification Commands:**
```bash
# Test rate limiting
ab -n 1000 -c 10 https://api.example.com/api/v1/licenses

# Test input validation
curl -X POST https://api.example.com/api/v1/licenses \
  -H "Content-Type: application/json" \
  -d '{"invalid": "../../etc/passwd"}'

# Test CORS
curl -H "Origin: https://malicious.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS https://api.example.com/api/v1/licenses
```

### 7. Application Security ✓

- [ ] Dependency scanning automated
- [ ] No known vulnerabilities in dependencies
- [ ] Security headers configured:
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - X-XSS-Protection: 1; mode=block
  - Content-Security-Policy configured
- [ ] CSRF protection implemented
- [ ] XSS prevention verified
- [ ] File upload validation (if applicable)
- [ ] Code obfuscation applied to clients
- [ ] Debug mode disabled in production
- [ ] Stack traces hidden from users
- [ ] Sensitive data not logged

**Verification Commands:**
```bash
# Dependency scanning
go list -m all | nancy sleuth

# Security headers check
curl -I https://api.example.com | grep -E "X-Frame|X-Content|X-XSS|Content-Security"

# Check for debug mode
grep -r "DEBUG.*true" config/
```

### 8. Integrity & Tampering ✓

- [ ] Code signing enabled for all binaries
- [ ] Tamper detection active
- [ ] Anti-debugging measures enabled (production only)
- [ ] Binary integrity verification implemented
- [ ] Runtime integrity checks active
- [ ] Continuous monitoring enabled
- [ ] License signature verification working
- [ ] Event chaining for audit logs enabled
- [ ] File integrity monitoring configured

**Verification Commands:**
```bash
# Verify code signing
codesign -vv /path/to/binary

# Test tamper detection
./test-tampering.sh

# Verify checksums
sha256sum -c checksums.txt
```

### 9. Infrastructure Security ✓

- [ ] OS and packages up to date
- [ ] Unnecessary services disabled
- [ ] Root login disabled
- [ ] SSH key-based authentication only
- [ ] Firewall configured (UFW/iptables)
- [ ] Fail2ban or similar intrusion prevention installed
- [ ] File permissions properly set (principle of least privilege)
- [ ] Application runs as non-root user
- [ ] Disk encryption enabled
- [ ] Secure boot enabled (if applicable)

**Verification Commands:**
```bash
# Check for updates
sudo apt update && sudo apt list --upgradable

# Verify SSH config
grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config

# Check firewall
sudo ufw status verbose

# Verify user permissions
id licensing-app
```

### 10. Monitoring & Incident Response ✓

- [ ] Real-time security monitoring active
- [ ] Anomaly detection configured
- [ ] Alert rules defined for:
  - Failed authentication attempts
  - Privilege escalation attempts
  - Unusual access patterns
  - System integrity violations
  - License tampering attempts
- [ ] Incident response plan documented
- [ ] Security team contacts configured
- [ ] Automated response playbooks active
- [ ] Regular security reviews scheduled
- [ ] Penetration testing completed

**Verification Commands:**
```bash
# Test alerting
./trigger-security-alert.sh

# Check monitoring
curl https://api.example.com/health/security

# Review alert rules
cat /etc/alerting/rules.yaml
```

### 11. Compliance ✓

- [ ] SOC 2 controls implemented (if required)
- [ ] GDPR compliance verified (if handling EU data)
- [ ] HIPAA compliance verified (if handling health data)
- [ ] PCI DSS compliance verified (if handling payment data)
- [ ] Data retention policy implemented
- [ ] Right to deletion implemented (GDPR)
- [ ] Data portability supported (GDPR)
- [ ] Privacy policy published
- [ ] Terms of service published
- [ ] Cookie consent implemented (if applicable)

**Verification:**
```bash
# Generate compliance report
./generate-compliance-report.sh SOC2 2024-01-01 2024-12-31

# Test data deletion
curl -X DELETE https://api.example.com/api/v1/users/123/data
```

### 12. Backup & Recovery ✓

- [ ] Automated backups configured
- [ ] Backup encryption enabled
- [ ] Backup integrity verified regularly
- [ ] Recovery procedures documented
- [ ] Recovery tested successfully
- [ ] Backup retention policy implemented
- [ ] Off-site backup storage configured
- [ ] Database point-in-time recovery available
- [ ] Disaster recovery plan documented
- [ ] RTO and RPO defined and achievable

**Verification Commands:**
```bash
# Test backup
./backup.sh

# Test restore
./restore.sh --dry-run

# Verify backup encryption
gpg --decrypt backup.gpg > /dev/null
```

## Deployment Checklist

### Pre-Deployment

- [ ] Security audit completed
- [ ] All tests passing (unit, integration, security)
- [ ] Code review completed
- [ ] Staging environment tested
- [ ] Performance testing completed
- [ ] Load testing completed
- [ ] Documentation updated
- [ ] Rollback plan prepared

### Deployment

- [ ] Maintenance window scheduled
- [ ] Users notified (if applicable)
- [ ] Database migrations tested
- [ ] Configuration files reviewed
- [ ] Environment variables set correctly
- [ ] Secrets properly secured
- [ ] Service dependencies available
- [ ] Health checks configured

### Post-Deployment

- [ ] Application started successfully
- [ ] Health checks passing
- [ ] Monitoring dashboards reviewed
- [ ] Log aggregation working
- [ ] Alerting functioning
- [ ] Performance metrics normal
- [ ] No critical errors in logs
- [ ] User acceptance testing passed
- [ ] Rollback plan ready if needed
- [ ] Post-deployment report completed

## Continuous Security

### Daily

- [ ] Review security alerts
- [ ] Check system health
- [ ] Review failed authentication attempts
- [ ] Monitor error rates

### Weekly

- [ ] Review audit logs
- [ ] Check for security updates
- [ ] Review access logs
- [ ] Update threat intelligence

### Monthly

- [ ] Security patch deployment
- [ ] Access review (remove unused accounts)
- [ ] Certificate expiration check
- [ ] Compliance report generation
- [ ] Security metrics review

### Quarterly

- [ ] Penetration testing
- [ ] Vulnerability assessment
- [ ] Security training
- [ ] Disaster recovery drill
- [ ] Incident response drill

### Annually

- [ ] Full security audit
- [ ] Key rotation
- [ ] Policy review and update
- [ ] Third-party security assessment
- [ ] Compliance certification renewal

## Security Metrics

Track these metrics for continuous improvement:

1. **Authentication Metrics**
   - Failed login attempts
   - MFA adoption rate
   - Password reset frequency

2. **Authorization Metrics**
   - Unauthorized access attempts
   - Permission changes
   - Privilege escalation attempts

3. **License Security Metrics**
   - Signature verification failures
   - Tampering detection events
   - License activation failures

4. **System Security Metrics**
   - Intrusion attempts
   - Vulnerability count
   - Patch deployment time
   - Mean time to detect (MTTD)
   - Mean time to respond (MTTR)

5. **Compliance Metrics**
   - Audit log completeness
   - Policy violations
   - Data retention compliance
   - Incident response time

## Emergency Contacts

**Security Incident Response**
- Primary: security-team@company.com
- Phone: +1-XXX-XXX-XXXX (24/7)
- Slack: #security-incidents

**On-Call Engineers**
- Primary: oncall-primary@company.com
- Secondary: oncall-backup@company.com

**Management Escalation**
- CTO: cto@company.com
- CISO: ciso@company.com

## Document Control

- **Version**: 1.0
- **Last Updated**: December 8, 2024
- **Next Review**: March 8, 2025
- **Owner**: Security Team
- **Approver**: CISO
