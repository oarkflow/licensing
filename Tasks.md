I want to build Subscription management platform in licensing. I am looking for a subscription management platform so that future customers can easily pay, cancel, and renew their plans automatically. I want to avoid having to reach out to users manually via email or phone to collect payments. Supporting various payment gateways for the payment based on the client, support reliable automated recurring billing, reminder, approval system. Create Tasks.md and start working.

Continue working based on Tasks.md and make sure not to stop until everything is implemented.

# Production Device Management Tasks

## Protocol and Documentation
- [x] Document canonical device fingerprint as `fp:v2:<alg>:SHA256(device_proof_public_key)`.
- [x] Add versioned hardware fingerprint format `hw:v1:<hash>`.
- [x] Clarify that hardware fingerprinting is diagnostic/risk metadata, not the authorization root.
- [x] Document diagnostic hardware metadata in device proof attestation.
- [ ] Regenerate SDK fixtures after the replacement-token activation flow is finalized.

## Device Schema and Storage
- [x] Add device lifecycle fields to `LicenseDevice`.
- [x] Persist lifecycle fields in SQLite and in-memory storage.
- [x] Add admin-issued device replacement token storage.
- [x] Treat existing devices as `trusted` by default.

## Device Management API
- [x] Add per-device revoke endpoint.
- [x] Add per-device reinstate endpoint.
- [x] Add replacement token issue endpoint.
- [x] Add replacement token list endpoint.
- [x] Keep hard delete endpoint for administrative cleanup.

## Activation and Verification
- [x] Require trusted device state for verification.
- [x] Reject revoked, replaced, and suspicious devices.
- [x] Allow one-time replacement token to bind a new proof-key fingerprint.
- [x] Mark old device as `replaced` and new device as `trusted` after successful replacement.
- [x] Carry diagnostic hardware fingerprint, label, and app version into device records.

## Client SDK
- [x] Add replacement-token activation helper.
- [x] Include diagnostic hardware fingerprint metadata in device proof attestation.
- [x] Include per-component hardware confidence metadata in device proof attestation.
- [x] Send app version as an explicit request header.

## Fingerprint Robustness
- [x] Enforce two-layer identity: proof-key fingerprint for authorization, hardware fingerprint for drift/risk.
- [x] Accept legacy raw SHA-256 fingerprints while emitting versioned `fp:v2` fingerprints from new clients.
- [x] Exclude hostname, MAC, IP address, CPU brand, container ID, pod UID, and pod name from canonical identity.
- [x] Prefer mounted persistent device keys and mounted volume/PVC marker files for container diagnostics.
- [x] Persist container proof keys through explicit application config or `--device-key-file`, not environment variables.
- [x] Ignore environment variables for device proof key selection and diagnostic hardware identifiers.
- [x] Add deterministic tests for proof-key identity, hardware diagnostics, confidence ordering, and container fallback behavior.

## Admin UI
- [x] Show device status and proof metadata in license detail.
- [x] Add revoke and reinstate device actions.
- [x] Add issue replacement token action.
- [x] Show replacement token history.

## Tests and Acceptance
- [x] Add unit tests for replacement token success/failure cases.
- [x] Add SQLite tests for lifecycle columns and replacement-token table creation.
- [x] Add handler tests for admin device lifecycle endpoints.
- [x] Run focused Go and frontend checks.

# Subscription Management Platform Tasks

## Billing Domain and Storage
- [x] Define gateway-agnostic billing records for payment gateways, payment methods, invoices, payment attempts, and approval requests.
- [x] Add SQLite schema for gateway configs, customer payment methods, invoices, payment retries, and approval workflows.
- [x] Add SQLite persistence methods and round-trip tests for the billing foundation.
- [x] Extend persistent/in-memory storage interfaces for the new billing records.
- [x] Add subscription fields for auto-renewal, collection method, gateway customer/subscription IDs, quantity, grace period, failure count, reminder state, and approval status.

## Payment Gateway Abstraction
- [x] Define a provider adapter interface for checkout/session creation, payment method setup, recurring subscription sync, payment capture, cancellation, and webhook verification.
- [x] Implement a manual/offline gateway for clients that require bank transfer, purchase order, or approval-before-payment workflows.
- [x] Implement Stripe adapter support.
- [x] Add extension points for PayPal/Razorpay/eSewa/Khalti or client-specific gateways without changing subscription lifecycle logic.

## Recurring Billing Automation
- [x] Add billing scheduler for upcoming renewals, due invoices, failed payment retries, grace-period expiry, and subscription renewal completion.
- [ ] Generate invoices from active subscriptions using plan price, quantity/devices, coupons, tax hooks, and billing cycle.
- [x] Automatically renew licenses after successful payment.
- [x] Pause, cancel, expire, or revoke subscription-linked licenses based on billing outcome and configured grace period.

## Customer Self-Service
- [x] Add customer endpoints for viewing current plan, invoices, payment methods, renewal date, and subscription status.
- [x] Add customer checkout/payment-method setup flow.
- [x] Add self-service cancel, resume, and renew endpoints with policy controls.
- [x] Add hosted invoice/payment links where supported by the selected gateway.

## Reminders and Notifications
- [ ] Add renewal reminder templates.
- [ ] Add payment failure and retry reminder templates.
- [ ] Add cancellation, renewal success, invoice paid, and grace-period expiry templates.
- [x] Queue reminder emails from billing scheduler using the existing email queue.

## Approval System
- [x] Add approval request lifecycle APIs for pending, approved, rejected, and expired decisions.
- [x] Support payment method approvals and manual invoice/payment approvals.
- [x] Record approval decisions in audit events.
- [ ] Notify customers/admins when approvals are requested or decided.

## Admin UI
- [x] Add billing gateway configuration screens.
- [ ] Add subscription detail billing timeline with invoices, attempts, reminders, and approvals.
- [x] Add invoice list and invoice detail screens.
- [x] Add approval queue with approve/reject actions.
- [ ] Add customer payment method visibility and administrative disable controls.

## Webhooks and Reconciliation
- [x] Add webhook ingestion table and idempotency handling.
- [x] Verify gateway webhook signatures.
- [ ] Reconcile gateway invoice/payment/subscription events to local invoices, attempts, subscriptions, and licenses.
- [x] Add admin reconciliation tools for out-of-sync records.

## Security, Compliance, and Operations
- [ ] Store gateway credentials securely and avoid persisting raw card/bank details.
- [x] Add RBAC permissions for billing read/write, gateway admin, approval decisions, and refund/cancel actions.
- [x] Add audit events for billing configuration, invoice, payment, subscription, and approval changes.
- [x] Add operational runbook for failed billing jobs, webhook replay, gateway outage, and manual collection fallback.
