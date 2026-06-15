# Billing Operations Runbook

## Daily Jobs

Run these actions from the admin Billing page or POST `/api/billing/jobs`:

- `generate_invoices`: creates renewal invoices for active auto-renewing subscriptions due by `due_before`.
- `process_due`: attempts collection for due invoices through the configured gateway adapter.
- `queue_reminders`: queues renewal and payment retry reminders through the existing email queue.

## Failed Billing

1. Open Admin > Billing.
2. Search invoices by `subscription_id` or `client_id`.
3. Review invoice status, attempt count, and next retry time.
4. For manual/offline payments, mark the invoice paid after finance approval or settlement.
5. If payment remains failed past the configured grace period, the subscription is expired and the linked license is revoked.

## Manual Collection Fallback

Use a `manual` payment gateway for bank transfer, purchase order, or approval-first customers.

- Gateway configs can require approval.
- Manual invoices remain pending until marked paid or rejected through metadata/webhook/admin action.
- Approval requests are listed in Admin > Billing.

## Gateway Outage

1. Disable the affected gateway configuration.
2. Switch impacted subscriptions to `manual` collection when needed.
3. Queue reminders after invoices are generated.
4. Replay provider webhooks after the gateway recovers. Webhook events are idempotent by `(gateway_id, event_id)`.

## Webhook Replay

POST the original payload to `/api/billing/webhooks/{gateway_id}` with the provider signature header.

- Stripe-compatible signatures are read from `Stripe-Signature`.
- Generic integrations can use `X-Webhook-Signature`.
- Duplicate events return the existing event instead of reprocessing.
