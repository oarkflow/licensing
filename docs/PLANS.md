# Product Plans

Plans are data, not built-in code. The server starts with an empty catalog and
expects operators to create product plans through the Admin UI/API or explicit
SQL seed files.

## Plan Fields

| Field | Purpose |
| --- | --- |
| `product_id` | Product the plan belongs to. |
| `name` / `slug` | Human and API identifiers. |
| `price` | Total plan price in cents. |
| `price_per_device` | Per-device price in cents when relevant. |
| `min_devices` / `max_devices` | Allowed activation seat range. |
| `duration_days` | Default license duration. |
| `billing_cycle` | `monthly`, `yearly`, `weekly`, `lifetime`, or `one-time`. |
| `trial_days` | Optional trial duration for this plan. |
| `is_trial` | Marks an explicit trial-only plan. |
| `is_active` | Controls whether new licenses/subscriptions can use the plan. |

## Trials

`trial_days` is independent of `is_trial`. A paid plan can have `trial_days > 0`
and be issued as a trial by upgrade/provisioning flows. `is_trial` remains for
dedicated free trial plans.

## Optional SQL Seeds

Use SQL seeds only when you intentionally want to preload a catalog:

```bash
migrator cli seed --include-raw=true --file=001_optional_catalog_seed.sql
```

Runtime startup does not execute seed files.
