# Entitlement Scopes

Entitlement scopes are product-defined permissions attached to features. The
license server does not ship a built-in scope catalog. Admins define products,
plans, features, scopes, and plan-feature mappings through the Admin UI/API or
through explicitly executed SQL seed files.

## Runtime Shape

Licenses expose computed entitlements in this form:

```json
{
  "entitlements": {
    "product_id": "product-id",
    "product_slug": "product-slug",
    "plan_id": "plan-id",
    "plan_slug": "plan-slug",
    "features": {
      "feature-slug": {
        "feature_id": "feature-id",
        "feature_slug": "feature-slug",
        "enabled": true,
        "scopes": {
          "scope-slug": {
            "scope_id": "scope-id",
            "scope_slug": "scope-slug",
            "permission": "allow"
          }
        }
      }
    }
  }
}
```

## Scope Metadata

Scope rows can include metadata to improve Admin UI grouping and labels:

```json
{
  "category": "Runtime",
  "label": "Start Server",
  "description": "Allows the application runtime to start"
}
```

If metadata is omitted, the UI derives labels from slugs and groups scopes under
the feature name.

## Source Of Truth

The database is the source of truth:

- `products` define licensed applications or modules.
- `plans` define sellable tiers for a product.
- `features` define coarse-grained capabilities.
- `feature_scopes` define fine-grained permissions.
- `plan_features.scope_overrides` controls plan-specific allow/deny/limit behavior.

The server no longer applies product-specific plan slug gates in code. If a
scope should be denied for a plan, store that deny rule in `plan_features`.
