# Transfer Entitlements

Transfer-style capabilities should be modeled as ordinary product features and
scopes. They are not built into the license server and are not tied to a fixed
product ID, feature ID, or plan slug.

## Suggested Modeling

Create a feature such as `transfer` or add transfer scopes under an existing
product-specific feature, then attach scopes such as:

- `devices:list`
- `devices:trust`
- `devices:revoke`
- `transfer:initiate`
- `transfer:status`
- `history:list`
- `history:detail`

Use `feature_scopes.metadata.category` to group these in the Admin UI.

## Plan Access

Grant or deny transfer access through `plan_features.scope_overrides`. The
server will compute entitlements from the stored plan-feature mapping and will
not apply fixed product or plan assumptions.
