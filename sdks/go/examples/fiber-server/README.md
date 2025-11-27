# Fiber Server Example with License Protection

This example demonstrates how to integrate the Go Licensing SDK into a [GoFiber](https://gofiber.io/) web application with:

- License activation and verification
- License-protected API routes
- Feature-gated endpoints
- Scope-based permission checking
- Background license verification

## Prerequisites

1. **License Server Running**: Start the license server first:
   ```bash
   cd /path/to/licensing
   go run cmd/server/main.go
   ```

2. **Create Client & License**: Use the admin API to create a client and license:
   ```bash
   # Get the bootstrap API key from server logs
   API_KEY="your-bootstrap-key"

   # Create a client
   curl -X POST http://localhost:8801/api/clients \
     -H "Content-Type: application/json" \
     -H "X-API-Key: $API_KEY" \
     -d '{
       "id": "client-123",
       "name": "Test Client",
       "email": "user@example.com"
     }'

   # Create a license
   curl -X POST http://localhost:8801/api/licenses \
     -H "Content-Type: application/json" \
     -H "X-API-Key: $API_KEY" \
     -d '{
       "client_id": "client-123",
       "plan_slug": "professional",
       "max_devices": 5,
       "expires_at": "2026-01-01T00:00:00Z"
     }'
   ```

3. **Note the License Key**: Copy the `license_key` from the response.

## Running the Example

```bash
cd sdks/go/examples/fiber-server

# Install dependencies
go mod tidy

# Run with license credentials
go run main.go \
  --license-key "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" \
  --email "user@example.com" \
  --client-id "client-123"
```

### Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://localhost:8801` | License server URL |
| `--license-key` | (required) | License key for activation |
| `--email` | (required) | Email for activation |
| `--client-id` | (required) | Client ID for activation |
| `--http` | `:3000` | HTTP server address |
| `--config-dir` | `~/.myapp-example` | Configuration directory |

## API Endpoints

### Public Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Welcome message |
| GET | `/health` | Health check with license status |
| GET | `/license` | License information |

### Protected Endpoints (require valid license)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/data` | Basic protected data |
| GET | `/api/entitlements` | View all entitlements |

### Feature-Gated Endpoints

| Method | Path | Required Feature |
|--------|------|------------------|
| GET | `/api/gui` | `gui` |
| GET | `/api/cli` | `cli` |
| GET | `/api/premium` | `premium` |

### Scope-Gated Endpoints

| Method | Path | Required Scope |
|--------|------|----------------|
| GET | `/api/secrets` | `gui:list` |
| POST | `/api/secrets` | `gui:create` |
| PUT | `/api/secrets/:id` | `gui:update` |
| DELETE | `/api/secrets/:id` | `gui:delete` |

## Testing the Endpoints

```bash
# Health check
curl http://localhost:3000/health

# License info
curl http://localhost:3000/license

# Protected endpoint
curl http://localhost:3000/api/data

# Feature-gated endpoint
curl http://localhost:3000/api/gui

# Scope-gated endpoint
curl http://localhost:3000/api/secrets

# Create secret (if gui:create scope is allowed)
curl -X POST http://localhost:3000/api/secrets

# View entitlements
curl http://localhost:3000/api/entitlements
```

## Code Structure

### LicenseMiddleware

The `LicenseMiddleware` struct provides reusable middleware functions:

```go
type LicenseMiddleware struct {
    client  *licensing.Client
    license *licensing.LicenseData
}
```

### Available Middleware

1. **`RequireLicense()`** - Ensures a valid license exists
2. **`RequireFeature(featureSlug)`** - Checks if a feature is enabled
3. **`RequireScope(featureSlug, scopeSlug)`** - Checks if a scope is allowed
4. **`RequireScopeWithLimit(featureSlug, scopeSlug)`** - Checks scope and provides limit info

### Usage Example

```go
// Apply license check to all /api routes
api := app.Group("/api", lm.RequireLicense())

// Feature-gated route
api.Get("/premium", lm.RequireFeature("premium"), handler)

// Scope-gated route
api.Post("/secrets", lm.RequireScope("gui", "create"), handler)
```

## Setting Up Product Features

To use feature and scope gating, configure your product in the license server:

```bash
API_KEY="your-api-key"

# Create product
curl -X POST http://localhost:8801/api/products \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SecretR",
    "slug": "secretr",
    "description": "Secret management system"
  }'

# Create features
curl -X POST http://localhost:8801/api/products/PRODUCT_ID/features \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "GUI",
    "slug": "gui",
    "category": "interface"
  }'

# Add scopes to feature
curl -X POST http://localhost:8801/api/products/PRODUCT_ID/features/FEATURE_ID/scopes \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "List",
    "slug": "list",
    "permission": "allow"
  }'

# Create plan and link features
# ... see SDK documentation for full setup
```

## Background Verification

The example automatically starts background license verification:

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
go client.StartBackgroundVerification(ctx)
```

This respects the `check_mode` configured for the license (e.g., `monthly`, `yearly`, `custom`).

## Error Responses

### License Invalid (403)
```json
{
  "error": "license_invalid",
  "message": "Valid license required to access this resource"
}
```

### Feature Disabled (403)
```json
{
  "error": "feature_disabled",
  "message": "Feature 'premium' is not enabled for your plan",
  "feature": "premium",
  "plan": "starter"
}
```

### Scope Denied (403)
```json
{
  "error": "scope_denied",
  "message": "Scope 'gui:delete' is not allowed for your plan",
  "feature": "gui",
  "scope": "delete",
  "plan": "basic"
}
```

## License

MIT License - see the main project LICENSE file.
