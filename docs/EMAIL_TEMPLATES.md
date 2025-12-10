# Email Templates - Embedded & Runtime Loading

The email template loader supports both **embedded templates** (compiled into the binary) and **filesystem templates** (loaded at runtime).

## How It Works

### Priority Order

The loader attempts to find templates in this order:

1. **Embedded templates** (if provided via `embed.FS`)
2. **Environment variable** `EMAIL_TEMPLATES_DIR` (explicit override)
3. **Executable directory** (`/path/to/binary/templates/email`)
4. **Working directory tree** (searches up for `templates/email`)
5. **Relative fallback** (`./templates/email`)

## Usage

### Standalone Binaries (Recommended for Production)

Templates are automatically embedded when you build the server:

```go
// Templates are embedded via licensing.TemplatesFS
server, err := licensing.NewLicenseServer(/* ... */)
// Server will use embedded templates automatically
```

**Build your binary:**

```bash
go build -o licensing-server ./cmd/main.go
```

The compiled binary includes templates and works without external files.

### Custom/Override Templates at Runtime

Set the environment variable to use custom templates:

```bash
export EMAIL_TEMPLATES_DIR=/opt/myapp/custom-templates/email
./licensing-server
```

### Development Mode

When running from source (`go run`), the loader automatically finds templates in the repository:

```bash
go run ./cmd/main.go
# Finds templates in ./templates/email
```

## Template Files

Templates must be HTML files in the `templates/email` directory:

- `welcome_email.html`
- `license_email.html`

## Testing

Run tests to verify both modes work:

```bash
# Test embedded templates
go test ./pkg/licensing -run TestEmailTemplateLoaderEmbedded -v

# Test filesystem fallback
go test ./pkg/licensing -run TestEmailTemplateLoaderFilesystemFallback -v
```

## Production Deployment

### Option 1: Standalone Binary (Recommended)

Build and deploy the binary with embedded templates:

```bash
go build -ldflags="-s -w" -o licensing-server ./cmd/main.go
./licensing-server
```

No external template files needed.

### Option 2: Binary + External Templates

Deploy with custom templates alongside the binary:

```
/opt/licensing/
  ├── licensing-server (binary)
  └── templates/
      └── email/
          ├── welcome_email.html
          └── license_email.html
```

Templates next to the binary are automatically detected.

### Option 3: Containerized Deployment

**Dockerfile example:**

```dockerfile
FROM golang:1.21 AS builder
WORKDIR /build
COPY . .
RUN go build -o licensing-server ./cmd/main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/licensing-server .
# Templates are embedded, no COPY needed
EXPOSE 6601
CMD ["./licensing-server"]
```

Or override with mounted templates:

```dockerfile
# ... (same as above)
COPY templates /app/templates
ENV EMAIL_TEMPLATES_DIR=/app/templates/email
CMD ["./licensing-server"]
```

## Advanced: Custom embed.FS

To use your own embedded templates:

```go
import "embed"

//go:embed my-templates/*.html
var customTemplates embed.FS

loader := licensing.NewEmailTemplateLoader(customTemplates)
loader.LoadTemplates()
```

## Troubleshooting

**Templates not loading?**

1. Check binary was built with templates: `strings licensing-server | grep "welcome_email"`
2. Verify embed directive: `//go:embed templates/email/*.html` (no space after `//`)
3. Run with debug env: `EMAIL_TEMPLATES_DIR=/path/to/templates ./licensing-server`

**Which templates are being used?**

The loader silently prefers embedded templates. To force filesystem templates, don't pass `embed.FS`:

```go
loader := licensing.NewEmailTemplateLoader() // no embed.FS = filesystem only
```
