# CORS Configuration

The backend now supports CORS (Cross-Origin Resource Sharing) to allow frontend applications to communicate with the API.

## Configuration

CORS can be configured using the `LICENSE_SERVER_ALLOWED_ORIGINS` environment variable.

### Environment Variable

```bash
LICENSE_SERVER_ALLOWED_ORIGINS="http://localhost:5173,http://localhost:3000,https://your-production-domain.com"
```

### Default Origins

If no environment variable is set, the following default origins are allowed:
- `http://localhost:5173` (Vite default port)
- `http://localhost:3000` (Common React port)
- `http://localhost:8080` (Common development port)

## CORS Headers

The backend sets the following CORS headers:

- `Access-Control-Allow-Origin`: The requesting origin (if allowed)
- `Access-Control-Allow-Methods`: `GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Headers`: `Content-Type, Authorization, X-API-Key, X-Device-Fingerprint, X-License-Key, X-License-Secure, Cookie`
- `Access-Control-Allow-Credentials`: `true`
- `Access-Control-Max-Age`: `86400` (24 hours)

## Implementation Details

### Licensing Server

The main licensing server (`pkg/licensing/server.go`) includes CORS middleware that:
1. Checks the `Origin` header from incoming requests
2. Validates the origin against the allowed origins list
3. Sets appropriate CORS headers
4. Handles OPTIONS requests for preflight

### Web Server

The web server (`pkg/web/server.go`) also includes CORS middleware with the same configuration for handling React frontend API requests.

## Testing

To test CORS functionality:

1. Start the backend server
2. Make a request from a frontend application running on one of the allowed origins
3. Verify that the response includes the correct CORS headers
4. Test both regular requests and OPTIONS preflight requests

## Troubleshooting

If you encounter CORS issues:

1. **Check the origin**: Ensure your frontend URL is in the allowed origins list
2. **Check credentials**: If using cookies or authentication, ensure `Access-Control-Allow-Credentials` is set to `true`
3. **Check headers**: Ensure all required headers are included in `Access-Control-Allow-Headers`
4. **Check environment**: Verify the `LICENSE_SERVER_ALLOWED_ORIGINS` environment variable is set correctly

## Security Considerations

- The CORS implementation validates origins before setting headers
- Wildcard origins (`*`) are only used when no origin header is present (non-browser clients)
- Credentialed requests require specific origin validation
- Default origins are development-focused; always configure production origins explicitly
