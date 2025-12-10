package licensing

import "embed"

// TemplatesFS holds embedded email templates
// This allows the server to run as a standalone binary with templates compiled in.
//
//go:embed templates/email/*.html
var TemplatesFS embed.FS
