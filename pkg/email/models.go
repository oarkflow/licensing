package email

import "time"

// ProviderType enumerates supported upstream email services.
type ProviderType string

const (
	ProviderTypeSMTP     ProviderType = "smtp"
	ProviderTypeSendGrid ProviderType = "sendgrid"
	ProviderTypeSES      ProviderType = "ses"
	ProviderTypeCustom   ProviderType = "custom"
)

// EmailProvider describes a configured upstream integration along with retry rules.
type EmailProvider struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Slug           string            `json:"slug"`
	Type           ProviderType      `json:"type"`
	Config         map[string]any    `json:"config"`
	Priority       int               `json:"priority"`
	MaxRetries     int               `json:"max_retries"`
	RetryBaseMS    int               `json:"retry_base_ms"`
	RetryMaxMS     int               `json:"retry_max_ms"`
	RetryJitterPct float64           `json:"retry_jitter_pct"`
	IsDefault      bool              `json:"is_default"`
	Enabled        bool              `json:"enabled"`
	SuccessCount   int64             `json:"success_count"`
	FailureCount   int64             `json:"failure_count"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// Clone returns a deep copy of the provider.
func (p *EmailProvider) Clone() *EmailProvider {
	if p == nil {
		return nil
	}
	clone := *p
	if p.Config != nil {
		clone.Config = make(map[string]any, len(p.Config))
		for k, v := range p.Config {
			clone.Config[k] = v
		}
	}
	if p.Metadata != nil {
		clone.Metadata = make(map[string]string, len(p.Metadata))
		for k, v := range p.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

// EmailTemplate represents a reusable subject/body pair.
type EmailTemplate struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Slug               string         `json:"slug"`
	Category           string         `json:"category"`
	Subject            string         `json:"subject"`
	HTMLBody           string         `json:"html_body"`
	TextBody           string         `json:"text_body"`
	Description        string         `json:"description,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	DefaultProviderID  string         `json:"default_provider_id,omitempty"`
	MaxRetriesOverride *int           `json:"max_retries_override,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// Clone returns a deep copy of the template.
func (t *EmailTemplate) Clone() *EmailTemplate {
	if t == nil {
		return nil
	}
	clone := *t
	if t.Metadata != nil {
		clone.Metadata = make(map[string]any, len(t.Metadata))
		for k, v := range t.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

// EmailTemplateRoute defines an ordered chain of providers per template/category.
type EmailTemplateRoute struct {
	ID                 string    `json:"id"`
	TemplateID         string    `json:"template_id,omitempty"`
	Category           string    `json:"category,omitempty"`
	ProviderID         string    `json:"provider_id"`
	Priority           int       `json:"priority"`
	RetryLimitOverride *int      `json:"retry_limit_override,omitempty"`
	Enabled            bool      `json:"enabled"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// Clone returns a deep copy of the route.
func (r *EmailTemplateRoute) Clone() *EmailTemplateRoute {
	if r == nil {
		return nil
	}
	clone := *r
	return &clone
}

// MessageStatus describes the life-cycle of queued outbound email.
type MessageStatus string

const (
	MessageStatusQueued   MessageStatus = "queued"
	MessageStatusSending  MessageStatus = "sending"
	MessageStatusRetrying MessageStatus = "retrying"
	MessageStatusSent     MessageStatus = "sent"
	MessageStatusFailed   MessageStatus = "failed"
	MessageStatusBounced  MessageStatus = "bounced"
)

// EmailAttachment represents a file attached to an email.
type EmailAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"data,omitempty"`        // Base64 decoded content
	DataBase64  string `json:"data_base64,omitempty"` // Base64 encoded content for JSON transport
	Size        int64  `json:"size"`
}

// Clone returns a deep copy of the attachment.
func (a *EmailAttachment) Clone() *EmailAttachment {
	if a == nil {
		return nil
	}
	clone := *a
	if a.Data != nil {
		clone.Data = make([]byte, len(a.Data))
		copy(clone.Data, a.Data)
	}
	return &clone
}

// EmailMessage is persisted for queueing, auditing, and retries.
type EmailMessage struct {
	ID            string             `json:"id"`
	TemplateID    string             `json:"template_id"`
	ProviderID    string             `json:"provider_id,omitempty"`
	To            string             `json:"to"`
	CC            []string           `json:"cc,omitempty"`
	BCC           []string           `json:"bcc,omitempty"`
	Subject       string             `json:"subject"`
	RenderedHTML  string             `json:"rendered_html,omitempty"`
	RenderedText  string             `json:"rendered_text,omitempty"`
	Variables     map[string]any     `json:"variables,omitempty"`
	Metadata      map[string]string  `json:"metadata,omitempty"`
	Attachments   []*EmailAttachment `json:"attachments,omitempty"`
	Status        MessageStatus      `json:"status"`
	RetryCount    int                `json:"retry_count"`
	MaxRetries    int                `json:"max_retries"`
	FailoverCount int                `json:"failover_count"`
	LastError     string             `json:"last_error,omitempty"`
	NextAttemptAt time.Time          `json:"next_attempt_at"`
	LastAttemptAt time.Time          `json:"last_attempt_at"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

// Clone returns a deep copy of the message.
func (m *EmailMessage) Clone() *EmailMessage {
	if m == nil {
		return nil
	}
	clone := *m
	clone.CC = cloneStringSlice(m.CC)
	clone.BCC = cloneStringSlice(m.BCC)
	if m.Variables != nil {
		clone.Variables = make(map[string]any, len(m.Variables))
		for k, v := range m.Variables {
			clone.Variables[k] = v
		}
	}
	if m.Metadata != nil {
		clone.Metadata = make(map[string]string, len(m.Metadata))
		for k, v := range m.Metadata {
			clone.Metadata[k] = v
		}
	}
	if m.Attachments != nil {
		clone.Attachments = make([]*EmailAttachment, len(m.Attachments))
		for i, att := range m.Attachments {
			clone.Attachments[i] = att.Clone()
		}
	}
	return &clone
}

// EmailEvent tracks downstream callbacks such as delivered/bounced notifications.
type EmailEvent struct {
	ID         string         `json:"id"`
	MessageID  string         `json:"message_id"`
	ProviderID string         `json:"provider_id"`
	EventType  string         `json:"event_type"`
	Payload    map[string]any `json:"payload,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Clone returns a deep copy of the event.
func (e *EmailEvent) Clone() *EmailEvent {
	if e == nil {
		return nil
	}
	clone := *e
	if e.Payload != nil {
		clone.Payload = make(map[string]any, len(e.Payload))
		for k, v := range e.Payload {
			clone.Payload[k] = v
		}
	}
	return &clone
}

func cloneStringSlice(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}
