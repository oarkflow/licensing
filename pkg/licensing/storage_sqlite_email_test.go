package licensing

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	email "github.com/oarkflow/licensing/pkg/email"
)

func TestSQLiteEmailQueuePersistsAttachments(t *testing.T) {
	storage, err := NewSQLiteStorage(filepath.Join(t.TempDir(), "licensing.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	defer storage.db.Close()

	ctx := context.Background()
	msg := &email.EmailMessage{
		ID:            "msg-attachments",
		To:            "client@example.com",
		Subject:       "License",
		RenderedText:  "Attached.",
		Status:        email.MessageStatusQueued,
		MaxRetries:    3,
		NextAttemptAt: time.Now().Add(-time.Minute),
		Attachments: []*email.EmailAttachment{
			{
				Filename:    "license.json",
				ContentType: "application/json",
				Data:        []byte(`{"license_key":"abc"}`),
			},
		},
	}
	if err := storage.EnqueueEmail(ctx, msg); err != nil {
		t.Fatalf("EnqueueEmail failed: %v", err)
	}

	stored, err := storage.GetEmailMessage(ctx, msg.ID)
	if err != nil {
		t.Fatalf("GetEmailMessage failed: %v", err)
	}
	assertEmailAttachment(t, stored)

	leased, err := storage.LeaseNextEmail(ctx, time.Now())
	if err != nil {
		t.Fatalf("LeaseNextEmail failed: %v", err)
	}
	if leased == nil {
		t.Fatalf("expected queued message to be leased")
	}
	assertEmailAttachment(t, leased)
}

func assertEmailAttachment(t *testing.T, msg *email.EmailMessage) {
	t.Helper()
	if msg == nil {
		t.Fatalf("message is nil")
	}
	if len(msg.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(msg.Attachments))
	}
	att := msg.Attachments[0]
	if att.Filename != "license.json" {
		t.Fatalf("unexpected filename: %q", att.Filename)
	}
	if att.ContentType != "application/json" {
		t.Fatalf("unexpected content type: %q", att.ContentType)
	}
	if string(att.Data) != `{"license_key":"abc"}` {
		t.Fatalf("unexpected attachment data: %q", string(att.Data))
	}
	if att.Size != int64(len(att.Data)) {
		t.Fatalf("unexpected attachment size: %d", att.Size)
	}
}
