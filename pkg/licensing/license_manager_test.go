package licensing

import "testing"

func TestResolveLicenseIdentity(t *testing.T) {
	lm := &LicenseManager{}
	license := &License{
		ClientID: "client-owner",
		Email:    "owner@example.com",
	}

	t.Run("owner identity", func(t *testing.T) {
		req := &ActivationRequest{Email: "owner@example.com", ClientID: "client-owner"}
		identity, needsAttach, err := lm.resolveLicenseIdentity(license, req, true)
		if err != nil {
			t.Fatalf("expected owner to resolve, got error: %v", err)
		}
		if needsAttach {
			t.Fatalf("owner identity should already be attached")
		}
		if identity == nil || identity.Email != license.Email {
			t.Fatalf("unexpected identity returned: %+v", identity)
		}
	})

	t.Run("missing client id", func(t *testing.T) {
		req := &ActivationRequest{Email: "delegate@example.com"}
		if _, _, err := lm.resolveLicenseIdentity(license, req, true); err == nil {
			t.Fatalf("expected error when client_id missing")
		}
	})

	t.Run("delegated identity", func(t *testing.T) {
		req := &ActivationRequest{
			Email:    "delegate@example.com",
			ClientID: "client-owner",
		}
		identity, needsAttach, err := lm.resolveLicenseIdentity(license, req, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !needsAttach {
			t.Fatalf("expected delegated identity to require persistence")
		}
		if identity == nil || identity.Email != "delegate@example.com" {
			t.Fatalf("unexpected identity returned: %+v", identity)
		}
		if identity.ProviderClientID != "client-owner" {
			t.Fatalf("expected provider id to match owner, got %+v", identity)
		}
		attachAuthorizedIdentity(license, identity)
	})

	t.Run("reuse without source", func(t *testing.T) {
		req := &ActivationRequest{Email: "delegate@example.com", ClientID: "client-owner"}
		identity, needsAttach, err := lm.resolveLicenseIdentity(license, req, false)
		if err != nil {
			t.Fatalf("expected stored delegate to resolve, got error: %v", err)
		}
		if needsAttach {
			t.Fatalf("resolved delegate should not require persistence")
		}
		if identity == nil || identity.Email != "delegate@example.com" {
			t.Fatalf("unexpected identity: %+v", identity)
		}
		if identity.ClientID == "" {
			t.Fatalf("expected subject client id to persist, got %+v", identity)
		}
	})
}
