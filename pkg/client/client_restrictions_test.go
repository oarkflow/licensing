package client

import "testing"

func TestCanPerformWithContext_StorageLimit(t *testing.T) {
	lic := &LicenseData{
		Entitlements: &LicenseEntitlements{
			Features: map[string]FeatureGrant{
				"file": {
					FeatureSlug: "file",
					Enabled:     true,
					Scopes: map[string]ScopeGrant{
						"basic_storage": {
							ScopeSlug:    "basic_storage",
							Permission:   ScopePermissionAllow,
							Restrictions: []ScopeRestriction{{Type: UsageRestrictionStorage, Limit: 10}},
						},
					},
				},
			},
		},
	}

	ok, limit, _ := lic.CanPerformWithContext("file", "basic_storage", UsageContext{SubjectType: SubjectTypeStorage, Amount: 5})
	if !ok || limit != 10 {
		t.Fatalf("expected allowed with limit 10, got allowed=%v limit=%d", ok, limit)
	}

	ok, _, reason := lic.CanPerformWithContext("file", "basic_storage", UsageContext{SubjectType: SubjectTypeStorage, Amount: 15})
	if ok {
		t.Fatalf("expected denied when amount exceeds limit, got allowed")
	}
	if reason == "" {
		t.Fatalf("expected denial reason, got empty")
	}
}

func TestCanPerformWithContext_DeviceAndUser(t *testing.T) {
	lic := &LicenseData{
		Entitlements: &LicenseEntitlements{
			Features: map[string]FeatureGrant{
				"file": {
					FeatureSlug: "file",
					Enabled:     true,
					Scopes: map[string]ScopeGrant{
						"export": {
							ScopeSlug:  "export",
							Permission: ScopePermissionAllow,
							Restrictions: []ScopeRestriction{
								{Type: UsageRestrictionDevice, Limit: 1},
								{Type: UsageRestrictionUser, Limit: 3},
							},
						},
					},
				},
			},
		},
	}

	// Device limit
	ok, _, _ := lic.CanPerformWithContext("file", "export", UsageContext{SubjectType: SubjectTypeDevice, SubjectID: "dev1", Amount: 1})
	if !ok {
		t.Fatalf("expected allowed for device amount 1")
	}
	ok, _, _ = lic.CanPerformWithContext("file", "export", UsageContext{SubjectType: SubjectTypeDevice, SubjectID: "dev1", Amount: 2})
	if ok {
		t.Fatalf("expected denied for device amount 2")
	}

	// User limit
	ok, _, _ = lic.CanPerformWithContext("file", "export", UsageContext{SubjectType: SubjectTypeUser, SubjectID: "user1", Amount: 2})
	if !ok {
		t.Fatalf("expected allowed for user amount 2")
	}
	ok, _, _ = lic.CanPerformWithContext("file", "export", UsageContext{SubjectType: SubjectTypeUser, SubjectID: "user1", Amount: 4})
	if ok {
		t.Fatalf("expected denied for user amount 4")
	}
}
