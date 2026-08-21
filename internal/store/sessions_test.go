package store

import (
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestMarkAssertionUsed_RejectsReplay is the regression test for the
// IdP-initiated SAML replay fix: a captured valid response (no
// InResponseTo, so saml_requests' consume-once mechanism never sees it)
// must not be accepted a second time within its own validity window.
func TestMarkAssertionUsed_RejectsReplay(t *testing.T) {
	s := openTestStore(t)
	expires := time.Now().Add(time.Hour)

	usedBefore, err := s.MarkAssertionUsed("acme", "_assert123", expires)
	if err != nil {
		t.Fatalf("first MarkAssertionUsed: %v", err)
	}
	if usedBefore {
		t.Fatal("expected first use to report usedBefore=false")
	}

	usedBefore, err = s.MarkAssertionUsed("acme", "_assert123", expires)
	if err != nil {
		t.Fatalf("second MarkAssertionUsed: %v", err)
	}
	if !usedBefore {
		t.Fatal("expected replayed assertion ID to report usedBefore=true")
	}
}

func TestMarkAssertionUsed_ScopedPerTenant(t *testing.T) {
	s := openTestStore(t)
	expires := time.Now().Add(time.Hour)

	if usedBefore, err := s.MarkAssertionUsed("acme", "_assert123", expires); err != nil || usedBefore {
		t.Fatalf("tenant acme first use: usedBefore=%v err=%v", usedBefore, err)
	}
	// Same assertion ID under a different tenant is a distinct row — IDs
	// are only unique per-(tenant, assertion), matching how every other
	// per-tenant table in this store is scoped.
	if usedBefore, err := s.MarkAssertionUsed("globex", "_assert123", expires); err != nil || usedBefore {
		t.Fatalf("tenant globex first use: usedBefore=%v err=%v", usedBefore, err)
	}
}
