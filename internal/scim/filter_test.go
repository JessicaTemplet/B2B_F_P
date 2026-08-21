package scim

import (
	"strings"
	"testing"

	"b2bfp/internal/store"
)

func TestParseFilter_Basics(t *testing.T) {
	u := &store.User{UserName: "alice@acme.example", Department: "Engineering", Active: true}
	tests := []struct {
		filter string
		want   bool
	}{
		{`userName eq "alice@acme.example"`, true},
		{`userName eq "bob@acme.example"`, false},
		{`department eq "Engineering" and active eq true`, true},
		{`department eq "Sales" or active eq true`, true},
		{`not (department eq "Sales")`, true},
		{`department co "Engin"`, true},
		{`externalId pr`, false},
	}
	for _, tc := range tests {
		node, err := ParseFilter(tc.filter)
		if err != nil {
			t.Fatalf("filter %q: parse error: %v", tc.filter, err)
		}
		if got := node.Eval(u); got != tc.want {
			t.Errorf("filter %q: got %v, want %v", tc.filter, got, tc.want)
		}
	}
}

// TestParseFilter_RejectsDeepNesting guards against unbounded recursion in
// the recursive-descent parser (parseOr/parseAnd/parseTerm re-enter each
// other once per '(' or 'not('): without maxFilterDepth, a filter query
// param well within any reasonable length limit can still nest deep enough
// to exhaust the goroutine stack, which is a Go runtime fatal error that
// ordinary panic recovery cannot catch.
func TestParseFilter_RejectsDeepNesting(t *testing.T) {
	depth := maxFilterDepth * 4
	filter := strings.Repeat("(", depth) + `userName pr` + strings.Repeat(")", depth)
	_, err := ParseFilter(filter)
	if err == nil {
		t.Fatal("expected deeply nested filter to be rejected, got nil error")
	}
}

func TestParseFilter_EmptyReturnsNilNode(t *testing.T) {
	node, err := ParseFilter("")
	if err != nil || node != nil {
		t.Fatalf("expected (nil, nil) for empty filter, got (%v, %v)", node, err)
	}
}
