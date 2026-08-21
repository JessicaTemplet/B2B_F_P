package abac

import (
	"testing"
	"time"
)

// examplePolicy mirrors the spec's motivating rule literally:
//
//	Allow access to resource 'Production_DB' IF
//	  user.Department == 'Engineering' AND
//	  request.Source_IP matches Vpc_Range AND
//	  time.Now() is Business_Hours
func examplePolicySet(t *testing.T) *PolicySet {
	t.Helper()
	ps, err := ParsePolicySet([]byte(`{
		"policies": [
			{
				"id": "allow-prod-db-engineering",
				"effect": "Allow",
				"resource": "Production_DB",
				"condition": {
					"all": [
						{"attr": "user.Department", "op": "eq", "value": "Engineering"},
						{"attr": "request.Source_IP", "op": "matches", "value": "Vpc_Range"},
						{"attr": "time.Now", "op": "is", "value": "Business_Hours"}
					]
				}
			}
		]
	}`))
	if err != nil {
		t.Fatalf("parse policy set: %v", err)
	}
	return ps
}

func testEnv() Environment {
	return Environment{
		CIDRRanges: map[string]string{"Vpc_Range": "10.0.0.0/16"},
		BusinessHours: BusinessHours{
			Timezone:  "UTC",
			Days:      []int{1, 2, 3, 4, 5}, // Mon-Fri
			StartHour: 9,
			EndHour:   17,
		},
	}
}

func TestExamplePolicy_AllowsWithinVPCAndBusinessHours(t *testing.T) {
	ps := examplePolicySet(t)
	// Wed 2026-08-19 14:00 UTC is a Wednesday, 10am-5pm window.
	now := time.Date(2026, 8, 19, 14, 0, 0, 0, time.UTC)
	ctx := NewContext(
		map[string]any{"Department": "Engineering"},
		map[string]any{"Source_IP": "10.0.5.9"},
		now, testEnv(),
	)
	d := Evaluate(ps, "Production_DB", ctx)
	if d.Effect != Allow {
		t.Fatalf("expected Allow, got %s (%s)", d.Effect, d.Reason)
	}
	if d.Policy != "allow-prod-db-engineering" {
		t.Fatalf("expected matching policy id, got %q", d.Policy)
	}
}

func TestExamplePolicy_DeniesWrongDepartment(t *testing.T) {
	ps := examplePolicySet(t)
	now := time.Date(2026, 8, 19, 14, 0, 0, 0, time.UTC)
	ctx := NewContext(
		map[string]any{"Department": "Sales"},
		map[string]any{"Source_IP": "10.0.5.9"},
		now, testEnv(),
	)
	if d := Evaluate(ps, "Production_DB", ctx); d.Effect != Deny {
		t.Fatalf("expected Deny for wrong department, got %s", d.Effect)
	}
}

func TestExamplePolicy_DeniesOutsideVPC(t *testing.T) {
	ps := examplePolicySet(t)
	now := time.Date(2026, 8, 19, 14, 0, 0, 0, time.UTC)
	ctx := NewContext(
		map[string]any{"Department": "Engineering"},
		map[string]any{"Source_IP": "203.0.113.5"}, // outside 10.0.0.0/16
		now, testEnv(),
	)
	if d := Evaluate(ps, "Production_DB", ctx); d.Effect != Deny {
		t.Fatalf("expected Deny for source IP outside VPC range, got %s", d.Effect)
	}
}

func TestExamplePolicy_DeniesOutsideBusinessHours(t *testing.T) {
	ps := examplePolicySet(t)
	// Same Wednesday, but 22:00 UTC — after hours.
	now := time.Date(2026, 8, 19, 22, 0, 0, 0, time.UTC)
	ctx := NewContext(
		map[string]any{"Department": "Engineering"},
		map[string]any{"Source_IP": "10.0.5.9"},
		now, testEnv(),
	)
	if d := Evaluate(ps, "Production_DB", ctx); d.Effect != Deny {
		t.Fatalf("expected Deny outside business hours, got %s", d.Effect)
	}
}

func TestExamplePolicy_DeniesOnWeekend(t *testing.T) {
	ps := examplePolicySet(t)
	// 2026-08-22 is a Saturday.
	now := time.Date(2026, 8, 22, 14, 0, 0, 0, time.UTC)
	ctx := NewContext(
		map[string]any{"Department": "Engineering"},
		map[string]any{"Source_IP": "10.0.5.9"},
		now, testEnv(),
	)
	if d := Evaluate(ps, "Production_DB", ctx); d.Effect != Deny {
		t.Fatalf("expected Deny on weekend, got %s", d.Effect)
	}
}

func TestExplicitDenyOverridesAllow(t *testing.T) {
	ps, err := ParsePolicySet([]byte(`{
		"policies": [
			{"id": "allow-all-eng", "effect": "Allow", "resource": "Production_DB",
			 "condition": {"attr": "user.Department", "op": "eq", "value": "Engineering"}},
			{"id": "deny-contractors", "effect": "Deny", "resource": "Production_DB",
			 "condition": {"attr": "user.EmploymentType", "op": "eq", "value": "Contractor"}}
		]
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx := NewContext(
		map[string]any{"Department": "Engineering", "EmploymentType": "Contractor"},
		map[string]any{}, time.Now(), Environment{},
	)
	d := Evaluate(ps, "Production_DB", ctx)
	if d.Effect != Deny || d.Policy != "deny-contractors" {
		t.Fatalf("expected explicit deny to win, got %+v", d)
	}
}

func TestDefaultDenyWhenNoPolicyMatches(t *testing.T) {
	ps, _ := ParsePolicySet([]byte(`{"policies": []}`))
	ctx := NewContext(nil, nil, time.Now(), Environment{})
	d := Evaluate(ps, "Anything", ctx)
	if d.Effect != Deny || d.Policy != "" {
		t.Fatalf("expected default deny with no policy id, got %+v", d)
	}
}

func TestResourceWildcard(t *testing.T) {
	ps, err := ParsePolicySet([]byte(`{
		"policies": [
			{"id": "allow-prod-star", "effect": "Allow", "resource": "Production_*",
			 "condition": {"attr": "user.Department", "op": "eq", "value": "Engineering"}}
		]
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx := NewContext(map[string]any{"Department": "Engineering"}, nil, time.Now(), Environment{})
	if d := Evaluate(ps, "Production_Cache", ctx); d.Effect != Allow {
		t.Fatalf("expected wildcard resource match to allow, got %s", d.Effect)
	}
	if d := Evaluate(ps, "Staging_Cache", ctx); d.Effect != Deny {
		t.Fatalf("expected non-matching resource to deny, got %s", d.Effect)
	}
}

func TestInvalidConditionRejected(t *testing.T) {
	_, err := ParsePolicySet([]byte(`{
		"policies": [{"id": "bad", "effect": "Allow", "resource": "X", "condition": {}}]
	}`))
	if err == nil {
		t.Fatal("expected validation error for empty condition")
	}
}
