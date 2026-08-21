// Package abac implements the Contextual Attribute-Based Access Control
// evaluator: it takes directory attributes mapped from a SAML/OIDC login
// (user.*), properties of the inbound request (request.*), and the current
// moment in time (time.*), and decides Allow/Deny against a set of
// declarative JSON policies such as:
//
//	Allow access to resource 'Production_DB' IF
//	  user.Department == 'Engineering' AND
//	  request.Source_IP matches Vpc_Range AND
//	  time.Now() is Business_Hours
package abac

import (
	"encoding/json"
	"fmt"
)

// Effect is the outcome a policy produces when its condition matches.
type Effect string

const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Condition is one boolean expression node. Exactly one of the group forms
// (All/Any/Not) or the leaf form (Attr/Op/Value) is set — see UnmarshalJSON.
type Condition struct {
	All   []Condition `json:"all,omitempty"`
	Any   []Condition `json:"any,omitempty"`
	Not   *Condition  `json:"not,omitempty"`
	Attr  string      `json:"attr,omitempty"`
	Op    string      `json:"op,omitempty"`
	Value any         `json:"value,omitempty"`
}

// Policy is one declarative rule. Resource matches by exact string or, if
// Resource ends in "*", by prefix — e.g. "Production_*" covers
// "Production_DB" and "Production_Cache".
type Policy struct {
	ID        string    `json:"id"`
	Effect    Effect    `json:"effect"`
	Resource  string    `json:"resource"`
	Condition Condition `json:"condition"`
	Reason    string    `json:"reason,omitempty"` // human-readable justification, echoed back in decisions/audit logs
}

type PolicySet struct {
	Policies []Policy `json:"policies"`
}

func ParsePolicySet(data []byte) (*PolicySet, error) {
	var ps PolicySet
	if err := json.Unmarshal(data, &ps); err != nil {
		return nil, fmt.Errorf("parse policy set: %w", err)
	}
	for i, p := range ps.Policies {
		if p.Effect != Allow && p.Effect != Deny {
			return nil, fmt.Errorf("policy %q: effect must be \"Allow\" or \"Deny\", got %q", p.ID, p.Effect)
		}
		if p.Resource == "" {
			return nil, fmt.Errorf("policy %q: resource is required", p.ID)
		}
		if err := validateCondition(p.Condition); err != nil {
			return nil, fmt.Errorf("policy %q: %w", p.ID, err)
		}
		_ = i
	}
	return &ps, nil
}

func validateCondition(c Condition) error {
	groups := 0
	if len(c.All) > 0 {
		groups++
	}
	if len(c.Any) > 0 {
		groups++
	}
	if c.Not != nil {
		groups++
	}
	isLeaf := c.Attr != "" || c.Op != ""
	if groups > 0 && isLeaf {
		return fmt.Errorf("condition mixes a group (all/any/not) with a leaf (attr/op) — pick one form")
	}
	if groups == 0 && !isLeaf {
		return fmt.Errorf("condition must set all/any/not or attr+op")
	}
	if isLeaf && (c.Attr == "" || c.Op == "") {
		return fmt.Errorf("leaf condition requires both attr and op")
	}
	for _, sub := range c.All {
		if err := validateCondition(sub); err != nil {
			return err
		}
	}
	for _, sub := range c.Any {
		if err := validateCondition(sub); err != nil {
			return err
		}
	}
	if c.Not != nil {
		if err := validateCondition(*c.Not); err != nil {
			return err
		}
	}
	return nil
}
