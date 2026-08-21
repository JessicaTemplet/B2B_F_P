package scim

import (
	"fmt"
	"regexp"
	"strings"

	"b2bfp/internal/store"
)

// applyUserPatch mutates u in place according to RFC 7644 §3.5.2 PATCH
// operations. It supports the operations real IdPs actually send for user
// lifecycle management: replacing 'active' (the standard deprovisioning
// signal), name/email/department fields, and whole-value replace with an
// object body (Okta's common form for "value": {"active": false}).
func applyUserPatch(u *store.User, ops []PatchOp) error {
	for _, op := range ops {
		verb := strings.ToLower(op.Op)
		path := normalizePatchPath(op.Path)
		switch verb {
		case "replace", "add":
			if path == "" {
				obj, ok := op.Value.(map[string]any)
				if !ok {
					return fmt.Errorf("patch: %s with empty path requires an object value", verb)
				}
				for k, v := range obj {
					if err := setUserField(u, normalizePatchPath(k), v); err != nil {
						return err
					}
				}
				continue
			}
			if err := setUserField(u, path, op.Value); err != nil {
				return err
			}
		case "remove":
			if path == "" {
				return fmt.Errorf("patch: remove requires a path")
			}
			if err := clearUserField(u, path); err != nil {
				return err
			}
		default:
			return fmt.Errorf("patch: unsupported op %q", op.Op)
		}
	}
	return nil
}

// bracketFilter strips SCIM's "attr[filter]" sub-attribute selector syntax
// down to the base attribute name, e.g. `emails[type eq "work"].value` ->
// `emails.value`. Filtering by which array element to touch isn't modeled;
// operations on multi-valued attributes act on the whole attribute.
var bracketFilter = regexp.MustCompile(`\[[^]]*\]`)

func normalizePatchPath(p string) string {
	p = bracketFilter.ReplaceAllString(p, "")
	p = strings.TrimPrefix(p, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:")
	p = strings.TrimPrefix(p, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:")
	return strings.ToLower(strings.TrimSpace(p))
}

func setUserField(u *store.User, path string, value any) error {
	switch path {
	case "active":
		b, ok := value.(bool)
		if !ok {
			return fmt.Errorf("patch: 'active' must be boolean")
		}
		u.Active = b
	case "username":
		s, _ := value.(string)
		u.UserName = s
	case "displayname":
		s, _ := value.(string)
		u.DisplayName = s
	case "externalid":
		s, _ := value.(string)
		u.ExternalID = s
	case "name.givenname":
		s, _ := value.(string)
		u.GivenName = s
	case "name.familyname":
		s, _ := value.(string)
		u.FamilyName = s
	case "department":
		s, _ := value.(string)
		u.Department = s
	case "emails", "emails.value":
		switch v := value.(type) {
		case string:
			u.Email = v
		case []any:
			if len(v) > 0 {
				if m, ok := v[0].(map[string]any); ok {
					if s, ok := m["value"].(string); ok {
						u.Email = s
					}
				}
			}
		case map[string]any:
			if s, ok := v["value"].(string); ok {
				u.Email = s
			}
		}
	case "name":
		if m, ok := value.(map[string]any); ok {
			if s, ok := m["givenName"].(string); ok {
				u.GivenName = s
			}
			if s, ok := m["familyName"].(string); ok {
				u.FamilyName = s
			}
		}
	default:
		if u.Attributes == nil {
			u.Attributes = map[string]any{}
		}
		u.Attributes[path] = value
	}
	return nil
}

func clearUserField(u *store.User, path string) error {
	switch path {
	case "active":
		u.Active = false
	case "displayname":
		u.DisplayName = ""
	case "department":
		u.Department = ""
	case "emails", "emails.value":
		u.Email = ""
	case "name.givenname":
		u.GivenName = ""
	case "name.familyname":
		u.FamilyName = ""
	default:
		delete(u.Attributes, path)
	}
	return nil
}

// applyGroupPatch supports the member-management operations IdPs send when
// syncing group rosters: add/remove/replace on "members".
func applyGroupPatch(g *store.Group, ops []PatchOp) error {
	for _, op := range ops {
		verb := strings.ToLower(op.Op)
		path := normalizePatchPath(op.Path)
		switch verb {
		case "add":
			ids := extractMemberIDs(op.Value)
			for _, id := range ids {
				if !containsStr(g.Members, id) {
					g.Members = append(g.Members, id)
				}
			}
		case "remove":
			if path == "members" || path == "" {
				ids := extractMemberIDs(op.Value)
				if len(ids) == 0 {
					g.Members = nil // remove with no filter/value: RFC 7644 example 3.5.2.2 clears the attribute
					continue
				}
				g.Members = removeAll(g.Members, ids)
				continue
			}
			// path like members[value eq "id"] -> normalizePatchPath already stripped the bracket;
			// fall back to treating the raw (pre-normalize) op.Path for the target id.
			if id := extractBracketedValue(op.Path); id != "" {
				g.Members = removeAll(g.Members, []string{id})
			}
		case "replace":
			if path == "displayname" {
				s, _ := op.Value.(string)
				g.DisplayName = s
				continue
			}
			g.Members = extractMemberIDs(op.Value)
		default:
			return fmt.Errorf("patch: unsupported op %q", op.Op)
		}
	}
	return nil
}

func extractMemberIDs(value any) []string {
	var out []string
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if s, ok := m["value"].(string); ok {
					out = append(out, s)
				}
			} else if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	case map[string]any:
		if s, ok := v["value"].(string); ok {
			out = append(out, s)
		}
	case string:
		out = append(out, v)
	}
	return out
}

var bracketValueEq = regexp.MustCompile(`value\s+eq\s+"([^"]+)"`)

func extractBracketedValue(path string) string {
	m := bracketValueEq.FindStringSubmatch(path)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func removeAll(list []string, remove []string) []string {
	rm := map[string]bool{}
	for _, r := range remove {
		rm[r] = true
	}
	var out []string
	for _, v := range list {
		if !rm[v] {
			out = append(out, v)
		}
	}
	return out
}
