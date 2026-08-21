package abac

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Decision is the outcome of evaluating a PolicySet against a Context for a
// specific resource.
type Decision struct {
	Effect Effect
	Policy string // matching policy ID, "" if default-deny
	Reason string
}

// Evaluate applies standard ABAC combining logic: explicit Deny beats
// explicit Allow, and the absence of any matching policy is a Deny (fail
// closed). Policies are otherwise order-independent — this is what makes
// evaluation deterministic regardless of how the policy file happens to be
// ordered.
func Evaluate(ps *PolicySet, resource string, ctx *Context) Decision {
	sawAllow := false
	var allowPolicy Policy
	for _, p := range ps.Policies {
		if !resourceMatches(p.Resource, resource) {
			continue
		}
		if !evalCondition(p.Condition, ctx) {
			continue
		}
		if p.Effect == Deny {
			return Decision{Effect: Deny, Policy: p.ID, Reason: reasonOr(p.Reason, "explicit deny policy matched")}
		}
		if !sawAllow {
			sawAllow, allowPolicy = true, p
		}
	}
	if sawAllow {
		return Decision{Effect: Allow, Policy: allowPolicy.ID, Reason: reasonOr(allowPolicy.Reason, "allow policy matched")}
	}
	return Decision{Effect: Deny, Reason: "no policy granted access (default deny)"}
}

func reasonOr(reason, fallback string) string {
	if reason != "" {
		return reason
	}
	return fallback
}

func resourceMatches(pattern, resource string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(resource, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == resource
}

func evalCondition(c Condition, ctx *Context) bool {
	switch {
	case len(c.All) > 0:
		for _, sub := range c.All {
			if !evalCondition(sub, ctx) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		for _, sub := range c.Any {
			if evalCondition(sub, ctx) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !evalCondition(*c.Not, ctx)
	default:
		return evalLeaf(c, ctx)
	}
}

func evalLeaf(c Condition, ctx *Context) bool {
	switch c.Op {
	case "is":
		// Named environmental predicates. "time.Now() is Business_Hours" is
		// the motivating case; the attr is nominal (documents intent) and
		// the predicate name drives the check.
		name, _ := c.Value.(string)
		switch name {
		case "Business_Hours":
			return inBusinessHours(ctx.Time, ctx.Environment.BusinessHours)
		default:
			return false
		}
	}

	actual, ok := resolveAttr(ctx, c.Attr)

	switch c.Op {
	case "pr", "exists":
		return ok && !isEmpty(actual)
	case "matches":
		if !ok {
			return false
		}
		ip, isStr := actual.(string)
		if !isStr {
			return false
		}
		cidr, _ := c.Value.(string)
		return ipInNamedOrLiteralCIDR(ip, cidr, ctx.Environment.CIDRRanges)
	case "regex":
		if !ok {
			return false
		}
		s, isStr := actual.(string)
		pattern, patOK := c.Value.(string)
		if !isStr || !patOK {
			return false
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(s)
	case "in":
		if !ok {
			return false
		}
		list, isList := c.Value.([]any)
		if !isList {
			return false
		}
		for _, v := range list {
			if valuesEqual(actual, v) {
				return true
			}
		}
		return false
	case "contains":
		if !ok {
			return false
		}
		switch a := actual.(type) {
		case string:
			s, _ := c.Value.(string)
			return strings.Contains(a, s)
		case []any:
			for _, v := range a {
				if valuesEqual(v, c.Value) {
					return true
				}
			}
		case []string:
			for _, v := range a {
				if s, isStr := c.Value.(string); isStr && v == s {
					return true
				}
			}
		}
		return false
	case "eq", "==":
		return ok && valuesEqual(actual, c.Value)
	case "ne", "!=":
		return !ok || !valuesEqual(actual, c.Value)
	case "gt", "ge", "lt", "le":
		if !ok {
			return false
		}
		return numericCompare(actual, c.Op, c.Value)
	default:
		return false
	}
}

func isEmpty(v any) bool {
	switch x := v.(type) {
	case string:
		return x == ""
	case nil:
		return true
	}
	return false
}

func valuesEqual(a, b any) bool {
	as, aIsStr := a.(string)
	bs, bIsStr := b.(string)
	if aIsStr && bIsStr {
		return as == bs
	}
	af, aIsNum := toFloat(a)
	bf, bIsNum := toFloat(b)
	if aIsNum && bIsNum {
		return af == bf
	}
	ab, aIsBool := a.(bool)
	bb, bIsBool := b.(bool)
	if aIsBool && bIsBool {
		return ab == bb
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func numericCompare(actual any, op string, want any) bool {
	af, aOK := toFloat(actual)
	wf, wOK := toFloat(want)
	if !aOK || !wOK {
		return false
	}
	switch op {
	case "gt":
		return af > wf
	case "ge":
		return af >= wf
	case "lt":
		return af < wf
	case "le":
		return af <= wf
	}
	return false
}

// resolveAttr resolves dotted paths like "user.Department" or
// "request.Source_IP" against the Context. "time.Now" resolves to the
// evaluation instant as an RFC3339 string.
func resolveAttr(ctx *Context, path string) (any, bool) {
	ns, rest, found := strings.Cut(path, ".")
	if !found {
		return nil, false
	}
	switch ns {
	case "user":
		return lookupPath(ctx.User, rest)
	case "request":
		return lookupPath(ctx.Request, rest)
	case "resource":
		return lookupPath(ctx.Resource, rest)
	case "time":
		if rest == "Now" || rest == "Now()" || rest == "now" {
			return ctx.Time.Format("2006-01-02T15:04:05Z07:00"), true
		}
		return nil, false
	default:
		return nil, false
	}
}

func lookupPath(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, seg := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func ipInNamedOrLiteralCIDR(ip, cidrOrName string, named map[string]string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	candidates := []string{cidrOrName}
	if !strings.Contains(cidrOrName, "/") {
		if resolved, ok := named[cidrOrName]; ok {
			candidates = []string{resolved}
		}
	}
	for _, c := range candidates {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// inBusinessHours checks the instant t against a weekly recurring window
// defined in bh.Timezone local time. An unset/invalid timezone falls back
// to UTC rather than erroring, so a misconfigured policy fails closed
// (narrows access) rather than panicking.
func inBusinessHours(t time.Time, bh BusinessHours) bool {
	loc, err := time.LoadLocation(bh.Timezone)
	if err != nil || bh.Timezone == "" {
		loc = time.UTC
	}
	local := t.In(loc)
	dayOK := len(bh.Days) == 0 // no days configured -> don't restrict by day
	for _, d := range bh.Days {
		if int(local.Weekday()) == d {
			dayOK = true
			break
		}
	}
	if !dayOK {
		return false
	}
	hour := local.Hour()
	return hour >= bh.StartHour && hour < bh.EndHour
}
