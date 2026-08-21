package scim

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"b2bfp/internal/store"
)

// ---- SCIM filter grammar (RFC 7644 §3.4.2.2), core subset -----------------
//
//   filter   := andExpr ( "or" andExpr )*
//   andExpr  := term ( "and" term )*
//   term     := "not" "(" filter ")" | "(" filter ")" | attrExpr
//   attrExpr := ATTRPATH "pr" | ATTRPATH OP compValue
//   OP       := eq | ne | co | sw | ew | gt | ge | lt | le
//
// Multi-valued sub-attribute filters (e.g. emails[type eq "work"]) are not
// supported; everything else in the core grammar is.

type Node interface {
	Eval(u *store.User) bool
}

type andNode struct{ children []Node }

func (n *andNode) Eval(u *store.User) bool {
	for _, c := range n.children {
		if !c.Eval(u) {
			return false
		}
	}
	return true
}

type orNode struct{ children []Node }

func (n *orNode) Eval(u *store.User) bool {
	for _, c := range n.children {
		if c.Eval(u) {
			return true
		}
	}
	return false
}

type notNode struct{ child Node }

func (n *notNode) Eval(u *store.User) bool { return !n.child.Eval(u) }

type presentNode struct{ attr string }

func (n *presentNode) Eval(u *store.User) bool {
	v, ok := attrValue(u, n.attr)
	if !ok || v == nil {
		return false
	}
	if s, isStr := v.(string); isStr {
		return s != ""
	}
	return true
}

type compareNode struct {
	attr string
	op   string
	val  any
}

func (n *compareNode) Eval(u *store.User) bool {
	actual, ok := attrValue(u, n.attr)
	if !ok {
		return false
	}
	return compare(actual, n.op, n.val)
}

func compare(actual any, op string, want any) bool {
	// Multi-valued attributes (e.g. emails.value -> []string): SCIM's
	// implicit semantics for a bare attrExpr against a multi-valued
	// attribute is "true if any value matches".
	if list, isList := actual.([]string); isList {
		for _, v := range list {
			if compare(v, op, want) {
				return true
			}
		}
		return false
	}

	as, aIsStr := actual.(string)
	ws, wIsStr := want.(string)
	if aIsStr && wIsStr {
		al, wl := strings.ToLower(as), strings.ToLower(ws)
		switch op {
		case "eq":
			return al == wl
		case "ne":
			return al != wl
		case "co":
			return strings.Contains(al, wl)
		case "sw":
			return strings.HasPrefix(al, wl)
		case "ew":
			return strings.HasSuffix(al, wl)
		case "gt":
			return as > ws
		case "ge":
			return as >= ws
		case "lt":
			return as < ws
		case "le":
			return as <= ws
		}
		return false
	}

	if ab, aIsBool := actual.(bool); aIsBool {
		if wb, wIsBool := want.(bool); wIsBool {
			switch op {
			case "eq":
				return ab == wb
			case "ne":
				return ab != wb
			}
		}
		return false
	}

	af, aIsNum := toFloat(actual)
	wf, wIsNum := toFloat(want)
	if aIsNum && wIsNum {
		switch op {
		case "eq":
			return af == wf
		case "ne":
			return af != wf
		case "gt":
			return af > wf
		case "ge":
			return af >= wf
		case "lt":
			return af < wf
		case "le":
			return af <= wf
		}
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}

// attrValue resolves a SCIM attribute path against a stored user. It covers
// the core + enterprise-extension attributes the SCIM engine models
// explicitly, then falls back to the raw attribute bag for anything else an
// IdP sent that we passed through verbatim.
func attrValue(u *store.User, path string) (any, bool) {
	p := strings.ToLower(strings.TrimPrefix(path, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:"))
	switch p {
	case "username", "userName":
		return u.UserName, true
	case "id":
		return u.ID, true
	case "externalid":
		return u.ExternalID, true
	case "displayname":
		return u.DisplayName, true
	case "active":
		return u.Active, true
	case "department":
		return u.Department, true
	case "name.givenname":
		return u.GivenName, true
	case "name.familyname":
		return u.FamilyName, true
	case "emails", "emails.value":
		if u.Email == "" {
			return []string{}, true
		}
		return []string{u.Email}, true
	case "meta.created":
		return u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), true
	case "meta.lastmodified":
		return u.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"), true
	}
	// Fallback: look up in the raw attribute bag by dotted path.
	var cur any = u.Attributes
	for _, seg := range strings.Split(p, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// ---- tokenizer --------------------------------------------------------

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokLParen
	tokRParen
	tokAnd
	tokOr
	tokNot
	tokPresent
	tokOp
	tokAttr
	tokString
	tokNumber
	tokBool
	tokNull
)

type token struct {
	kind tokenKind
	text string
}

func tokenize(input string) ([]token, error) {
	var toks []token
	r := []rune(input)
	i := 0
	for i < len(r) {
		c := r[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '(':
			toks = append(toks, token{tokLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tokRParen, ")"})
			i++
		case c == '"':
			j := i + 1
			var sb strings.Builder
			for j < len(r) && r[j] != '"' {
				if r[j] == '\\' && j+1 < len(r) {
					j++
				}
				sb.WriteRune(r[j])
				j++
			}
			if j >= len(r) {
				return nil, fmt.Errorf("unterminated string literal")
			}
			toks = append(toks, token{tokString, sb.String()})
			i = j + 1
		case unicode.IsDigit(c) || (c == '-' && i+1 < len(r) && unicode.IsDigit(r[i+1])):
			j := i + 1
			for j < len(r) && (unicode.IsDigit(r[j]) || r[j] == '.') {
				j++
			}
			toks = append(toks, token{tokNumber, string(r[i:j])})
			i = j
		case isWordChar(c):
			j := i
			for j < len(r) && (isWordChar(r[j]) || r[j] == ':') {
				j++
			}
			word := string(r[i:j])
			toks = append(toks, classifyWord(word))
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q in filter", c)
		}
	}
	toks = append(toks, token{tokEOF, ""})
	return toks, nil
}

func isWordChar(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_' || c == '.' || c == '-'
}

func classifyWord(word string) token {
	switch strings.ToLower(word) {
	case "and":
		return token{tokAnd, word}
	case "or":
		return token{tokOr, word}
	case "not":
		return token{tokNot, word}
	case "pr":
		return token{tokPresent, word}
	case "eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le":
		return token{tokOp, strings.ToLower(word)}
	case "true", "false":
		return token{tokBool, word}
	case "null":
		return token{tokNull, word}
	default:
		return token{tokAttr, word}
	}
}

// ---- recursive-descent parser -----------------------------------------

type parser struct {
	toks []token
	pos  int
}

func ParseFilter(input string) (Node, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}
	toks, err := tokenize(input)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected token %q after filter", p.peek().text)
	}
	return node, nil
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	children := []Node{left}
	for p.peek().kind == tokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 1 {
		return left, nil
	}
	return &orNode{children}, nil
}

func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	children := []Node{left}
	for p.peek().kind == tokAnd {
		p.next()
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 1 {
		return left, nil
	}
	return &andNode{children}, nil
}

func (p *parser) parseTerm() (Node, error) {
	switch p.peek().kind {
	case tokNot:
		p.next()
		if p.peek().kind != tokLParen {
			return nil, fmt.Errorf("expected '(' after 'not'")
		}
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("expected ')' to close 'not' group")
		}
		p.next()
		return &notNode{inner}, nil
	case tokLParen:
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("expected ')'")
		}
		p.next()
		return inner, nil
	case tokAttr:
		attr := p.next().text
		switch p.peek().kind {
		case tokPresent:
			p.next()
			return &presentNode{attr}, nil
		case tokOp:
			op := p.next().text
			val, err := p.parseCompValue()
			if err != nil {
				return nil, err
			}
			return &compareNode{attr, op, val}, nil
		default:
			return nil, fmt.Errorf("expected operator after attribute %q", attr)
		}
	default:
		return nil, fmt.Errorf("unexpected token %q in filter", p.peek().text)
	}
}

func (p *parser) parseCompValue() (any, error) {
	t := p.next()
	switch t.kind {
	case tokString:
		return t.text, nil
	case tokNumber:
		f, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q", t.text)
		}
		return f, nil
	case tokBool:
		return strings.EqualFold(t.text, "true"), nil
	case tokNull:
		return nil, nil
	default:
		return nil, fmt.Errorf("expected comparison value, got %q", t.text)
	}
}
