package saml

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
)

// This file implements a minimal Exclusive XML Canonicalization
// (xml-exc-c14n, http://www.w3.org/2001/10/xml-exc-c14n#) suitable for
// verifying/producing XML-DSig enveloped signatures on SAML documents. It
// intentionally does NOT implement the full C14N/xml-exc-c14n spec (no
// comment handling beyond stripping, no InclusiveNamespaces PrefixList
// support, no processing-instruction passthrough) — those features are
// rarely exercised by IdP-generated SAML assertions. Treat this as a
// building block that has been tested for internal round-trip correctness
// (see canon_test.go / signature_test.go), not as a general-purpose,
// independently-audited C14N implementation. XML-DSig is a well-known
// source of "signature wrapping" bugs; see verifyReferencedElement in
// xmldsig.go for the structural defense this package relies on instead of
// assuming canonicalization alone is enough.
//
// Go's encoding/xml resolves element/attribute prefixes to full namespace
// URIs and discards the literal prefix text, but C14N output must preserve
// the *original* prefix strings byte-for-byte (it does not rename them).
// So this parser captures each start tag's raw source bytes (via
// decoder.InputOffset) alongside the decoded token, and canon.go re-derives
// literal QNames from that raw text instead of from xml.Name.

type rawStartTag struct {
	raw []byte // exact source bytes of "<prefix:Local attr="v" .../>" or "...>"
}

// captureRawTags re-parses src token-by-token purely to record each
// StartElement's literal source bytes, indexed the same way parseXMLDoc
// indexes tokens (so raw[i] corresponds to d.tokens[i]).
func captureRawTags(src []byte) (map[int][]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(src))
	dec.Strict = true
	raw := map[int][]byte{}
	i := 0
	offset := int64(0)
	for {
		t, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("xml raw scan: %w", err)
		}
		end := dec.InputOffset()
		if _, ok := t.(xml.StartElement); ok {
			raw[i] = bytes.TrimSpace(src[offset:end])
		}
		offset = end
		i++
	}
	return raw, nil
}

// qname extracts the literal element/attribute QNames from a captured raw
// start tag, in document order, tag name first.
func qname(rawTag []byte) (tagName string, attrNames []string) {
	s := rawTag
	// strip leading '<'
	i := 0
	for i < len(s) && s[i] != '<' {
		i++
	}
	i++
	start := i
	for i < len(s) && !isSpaceByte(s[i]) && s[i] != '>' && s[i] != '/' {
		i++
	}
	tagName = string(s[start:i])
	for i < len(s) {
		for i < len(s) && (isSpaceByte(s[i])) {
			i++
		}
		if i >= len(s) || s[i] == '/' || s[i] == '>' {
			break
		}
		nstart := i
		for i < len(s) && s[i] != '=' && !isSpaceByte(s[i]) {
			i++
		}
		attrNames = append(attrNames, string(s[nstart:i]))
		for i < len(s) && s[i] != '=' {
			i++
		}
		i++ // skip '='
		for i < len(s) && isSpaceByte(s[i]) {
			i++
		}
		if i >= len(s) {
			break
		}
		quote := s[i]
		if quote != '"' && quote != '\'' {
			break
		}
		i++
		for i < len(s) && s[i] != quote {
			i++
		}
		i++ // skip closing quote
	}
	return
}

func isSpaceByte(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

// canonElement is the parsed, c14n-relevant view of one start tag: literal
// prefix (or "" for unprefixed/default), namespace URI, and local name.
type canonName struct {
	prefix string
	uri    string
	local  string
}

func splitQName(qn string) (prefix, local string) {
	for i := 0; i < len(qn); i++ {
		if qn[i] == ':' {
			return qn[:i], qn[i+1:]
		}
	}
	return "", qn
}

// canonicalizer holds the state needed to render one C14N pass over a
// subtree of an xmldoc.
type canonicalizer struct {
	doc     *xmldoc
	raw     map[int][]byte
	exclude map[int]bool // token indices (StartElement) whose whole subtree is omitted (the enveloped ds:Signature)
	out     bytes.Buffer
	tooDeep bool
}

// maxCanonDepth bounds element-nesting recursion in render(). This runs on
// attacker-controlled XML (a POSTed SAMLResponse, verified or not — the
// digest must be computed before we know the signature is valid) via direct
// Go function recursion, so with no limit a pathologically deep document
// (well within ordinary body-size limits) can exhaust the goroutine stack.
// That is a runtime fatal error in Go, not an ordinary panic — it is NOT
// caught by net/http's per-request recover() and takes down the whole
// process. Real SAML assertions never come close to this depth.
const maxCanonDepth = 256

// canonicalize renders the exclusive-c14n serialization of doc[start:end]
// (inclusive of the StartElement at start and EndElement at end).
func canonicalize(doc *xmldoc, raw map[int][]byte, start, end int, exclude map[int]bool) ([]byte, error) {
	c := &canonicalizer{doc: doc, raw: raw, exclude: exclude}
	c.render(start, end, nsScope{}, 0)
	if c.tooDeep {
		return nil, fmt.Errorf("saml: XML element nesting exceeds %d levels, refusing to canonicalize", maxCanonDepth)
	}
	return c.out.Bytes(), nil
}

// render walks [start,end], writing canonical bytes. rendered tracks which
// namespace prefix->URI bindings have already been emitted by an ancestor
// *within this canonicalization pass* (not the original document), which is
// the crux of exclusive c14n's "visibly utilized" rule.
func (c *canonicalizer) render(start, end int, rendered nsScope, depth int) {
	if c.exclude[start] {
		return
	}
	if depth > maxCanonDepth {
		c.tooDeep = true
		return
	}
	se := c.doc.tokens[start].(xml.StartElement)
	rawTag, ok := c.raw[start]
	if !ok {
		return
	}
	tagQ, attrQs := qname(rawTag)
	prefix, local := splitQName(tagQ)
	_ = local

	// Effective namespace scope at this element (document truth, used to
	// resolve prefix -> URI), including this element's own declarations.
	effective := c.doc.nsAtStart[start].clone()
	for _, a := range se.Attr {
		if a.Name.Space == "xmlns" {
			effective[a.Name.Local] = a.Value
		} else if a.Name.Space == "" && a.Name.Local == "xmlns" {
			effective[""] = a.Value
		}
	}

	elemURI := effective[prefix]

	// Determine which namespace declarations must be emitted on this
	// element: those visibly utilized (by the element name or a
	// non-xmlns, prefixed attribute) whose current binding differs from
	// what's already been rendered by an ancestor in this pass.
	type nsDecl struct{ prefix, uri string }
	var needed []nsDecl
	seen := map[string]bool{}
	addIfNeeded := func(pfx string) {
		if seen[pfx] {
			return
		}
		seen[pfx] = true
		uri := effective[pfx]
		if r, ok := rendered[pfx]; ok && r == uri {
			return
		}
		needed = append(needed, nsDecl{pfx, uri})
	}
	addIfNeeded(prefix)
	for idx, a := range se.Attr {
		if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
			continue // xmlns declarations themselves aren't "attributes visibly utilizing a namespace"
		}
		aPrefix, _ := splitQName(attrQs[idx])
		if aPrefix != "" {
			addIfNeeded(aPrefix)
		}
	}
	sort.Slice(needed, func(i, j int) bool { return needed[i].prefix < needed[j].prefix })

	newRendered := rendered.clone()
	for _, n := range needed {
		newRendered[n.prefix] = n.uri
	}

	// Non-namespace attributes, sorted per C14N: by namespace URI then
	// local name (unprefixed attributes sort first, namespace URI "").
	type attrOut struct {
		uri, local, qname, value string
	}
	var attrs []attrOut
	for idx, a := range se.Attr {
		if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
			continue
		}
		aPrefix, aLocal := splitQName(attrQs[idx])
		uri := ""
		if aPrefix != "" {
			uri = effective[aPrefix]
		}
		attrs = append(attrs, attrOut{uri, aLocal, attrQs[idx], a.Value})
	}
	sort.Slice(attrs, func(i, j int) bool {
		if attrs[i].uri != attrs[j].uri {
			return attrs[i].uri < attrs[j].uri
		}
		return attrs[i].local < attrs[j].local
	})

	c.out.WriteByte('<')
	c.out.WriteString(tagQ)
	for _, n := range needed {
		c.out.WriteByte(' ')
		if n.prefix == "" {
			c.out.WriteString("xmlns")
		} else {
			c.out.WriteString("xmlns:" + n.prefix)
		}
		c.out.WriteString(`="`)
		c.out.WriteString(escapeAttr(n.uri))
		c.out.WriteByte('"')
	}
	for _, a := range attrs {
		c.out.WriteByte(' ')
		c.out.WriteString(a.qname)
		c.out.WriteString(`="`)
		c.out.WriteString(escapeAttr(a.value))
		c.out.WriteByte('"')
	}
	c.out.WriteByte('>')

	i := start + 1
	for i < end {
		switch t := c.doc.tokens[i].(type) {
		case xml.StartElement:
			childEnd := c.doc.matchEnd[i]
			if !c.exclude[i] {
				c.render(i, childEnd, newRendered, depth+1)
			}
			i = childEnd + 1
			continue
		case xml.CharData:
			c.out.WriteString(escapeText(string(t)))
		case xml.Comment, xml.ProcInst, xml.Directive:
			// omitted (C14N without comments)
		}
		i++
	}

	c.out.WriteString("</")
	c.out.WriteString(tagQ)
	c.out.WriteByte('>')

	_ = elemURI
}

func escapeAttr(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '"':
			b.WriteString("&quot;")
		case '\t':
			b.WriteString("&#x9;")
		case '\n':
			b.WriteString("&#xA;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func escapeText(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
