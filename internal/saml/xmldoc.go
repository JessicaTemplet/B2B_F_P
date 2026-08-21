package saml

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
)

// xmldoc is a fully materialized token stream of one XML document, with
// start/end tag indices pre-matched so subtrees can be located and sliced
// without re-parsing. This is the substrate the raw XML-DSig canonicalizer
// and signature verifier in xmldsig.go operate on.
type xmldoc struct {
	tokens []xml.Token
	// matchEnd[i] is the index of the EndElement matching tokens[i] when
	// tokens[i] is a StartElement.
	matchEnd map[int]int
	// nsAtStart[i] is the namespace scope (prefix -> URI, "" key = default
	// namespace) in effect *before* processing StartElement tokens[i] —
	// i.e. what an ancestor has declared. Needed to canonicalize a subtree
	// independent of its parents' start tags.
	nsAtStart map[int]nsScope
}

type nsScope map[string]string

func (s nsScope) clone() nsScope {
	c := make(nsScope, len(s))
	for k, v := range s {
		c[k] = v
	}
	return c
}

func parseXMLDoc(b []byte) (*xmldoc, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	var toks []xml.Token
	for {
		t, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("xml parse: %w", err)
		}
		toks = append(toks, xml.CopyToken(t))
	}
	d := &xmldoc{tokens: toks, matchEnd: map[int]int{}, nsAtStart: map[int]nsScope{}}
	d.index()
	return d, nil
}

func (d *xmldoc) index() {
	type frame struct {
		startIdx int
		scope    nsScope
	}
	var stack []frame
	cur := nsScope{}
	for i, t := range d.tokens {
		switch el := t.(type) {
		case xml.StartElement:
			d.nsAtStart[i] = cur.clone()
			next := cur.clone()
			for _, a := range el.Attr {
				if a.Name.Space == "xmlns" {
					next[a.Name.Local] = a.Value
				} else if a.Name.Space == "" && a.Name.Local == "xmlns" {
					next[""] = a.Value
				}
			}
			stack = append(stack, frame{i, cur})
			cur = next
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			d.matchEnd[f.startIdx] = i
			cur = f.scope
		}
	}
}

// findByID returns the [start,end] token index range of the element whose
// "ID" attribute equals id (the target of a ds:Reference URI="#id").
func (d *xmldoc) findByID(id string) (int, int, bool) {
	for i, t := range d.tokens {
		se, ok := t.(xml.StartElement)
		if !ok {
			continue
		}
		if end, ok := d.matchEnd[i]; ok {
			for _, a := range se.Attr {
				if a.Name.Local == "ID" && a.Value == id {
					return i, end, true
				}
			}
		}
	}
	return 0, 0, false
}

// findChild returns the first descendant of [start,end] (at any depth)
// matching (space, local); depth 0 = direct children only if directOnly.
func (d *xmldoc) findDescendant(start, end int, space, local string) (int, int, bool) {
	for i := start + 1; i < end; i++ {
		se, ok := d.tokens[i].(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == local && (space == "" || se.Name.Space == space) {
			if e, ok := d.matchEnd[i]; ok {
				return i, e, true
			}
		}
	}
	return 0, 0, false
}

func (d *xmldoc) findAllDescendants(start, end int, space, local string) [][2]int {
	var out [][2]int
	i := start + 1
	for i < end {
		se, ok := d.tokens[i].(xml.StartElement)
		if !ok {
			i++
			continue
		}
		e := d.matchEnd[i]
		if se.Name.Local == local && (space == "" || se.Name.Space == space) {
			out = append(out, [2]int{i, e})
			i = e + 1
			continue
		}
		i++
	}
	return out
}

func elementText(d *xmldoc, start, end int) string {
	var sb []byte
	for i := start + 1; i < end; i++ {
		if cd, ok := d.tokens[i].(xml.CharData); ok {
			sb = append(sb, cd...)
		}
	}
	return string(sb)
}

func attrValue(se xml.StartElement, local string) (string, bool) {
	for _, a := range se.Attr {
		if a.Name.Local == local {
			return a.Value, true
		}
	}
	return "", false
}
