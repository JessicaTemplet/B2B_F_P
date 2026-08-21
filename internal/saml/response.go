package saml

import (
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Assertion is the caller-facing, already-verified view of a SAMLResponse's
// assertion data. Every field is read from VerifiedAssertion's token range,
// so nothing here can have come from outside the signed subtree.
type Assertion struct {
	NameID       string
	NameIDFormat string
	Issuer       string
	InResponseTo string
	Attributes   map[string][]string
	NotBefore    time.Time
	NotOnOrAfter time.Time
}

const timeLayout = "2006-01-02T15:04:05Z"

func parseSAMLTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse(timeLayout, s)
}

// ParseAndVerifyResponse verifies rawXML's signature against cert, then
// extracts and validates the assertion: signature check (verifyEnvelopedSignature
// via VerifySAMLResponseSignature), Conditions time window, audience
// restriction (must include spEntityID), and — when expectedRequestID is
// non-empty — that InResponseTo matches the AuthnRequest we actually sent
// (replay/CSRF defense for the SP-initiated flow).
func ParseAndVerifyResponse(rawXML []byte, cert *x509.Certificate, spEntityID, expectedRequestID string, now time.Time, clockSkew time.Duration) (*Assertion, error) {
	verified, err := VerifySAMLResponseSignature(rawXML, cert)
	if err != nil {
		return nil, err
	}
	doc, raw := verified.doc, verified.raw
	_ = raw
	aStart, aEnd := verified.Start, verified.End

	a := &Assertion{Attributes: map[string][]string{}}

	if issStart, issEnd, ok := doc.findDirectChild(aStart, aEnd, samlNS, "Issuer"); ok {
		a.Issuer = strings.TrimSpace(elementText(doc, issStart, issEnd))
	}

	subStart, subEnd, ok := doc.findDirectChild(aStart, aEnd, samlNS, "Subject")
	if !ok {
		return nil, fmt.Errorf("saml: assertion missing Subject")
	}
	if nidStart, nidEnd, ok := doc.findDirectChild(subStart, subEnd, samlNS, "NameID"); ok {
		a.NameID = strings.TrimSpace(elementText(doc, nidStart, nidEnd))
		if se, ok := doc.tokens[nidStart].(xml.StartElement); ok {
			a.NameIDFormat, _ = attrValue(se, "Format")
		}
	}
	if a.NameID == "" {
		return nil, fmt.Errorf("saml: assertion missing NameID")
	}

	// SubjectConfirmationData: InResponseTo must match our own pending
	// AuthnRequest, and NotOnOrAfter must not have elapsed — this is the
	// primary anti-replay control for SP-initiated SSO.
	if scdStart, scdEnd, ok := findSubjectConfirmationData(doc, subStart, subEnd); ok {
		se := doc.tokens[scdStart].(xml.StartElement)
		if irt, ok := attrValue(se, "InResponseTo"); ok {
			a.InResponseTo = irt
		}
		if noa, ok := attrValue(se, "NotOnOrAfter"); ok {
			t, err := parseSAMLTime(noa)
			if err != nil {
				return nil, fmt.Errorf("saml: invalid SubjectConfirmationData NotOnOrAfter: %w", err)
			}
			if now.After(t.Add(clockSkew)) {
				return nil, fmt.Errorf("saml: subject confirmation expired at %s", t)
			}
		}
		_ = scdEnd
	}
	if expectedRequestID != "" && a.InResponseTo != expectedRequestID {
		return nil, fmt.Errorf("saml: InResponseTo %q does not match the outstanding AuthnRequest", a.InResponseTo)
	}

	condStart, condEnd, ok := doc.findDirectChild(aStart, aEnd, samlNS, "Conditions")
	if ok {
		se := doc.tokens[condStart].(xml.StartElement)
		if nb, ok := attrValue(se, "NotBefore"); ok {
			t, err := parseSAMLTime(nb)
			if err != nil {
				return nil, fmt.Errorf("saml: invalid Conditions NotBefore: %w", err)
			}
			a.NotBefore = t
			if now.Add(clockSkew).Before(t) {
				return nil, fmt.Errorf("saml: assertion not yet valid (NotBefore %s)", t)
			}
		}
		if noa, ok := attrValue(se, "NotOnOrAfter"); ok {
			t, err := parseSAMLTime(noa)
			if err != nil {
				return nil, fmt.Errorf("saml: invalid Conditions NotOnOrAfter: %w", err)
			}
			a.NotOnOrAfter = t
			if now.After(t.Add(clockSkew)) {
				return nil, fmt.Errorf("saml: assertion expired at %s", t)
			}
		}
		if err := checkAudience(doc, condStart, condEnd, spEntityID); err != nil {
			return nil, err
		}
	}

	for _, asRange := range doc.findAllDescendants(aStart, aEnd, samlNS, "AttributeStatement") {
		for _, attrRange := range doc.findAllDescendants(asRange[0], asRange[1], samlNS, "Attribute") {
			se := doc.tokens[attrRange[0]].(xml.StartElement)
			name, _ := attrValue(se, "Name")
			if name == "" {
				name, _ = attrValue(se, "FriendlyName")
			}
			var values []string
			for _, avRange := range doc.findAllDescendants(attrRange[0], attrRange[1], samlNS, "AttributeValue") {
				values = append(values, strings.TrimSpace(elementText(doc, avRange[0], avRange[1])))
			}
			if name != "" {
				a.Attributes[name] = append(a.Attributes[name], values...)
			}
		}
	}

	return a, nil
}

func findSubjectConfirmationData(doc *xmldoc, subStart, subEnd int) (int, int, bool) {
	scStart, scEnd, ok := doc.findDirectChild(subStart, subEnd, samlNS, "SubjectConfirmation")
	if !ok {
		return 0, 0, false
	}
	return doc.findDirectChild(scStart, scEnd, samlNS, "SubjectConfirmationData")
}

func checkAudience(doc *xmldoc, condStart, condEnd int, spEntityID string) error {
	arStart, arEnd, ok := doc.findDirectChild(condStart, condEnd, samlNS, "AudienceRestriction")
	if !ok {
		return nil // no restriction present; nothing to check
	}
	for _, audRange := range doc.findAllDescendants(arStart, arEnd, samlNS, "Audience") {
		if strings.TrimSpace(elementText(doc, audRange[0], audRange[1])) == spEntityID {
			return nil
		}
	}
	return fmt.Errorf("saml: this SP's entityID %q is not in the assertion's AudienceRestriction", spEntityID)
}
