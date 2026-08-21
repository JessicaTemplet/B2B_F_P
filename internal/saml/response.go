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
	AssertionID  string
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
// via VerifySAMLResponseSignature), Response/@Destination and
// SubjectConfirmationData/@Recipient (both must match acsURL), a *required*
// Conditions/AudienceRestriction naming spEntityID (documents that omit
// either are rejected, not silently accepted), the NotBefore/NotOnOrAfter
// time window, and — when expectedRequestID is non-empty — that
// InResponseTo matches the AuthnRequest we actually sent (replay/CSRF
// defense for the SP-initiated flow). Single-use replay defense for the
// assertion itself (including IdP-initiated responses, which carry no
// InResponseTo) is the caller's responsibility via store.MarkAssertionUsed
// on the returned Assertion.AssertionID — this function only validates the
// document, it has no persistent state to consult.
func ParseAndVerifyResponse(rawXML []byte, cert *x509.Certificate, spEntityID, acsURL, expectedRequestID string, now time.Time, clockSkew time.Duration) (*Assertion, error) {
	verified, err := VerifySAMLResponseSignature(rawXML, cert)
	if err != nil {
		return nil, err
	}
	doc, raw := verified.doc, verified.raw
	_ = raw
	aStart, aEnd := verified.Start, verified.End

	if rootSE, ok := doc.tokens[verified.responseStart].(xml.StartElement); ok {
		if dest, ok := attrValue(rootSE, "Destination"); ok && dest != acsURL {
			return nil, fmt.Errorf("saml: Response Destination %q does not match this SP's ACS URL %q", dest, acsURL)
		}
	}

	a := &Assertion{Attributes: map[string][]string{}}
	if aSE, ok := doc.tokens[aStart].(xml.StartElement); ok {
		a.AssertionID, _ = attrValue(aSE, "ID")
	}

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

	// SubjectConfirmationData: Recipient must match this SP's ACS URL,
	// InResponseTo must match our own pending AuthnRequest, and
	// NotOnOrAfter must not have elapsed — these are the primary anti-replay
	// and anti-relay controls for SP-initiated SSO.
	scdStart, scdEnd, ok := findSubjectConfirmationData(doc, subStart, subEnd)
	if !ok {
		return nil, fmt.Errorf("saml: assertion missing SubjectConfirmationData")
	}
	se := doc.tokens[scdStart].(xml.StartElement)
	if recipient, ok := attrValue(se, "Recipient"); ok && recipient != acsURL {
		return nil, fmt.Errorf("saml: SubjectConfirmationData Recipient %q does not match this SP's ACS URL %q", recipient, acsURL)
	}
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
	if expectedRequestID != "" && a.InResponseTo != expectedRequestID {
		return nil, fmt.Errorf("saml: InResponseTo %q does not match the outstanding AuthnRequest", a.InResponseTo)
	}

	// Conditions/AudienceRestriction are required, not merely checked when
	// present: an assertion that omits them is rejected rather than treated
	// as unscoped/unbounded. This matters most in multi-tenant deployments
	// where more than one tenant's SP may trust the same IdP certificate —
	// without a required, verified audience, an assertion legitimately
	// issued for one tenant could otherwise be accepted by another.
	condStart, condEnd, ok := doc.findDirectChild(aStart, aEnd, samlNS, "Conditions")
	if !ok {
		return nil, fmt.Errorf("saml: assertion missing Conditions")
	}
	condSE := doc.tokens[condStart].(xml.StartElement)
	if nb, ok := attrValue(condSE, "NotBefore"); ok {
		t, err := parseSAMLTime(nb)
		if err != nil {
			return nil, fmt.Errorf("saml: invalid Conditions NotBefore: %w", err)
		}
		a.NotBefore = t
		if now.Add(clockSkew).Before(t) {
			return nil, fmt.Errorf("saml: assertion not yet valid (NotBefore %s)", t)
		}
	}
	if noa, ok := attrValue(condSE, "NotOnOrAfter"); ok {
		t, err := parseSAMLTime(noa)
		if err != nil {
			return nil, fmt.Errorf("saml: invalid Conditions NotOnOrAfter: %w", err)
		}
		a.NotOnOrAfter = t
		if now.After(t.Add(clockSkew)) {
			return nil, fmt.Errorf("saml: assertion expired at %s", t)
		}
	} else {
		return nil, fmt.Errorf("saml: Conditions missing NotOnOrAfter")
	}
	if err := checkAudience(doc, condStart, condEnd, spEntityID); err != nil {
		return nil, err
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
		return fmt.Errorf("saml: Conditions missing AudienceRestriction")
	}
	for _, audRange := range doc.findAllDescendants(arStart, arEnd, samlNS, "Audience") {
		if strings.TrimSpace(elementText(doc, audRange[0], audRange[1])) == spEntityID {
			return nil
		}
	}
	return fmt.Errorf("saml: this SP's entityID %q is not in the assertion's AudienceRestriction", spEntityID)
}
