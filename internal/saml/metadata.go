package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
)

const mdNS = "urn:oasis:names:tc:SAML:2.0:metadata"

// IdPMetadata is what the SP needs from a corporate IdP's published
// metadata document: where to send AuthnRequests, and which certificate(s)
// to trust for verifying its signed responses.
type IdPMetadata struct {
	EntityID            string
	SSORedirectURL      string
	SSOPostURL          string
	SigningCertificates []*x509.Certificate
}

// ParseIdPMetadata parses a SAML 2.0 IdP metadata XML document (as
// downloaded from Okta's "Identity Provider metadata" link, Entra ID's
// federation metadata endpoint, PingOne's SSO connection metadata, etc).
func ParseIdPMetadata(data []byte) (*IdPMetadata, error) {
	doc, err := parseXMLDoc(data)
	if err != nil {
		return nil, err
	}
	rootStart, rootEnd, ok := rootRange(doc)
	if !ok {
		return nil, fmt.Errorf("saml metadata: empty document")
	}
	rootSE := doc.tokens[rootStart].(xml.StartElement)
	if rootSE.Name.Local != "EntityDescriptor" || rootSE.Name.Space != mdNS {
		return nil, fmt.Errorf("saml metadata: root element is not md:EntityDescriptor")
	}
	entityID, _ := attrValue(rootSE, "entityID")
	if entityID == "" {
		return nil, fmt.Errorf("saml metadata: missing entityID")
	}
	idpStart, idpEnd, ok := doc.findDirectChild(rootStart, rootEnd, mdNS, "IDPSSODescriptor")
	if !ok {
		return nil, fmt.Errorf("saml metadata: no IDPSSODescriptor")
	}

	m := &IdPMetadata{EntityID: entityID}

	for _, ssoRange := range doc.findAllDescendants(idpStart, idpEnd, mdNS, "SingleSignOnService") {
		se := doc.tokens[ssoRange[0]].(xml.StartElement)
		binding, _ := attrValue(se, "Binding")
		loc, _ := attrValue(se, "Location")
		switch binding {
		case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":
			m.SSORedirectURL = loc
		case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
			m.SSOPostURL = loc
		}
	}
	if m.SSORedirectURL == "" && m.SSOPostURL == "" {
		return nil, fmt.Errorf("saml metadata: no usable SingleSignOnService binding found")
	}

	for _, kdRange := range doc.findAllDescendants(idpStart, idpEnd, mdNS, "KeyDescriptor") {
		se := doc.tokens[kdRange[0]].(xml.StartElement)
		use, hasUse := attrValue(se, "use")
		if hasUse && use != "signing" {
			continue
		}
		for _, certRange := range doc.findAllDescendants(kdRange[0], kdRange[1], dsNS, "X509Certificate") {
			b64 := strings.Join(strings.Fields(elementText(doc, certRange[0], certRange[1])), "")
			der, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			m.SigningCertificates = append(m.SigningCertificates, cert)
		}
	}
	if len(m.SigningCertificates) == 0 {
		return nil, fmt.Errorf("saml metadata: no signing certificate found")
	}
	return m, nil
}
