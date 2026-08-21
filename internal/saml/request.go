package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SP holds this gateway's own SAML Service Provider identity for one
// tenant: its entityID, ACS URL, and the key pair it signs AuthnRequests
// with.
type SP struct {
	EntityID   string
	ACSURL     string
	PrivateKey *rsa.PrivateKey
	Cert       *x509.Certificate
	CertDER    []byte
}

// NewAuthnRequestID generates a SAML-legal ID: NCName cannot start with a
// digit, so it's prefixed with an underscore.
func NewAuthnRequestID() string {
	return "_" + strings.ReplaceAll(uuid.NewString(), "-", "")
}

func buildAuthnRequestXML(id, spEntityID, acsURL, destination string, issueInstant time.Time) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<samlp:AuthnRequest xmlns:samlp="%s" xmlns:saml="%s" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">`,
		sampNS, samlNS, id, issueInstant.UTC().Format(timeLayout), xmlEscapeAttrString(destination), xmlEscapeAttrString(acsURL))
	fmt.Fprintf(&b, `<saml:Issuer>%s</saml:Issuer>`, xmlEscapeTextString(spEntityID))
	b.WriteString(`<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"></samlp:NameIDPolicy>`)
	b.WriteString(`</samlp:AuthnRequest>`)
	return b.Bytes()
}

func xmlEscapeAttrString(s string) string { return escapeAttr(s) }
func xmlEscapeTextString(s string) string { return escapeText(s) }

// BuildRedirectURL implements the SAML HTTP-Redirect binding (§3.4 of
// saml-bindings-2.0-os): deflate the AuthnRequest, base64-encode it, and —
// because this SP always signs its requests — append SigAlg and a
// Signature computed over the exact query-string bytes
// "SAMLRequest=...&RelayState=...&SigAlg=..." as required by the spec.
// This is the standard mechanism for a "signed AuthnRequest" carried over a
// GET redirect; it does not require embedding an XML-DSig <ds:Signature>
// inside the request body.
func (sp *SP) BuildRedirectURL(idp *IdPMetadata, relayState string) (redirectURL, requestID string, err error) {
	if idp.SSORedirectURL == "" {
		return "", "", fmt.Errorf("saml: IdP metadata has no HTTP-Redirect SSO binding")
	}
	requestID = NewAuthnRequestID()
	reqXML := buildAuthnRequestXML(requestID, sp.EntityID, sp.ACSURL, idp.SSORedirectURL, time.Now())

	var deflated bytes.Buffer
	fw, err := flate.NewWriter(&deflated, flate.BestCompression)
	if err != nil {
		return "", "", err
	}
	if _, err := fw.Write(reqXML); err != nil {
		return "", "", err
	}
	if err := fw.Close(); err != nil {
		return "", "", err
	}
	samlRequestB64 := base64.StdEncoding.EncodeToString(deflated.Bytes())

	const sigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	qs := "SAMLRequest=" + url.QueryEscape(samlRequestB64)
	if relayState != "" {
		qs += "&RelayState=" + url.QueryEscape(relayState)
	}
	qs += "&SigAlg=" + url.QueryEscape(sigAlg)

	digest := sha256.Sum256([]byte(qs))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, sp.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", "", fmt.Errorf("sign AuthnRequest: %w", err)
	}
	qs += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sigBytes))

	return idp.SSORedirectURL + "?" + qs, requestID, nil
}

// VerifyRedirectSignature checks a SAML HTTP-Redirect-bound message's query
// string signature (used if this gateway ever needs to validate signed
// LogoutRequests/Responses from the IdP over the redirect binding).
func VerifyRedirectSignature(rawQuery string, cert *x509.Certificate) error {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return err
	}
	sigB64 := values.Get("Signature")
	sigAlg := values.Get("SigAlg")
	if sigB64 == "" || sigAlg == "" {
		return fmt.Errorf("saml: missing Signature/SigAlg on redirect binding message")
	}
	hash, ok := sigAlgByURI[sigAlg]
	if !ok {
		return fmt.Errorf("saml: unsupported SigAlg %q", sigAlg)
	}
	// Reconstruct exactly the signed bytes: the ordered param subset,
	// still percent-encoded as received, excluding Signature itself.
	parts := []string{}
	for _, key := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg"} {
		if v := values.Get(key); v != "" {
			parts = append(parts, key+"="+url.QueryEscape(v))
		}
	}
	signedBytes := []byte(strings.Join(parts, "&"))
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("saml: invalid Signature base64: %w", err)
	}
	digest := hashBytes(hash, signedBytes)
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("saml: only RSA IdP certs supported")
	}
	return rsa.VerifyPKCS1v15(pub, hash, digest, sigBytes)
}

// InflateAndDecodeSAMLMessage reverses the redirect binding's
// base64+DEFLATE encoding (used for SAMLRequest/SAMLResponse params).
func InflateAndDecodeSAMLMessage(b64 string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("saml: invalid base64: %w", err)
	}
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	return io.ReadAll(r)
}

// SPMetadataXML renders this SP's own metadata document, for the corporate
// IdP administrator to upload when configuring the SSO connection.
func (sp *SP) SPMetadataXML() []byte {
	certB64 := base64.StdEncoding.EncodeToString(sp.CertDER)
	var b bytes.Buffer
	fmt.Fprintf(&b, `<md:EntityDescriptor xmlns:md="%s" xmlns:ds="%s" entityID="%s">`, mdNS, dsNS, xmlEscapeAttrString(sp.EntityID))
	b.WriteString(`<md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`)
	b.WriteString(`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>`)
	b.WriteString(certB64)
	b.WriteString(`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
	fmt.Fprintf(&b, `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"></md:AssertionConsumerService>`,
		xmlEscapeAttrString(sp.ACSURL))
	b.WriteString(`</md:SPSSODescriptor></md:EntityDescriptor>`)
	return b.Bytes()
}
