package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// signEnvelopedForTest exercises the same BuildSignedElementXML production
// code path cmd/fakeidp uses, giving the verifier in
// xmldsig.go/response.go something genuine to check itself against: build
// -> serialize to bytes -> re-parse -> verify.
func signEnvelopedForTest(t *testing.T, priv *rsa.PrivateKey, certDER []byte, id string, openTag string, bodyXML string) string {
	t.Helper()
	signed, err := BuildSignedElementXML(priv, certDER, id, openTag, bodyXML, closingTagOf(t, openTag))
	if err != nil {
		t.Fatalf("BuildSignedElementXML: %v", err)
	}
	return signed
}

func closingTagOf(t *testing.T, openTag string) string {
	t.Helper()
	// openTag looks like `<samlp:Response ...>`; extract "samlp:Response".
	i := 1
	for i < len(openTag) && openTag[i] != ' ' && openTag[i] != '>' {
		i++
	}
	return "</" + openTag[1:i] + ">"
}

func testCA(t *testing.T) (*rsa.PrivateKey, []byte, *x509.Certificate) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return priv, der, cert
}

func buildAssertionBody() string {
	return `<saml:Issuer>https://idp.example.com/entity</saml:Issuer>` +
		`<saml:Subject>` +
		`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@acme-corp.example</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<saml:SubjectConfirmationData InResponseTo="_req123" NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="https://gateway.example.com/saml/acme/acs"></saml:SubjectConfirmationData>` +
		`</saml:SubjectConfirmation>` +
		`</saml:Subject>` +
		`<saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">` +
		`<saml:AudienceRestriction><saml:Audience>https://gateway.example.com/saml/acme/metadata</saml:Audience></saml:AudienceRestriction>` +
		`</saml:Conditions>` +
		`<saml:AttributeStatement>` +
		`<saml:Attribute Name="Department"><saml:AttributeValue>Engineering</saml:AttributeValue></saml:Attribute>` +
		`<saml:Attribute Name="Groups"><saml:AttributeValue>eng-prod-access</saml:AttributeValue><saml:AttributeValue>eng-all</saml:AttributeValue></saml:Attribute>` +
		`</saml:AttributeStatement>`
}

func wrapResponse(assertionXML string) string {
	return `<samlp:Response xmlns:samlp="` + sampNS + `" xmlns:saml="` + samlNS + `" ID="_resp789" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">` +
		`<saml:Issuer>https://idp.example.com/entity</saml:Issuer>` +
		assertionXML +
		`</samlp:Response>`
}

func TestSignAndVerify_AssertionLevelSignature(t *testing.T) {
	priv, certDER, cert := testCA(t)
	assertionOpen := `<saml:Assertion xmlns:saml="` + samlNS + `" ID="_assert456" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">`
	signedAssertion := signEnvelopedForTest(t, priv, certDER, "_assert456", assertionOpen, buildAssertionBody())
	fullResponse := wrapResponse(signedAssertion)

	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	a, err := ParseAndVerifyResponse([]byte(fullResponse), cert, "https://gateway.example.com/saml/acme/metadata", "_req123", now, 2*time.Minute)
	if err != nil {
		t.Fatalf("expected valid signature, got error: %v", err)
	}
	if a.NameID != "alice@acme-corp.example" {
		t.Errorf("unexpected NameID: %q", a.NameID)
	}
	if got := a.Attributes["Department"]; len(got) != 1 || got[0] != "Engineering" {
		t.Errorf("unexpected Department attribute: %v", got)
	}
	if got := a.Attributes["Groups"]; len(got) != 2 {
		t.Errorf("expected 2 Groups values, got %v", got)
	}
}

func TestVerify_RejectsTamperedAttribute(t *testing.T) {
	priv, certDER, cert := testCA(t)
	assertionOpen := `<saml:Assertion xmlns:saml="` + samlNS + `" ID="_assert456" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">`
	signedAssertion := signEnvelopedForTest(t, priv, certDER, "_assert456", assertionOpen, buildAssertionBody())
	// Tamper: escalate the signed-in user's department after signing.
	tampered := []byte(signedAssertion)
	tamperedStr := string(tampered)
	tamperedStr = replaceOnce(tamperedStr, "Engineering", "SuperAdmin")
	fullResponse := wrapResponse(tamperedStr)

	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := ParseAndVerifyResponse([]byte(fullResponse), cert, "https://gateway.example.com/saml/acme/metadata", "_req123", now, 2*time.Minute)
	if err == nil {
		t.Fatal("expected signature verification to fail on tampered content, got nil error")
	}
}

func TestVerify_RejectsWrongSigningCert(t *testing.T) {
	priv, certDER, _ := testCA(t)
	_, _, wrongCert := testCA(t) // different key pair
	assertionOpen := `<saml:Assertion xmlns:saml="` + samlNS + `" ID="_assert456" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">`
	signedAssertion := signEnvelopedForTest(t, priv, certDER, "_assert456", assertionOpen, buildAssertionBody())
	fullResponse := wrapResponse(signedAssertion)

	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := ParseAndVerifyResponse([]byte(fullResponse), wrongCert, "https://gateway.example.com/saml/acme/metadata", "_req123", now, 2*time.Minute)
	if err == nil {
		t.Fatal("expected verification against the wrong cert to fail")
	}
}

func TestVerify_RejectsSignatureWrappingViaExtraAssertion(t *testing.T) {
	priv, certDER, cert := testCA(t)
	assertionOpen := `<saml:Assertion xmlns:saml="` + samlNS + `" ID="_assert456" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">`
	signedAssertion := signEnvelopedForTest(t, priv, certDER, "_assert456", assertionOpen, buildAssertionBody())

	// Classic XSW: smuggle a second, unsigned, attacker-controlled Assertion
	// into the Response alongside the legitimately signed one.
	evilAssertion := `<saml:Assertion xmlns:saml="` + samlNS + `" ID="_evil" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">` +
		`<saml:Issuer>https://idp.example.com/entity</saml:Issuer>` +
		`<saml:Subject><saml:NameID>attacker@evil.example</saml:NameID></saml:Subject>` +
		`<saml:AttributeStatement><saml:Attribute Name="Department"><saml:AttributeValue>SuperAdmin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` +
		`</saml:Assertion>`
	fullResponse := `<samlp:Response xmlns:samlp="` + sampNS + `" xmlns:saml="` + samlNS + `" ID="_resp789" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">` +
		`<saml:Issuer>https://idp.example.com/entity</saml:Issuer>` +
		evilAssertion + signedAssertion +
		`</samlp:Response>`

	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := ParseAndVerifyResponse([]byte(fullResponse), cert, "https://gateway.example.com/saml/acme/metadata", "_req123", now, 2*time.Minute)
	if err == nil {
		t.Fatal("expected multi-assertion response (XSW attempt) to be rejected")
	}
}

func TestVerify_RejectsExpiredAssertion(t *testing.T) {
	priv, certDER, cert := testCA(t)
	assertionOpen := `<saml:Assertion xmlns:saml="` + samlNS + `" ID="_assert456" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">`
	signedAssertion := signEnvelopedForTest(t, priv, certDER, "_assert456", assertionOpen, buildAssertionBody())
	fullResponse := wrapResponse(signedAssertion)

	longAfterExpiry := time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := ParseAndVerifyResponse([]byte(fullResponse), cert, "https://gateway.example.com/saml/acme/metadata", "_req123", longAfterExpiry, 2*time.Minute)
	if err == nil {
		t.Fatal("expected expired assertion to be rejected")
	}
}

func TestVerify_RejectsWrongInResponseTo(t *testing.T) {
	priv, certDER, cert := testCA(t)
	assertionOpen := `<saml:Assertion xmlns:saml="` + samlNS + `" ID="_assert456" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">`
	signedAssertion := signEnvelopedForTest(t, priv, certDER, "_assert456", assertionOpen, buildAssertionBody())
	fullResponse := wrapResponse(signedAssertion)

	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := ParseAndVerifyResponse([]byte(fullResponse), cert, "https://gateway.example.com/saml/acme/metadata", "_some_other_request_id", now, 2*time.Minute)
	if err == nil {
		t.Fatal("expected mismatched InResponseTo to be rejected (replay/CSRF defense)")
	}
}

func replaceOnce(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
