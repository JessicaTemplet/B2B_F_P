// Command fakeidp simulates a corporate IdP (the role Okta/Entra ID/Ping
// Identity play in production) for local development: it generates a
// signing key pair + SAML IdP metadata file, and can mint a signed
// SAMLResponse for a given tenant/user/attribute set so the gateway's ACS
// endpoint can be exercised end-to-end without a live IdP tenant.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"b2bfp/internal/saml"
)

func main() {
	initCmd := flag.NewFlagSet("init", flag.ExitOnError)
	initEntityID := initCmd.String("entity-id", "https://fake-idp.example.com/entity", "IdP entityID")
	initSSOURL := initCmd.String("sso-url", "http://localhost:8443/__fakeidp_unused__", "SSO redirect binding URL advertised in metadata (informational only)")
	initOut := initCmd.String("out", "policies/fakeidp-metadata.xml", "where to write IdP metadata XML")
	initKeyOut := initCmd.String("key-out", "data/fakeidp.key.pem", "where to write the IdP's private key")

	mintCmd := flag.NewFlagSet("mint-response", flag.ExitOnError)
	mintKeyIn := mintCmd.String("key", "data/fakeidp.key.pem", "IdP private key PEM (from 'init')")
	mintSPEntityID := mintCmd.String("sp-entity-id", "", "the gateway tenant's SP entityID (its /saml/{tenant}/metadata URL)")
	mintACS := mintCmd.String("acs-url", "", "the gateway tenant's ACS URL")
	mintInResponseTo := mintCmd.String("in-response-to", "", "AuthnRequest ID to echo back (from the redirect the gateway sent)")
	mintNameID := mintCmd.String("name-id", "alice@acme-corp.example", "subject NameID (also used as SCIM userName to match)")
	mintDept := mintCmd.String("department", "Engineering", "Department attribute value")
	mintOut := mintCmd.String("out", "", "write the <html><form auto-submit> POST-binding page here instead of stdout")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fakeidp <init|mint-response> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		initCmd.Parse(os.Args[2:])
		runInit(*initEntityID, *initSSOURL, *initOut, *initKeyOut)
	case "mint-response":
		mintCmd.Parse(os.Args[2:])
		runMint(*mintKeyIn, *mintSPEntityID, *mintACS, *mintInResponseTo, *mintNameID, *mintDept, *mintOut)
	default:
		fmt.Fprintln(os.Stderr, "usage: fakeidp <init|mint-response> [flags]")
		os.Exit(2)
	}
}

func runInit(entityID, ssoURL, out, keyOut string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "fake-idp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	must(err)

	must(os.MkdirAll(dirOf(keyOut), 0700))
	must(os.WriteFile(keyOut, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), 0600))

	certB64 := base64.StdEncoding.EncodeToString(der)
	metadata := fmt.Sprintf(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"></md:SingleSignOnService>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`, entityID, certB64, ssoURL)

	must(os.MkdirAll(dirOf(out), 0755))
	must(os.WriteFile(out, []byte(metadata), 0644))
	fmt.Printf("wrote IdP metadata to %s and signing key to %s\n", out, keyOut)
	fmt.Printf("point the tenant's saml_idp_metadata_file config at %s\n", out)
}

func runMint(keyPath, spEntityID, acsURL, inResponseTo, nameID, department, out string) {
	if spEntityID == "" || acsURL == "" {
		fmt.Fprintln(os.Stderr, "mint-response requires -sp-entity-id and -acs-url (see the tenant's GET /saml/{tenant}/metadata)")
		os.Exit(2)
	}
	keyPEM, err := os.ReadFile(keyPath)
	must(err)
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		fatal(fmt.Errorf("no PEM block in %s", keyPath))
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	must(err)
	pub := &priv.PublicKey
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "fake-idp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	must(err)

	assertionID := saml.NewAuthnRequestID()
	now := time.Now().UTC()
	notAfter := now.Add(10 * time.Minute)
	body := fmt.Sprintf(
		`<saml:Issuer>https://fake-idp.example.com/entity</saml:Issuer>`+
			`<saml:Subject>`+
			`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>`+
			`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`+
			`<saml:SubjectConfirmationData InResponseTo="%s" NotOnOrAfter="%s" Recipient="%s"></saml:SubjectConfirmationData>`+
			`</saml:SubjectConfirmation>`+
			`</saml:Subject>`+
			`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">`+
			`<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>`+
			`</saml:Conditions>`+
			`<saml:AttributeStatement>`+
			`<saml:Attribute Name="Department"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>`+
			`</saml:AttributeStatement>`,
		nameID, inResponseTo, fmtTime(notAfter), acsURL, fmtTime(now.Add(-time.Minute)), fmtTime(notAfter), spEntityID, department)

	openTag := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s">`, assertionID, fmtTime(now))
	signedAssertion, err := saml.BuildSignedElementXML(priv, certDER, assertionID, openTag, body, "</saml:Assertion>")
	must(err)

	responseID := saml.NewAuthnRequestID()
	response := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s"><saml:Issuer>https://fake-idp.example.com/entity</saml:Issuer>%s</samlp:Response>`,
		responseID, fmtTime(now), acsURL, signedAssertion)

	respB64 := base64.StdEncoding.EncodeToString([]byte(response))
	page := fmt.Sprintf(`<!doctype html><html><body onload="document.forms[0].submit()">
<form method="POST" action="%s">
<input type="hidden" name="SAMLResponse" value="%s">
</form>
<p>Submitting fake SAML response to %s ...</p>
</body></html>`, acsURL, respB64, acsURL)

	if out == "" {
		fmt.Println(page)
		return
	}
	must(os.WriteFile(out, []byte(page), 0644))
	fmt.Printf("wrote auto-submitting SAMLResponse form to %s\n", out)
}

func fmtTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return "."
}

func must(err error) {
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fakeidp: "+err.Error())
	os.Exit(1)
}
