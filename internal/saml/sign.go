package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// BuildSignedElementXML wraps bodyXML (the child content of the element
// opened by openTag, which must carry an ID="..." attribute) in an
// enveloped XML-DSig <ds:Signature>, computed the same way this package's
// own verifier checks it (see xmldsig.go). This SP itself never needs to
// sign an assertion — only an IdP does — but it's exported here (rather
// than only living in a _test.go file) so cmd/fakeidp can use it to
// simulate a real corporate IdP for local development and demos, without
// needing a second, drifted implementation of XML-DSig signing.
func BuildSignedElementXML(priv *rsa.PrivateKey, certDER []byte, id, openTag, bodyXML, closeTag string) (string, error) {
	unsigned := openTag + bodyXML + closeTag
	unsignedDoc, err := parseXMLDoc([]byte(unsigned))
	if err != nil {
		return "", fmt.Errorf("sign: parse unsigned element: %w", err)
	}
	raw, err := captureRawTags([]byte(unsigned))
	if err != nil {
		return "", fmt.Errorf("sign: capture raw tags: %w", err)
	}
	start, end, ok := rootRange(unsignedDoc)
	if !ok {
		return "", fmt.Errorf("sign: no root element")
	}
	canonicalTarget, err := canonicalize(unsignedDoc, raw, start, end, nil)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	digest := sha256.Sum256(canonicalTarget)
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	signedInfo := fmt.Sprintf(
		`<ds:SignedInfo xmlns:ds="%s"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#%s"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>%s</ds:DigestValue></ds:Reference></ds:SignedInfo>`,
		dsNS, id, digestB64)

	siDoc, err := parseXMLDoc([]byte(signedInfo))
	if err != nil {
		return "", fmt.Errorf("sign: parse SignedInfo: %w", err)
	}
	siRaw, err := captureRawTags([]byte(signedInfo))
	if err != nil {
		return "", fmt.Errorf("sign: capture SignedInfo raw tags: %w", err)
	}
	siStart, siEnd, _ := rootRange(siDoc)
	canonicalSignedInfo, err := canonicalize(siDoc, siRaw, siStart, siEnd, nil)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	siDigest := sha256.Sum256(canonicalSignedInfo)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, siDigest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	signatureXML := fmt.Sprintf(
		`<ds:Signature xmlns:ds="%s">%s<ds:SignatureValue>%s</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`,
		dsNS, signedInfo, sigB64, certB64)

	return openTag + signatureXML + bodyXML + closeTag, nil
}
