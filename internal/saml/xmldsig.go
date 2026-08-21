package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

const (
	dsNS   = "http://www.w3.org/2000/09/xmldsig#"
	samlNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	sampNS = "urn:oasis:names:tc:SAML:2.0:protocol"
)

// SHA-1-based DigestMethod/SignatureMethod algorithms are deliberately not
// in these maps. SHA-1 is deprecated industry-wide for digital signatures
// (practical chosen-prefix collisions), and this gateway has no legacy IdP
// that requires it — accepting it by default would mean the algorithm
// strength actually enforced is whatever the IdP's connection metadata
// happens to negotiate, not a gateway-enforced minimum. If a real
// deployment needs SHA-1 for an old IdP, add it back deliberately here
// rather than defaulting to it.
var digestAlgByURI = map[string]crypto.Hash{
	"http://www.w3.org/2001/04/xmlenc#sha256":       crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#sha256": crypto.SHA256,
}

var sigAlgByURI = map[string]crypto.Hash{
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": crypto.SHA256,
}

// VerifiedAssertion is the outcome of successfully validating a SAMLResponse's
// signature: the exact token range of the Assertion element whose ID was
// covered by a verified Reference digest and SignatureValue. Callers must
// only ever extract claims from this range, never by re-searching the
// document for "an Assertion element" — that reopens the signature-wrapping
// hole this package is designed to close.
type VerifiedAssertion struct {
	doc           *xmldoc
	raw           map[int][]byte
	Start         int
	End           int
	responseStart int
	responseEnd   int
}

// VerifySAMLResponseSignature parses rawXML as a SAMLResponse and verifies
// it was signed by the holder of cert's private key, defending against the
// classic XML Signature Wrapping (XSW) attack pattern by construction:
//
//  1. Exactly one <Assertion> is permitted in the document. Multi-assertion
//     responses (a hallmark of several XSW variants) are rejected outright.
//  2. A Signature is only accepted if its Reference URI points at the ID of
//     the element that structurally contains it (Response or Assertion) —
//     i.e. it must be a "same object" enveloped signature, not a reference
//     to a look-alike element elsewhere in the document.
//  3. Trust is anchored entirely in the cert the caller passes in (from the
//     tenant's pre-registered IdP metadata). Any <ds:KeyInfo>/X509Certificate
//     embedded in the response itself is ignored for trust purposes — an
//     attacker who can forge a response can just as easily embed their own
//     certificate in it.
//  4. Attributes/NameID are only ever read from the returned VerifiedAssertion
//     token range, which is exactly the element whose digest was checked.
func VerifySAMLResponseSignature(rawXML []byte, cert *x509.Certificate) (*VerifiedAssertion, error) {
	doc, err := parseXMLDoc(rawXML)
	if err != nil {
		return nil, err
	}
	raw, err := captureRawTags(rawXML)
	if err != nil {
		return nil, err
	}
	rootStart, rootEnd, ok := rootRange(doc)
	if !ok {
		return nil, errors.New("saml: empty document")
	}
	rootSE := doc.tokens[rootStart].(xml.StartElement)
	if rootSE.Name.Local != "Response" || rootSE.Name.Space != sampNS {
		return nil, fmt.Errorf("saml: root element is not samlp:Response")
	}

	assertions := doc.findAllDescendants(rootStart, rootEnd, samlNS, "Assertion")
	if len(assertions) != 1 {
		return nil, fmt.Errorf("saml: expected exactly 1 Assertion, found %d", len(assertions))
	}
	aStart, aEnd := assertions[0][0], assertions[0][1]

	respSigStart, respSigEnd, respSigned := doc.findDirectChild(rootStart, rootEnd, dsNS, "Signature")
	assertSigStart, assertSigEnd, assertSigned := doc.findDirectChild(aStart, aEnd, dsNS, "Signature")

	if !respSigned && !assertSigned {
		return nil, errors.New("saml: neither Response nor Assertion is signed")
	}
	if respSigned {
		if err := verifyEnvelopedSignature(doc, raw, rootStart, rootEnd, respSigStart, respSigEnd, cert); err != nil {
			return nil, fmt.Errorf("saml: Response signature invalid: %w", err)
		}
	}
	if assertSigned {
		if err := verifyEnvelopedSignature(doc, raw, aStart, aEnd, assertSigStart, assertSigEnd, cert); err != nil {
			return nil, fmt.Errorf("saml: Assertion signature invalid: %w", err)
		}
	}
	return &VerifiedAssertion{doc: doc, raw: raw, Start: aStart, End: aEnd, responseStart: rootStart, responseEnd: rootEnd}, nil
}

func rootRange(d *xmldoc) (int, int, bool) {
	for i, t := range d.tokens {
		if _, ok := t.(xml.StartElement); ok {
			if end, ok := d.matchEnd[i]; ok {
				return i, end, true
			}
		}
	}
	return 0, 0, false
}

// findDirectChild is like findDescendant but only matches elements at
// exactly one level below [start,end] — used so a Signature nested deeper
// inside (e.g. smuggled inside an Extensions block) is never mistaken for
// the element's own enveloped signature.
func (d *xmldoc) findDirectChild(start, end int, space, local string) (int, int, bool) {
	i := start + 1
	for i < end {
		se, ok := d.tokens[i].(xml.StartElement)
		if !ok {
			i++
			continue
		}
		e := d.matchEnd[i]
		if se.Name.Local == local && se.Name.Space == space {
			return i, e, true
		}
		i = e + 1
	}
	return 0, 0, false
}

// verifyEnvelopedSignature checks that (sigStart,sigEnd), found as a direct
// child of (parentStart,parentEnd), is a valid enveloped XML-DSig signature
// over its parent, verified against cert.
func verifyEnvelopedSignature(doc *xmldoc, raw map[int][]byte, parentStart, parentEnd, sigStart, sigEnd int, cert *x509.Certificate) error {
	parentSE := doc.tokens[parentStart].(xml.StartElement)
	parentID, ok := attrValue(parentSE, "ID")
	if !ok || parentID == "" {
		return errors.New("signed element has no ID attribute")
	}

	siStart, siEnd, ok := doc.findDirectChild(sigStart, sigEnd, dsNS, "SignedInfo")
	if !ok {
		return errors.New("Signature missing SignedInfo")
	}
	refStart, refEnd, ok := doc.findDirectChild(siStart, siEnd, dsNS, "Reference")
	if !ok {
		return errors.New("SignedInfo missing Reference")
	}
	refSE := doc.tokens[refStart].(xml.StartElement)
	uri, _ := attrValue(refSE, "URI")
	if strings.TrimPrefix(uri, "#") != parentID {
		return fmt.Errorf("Reference URI %q does not match signed element's own ID %q (possible signature wrapping attempt)", uri, parentID)
	}

	dmStart, _, ok := doc.findDirectChild(refStart, refEnd, dsNS, "DigestMethod")
	if !ok {
		return errors.New("Reference missing DigestMethod")
	}
	dmSE := doc.tokens[dmStart].(xml.StartElement)
	digestAlgURI, _ := attrValue(dmSE, "Algorithm")
	digestHash, ok := digestAlgByURI[digestAlgURI]
	if !ok {
		return fmt.Errorf("unsupported DigestMethod algorithm %q", digestAlgURI)
	}
	dvStart, dvEnd, ok := doc.findDirectChild(refStart, refEnd, dsNS, "DigestValue")
	if !ok {
		return errors.New("Reference missing DigestValue")
	}
	wantDigest, err := base64.StdEncoding.DecodeString(strings.TrimSpace(elementText(doc, dvStart, dvEnd)))
	if err != nil {
		return fmt.Errorf("invalid DigestValue base64: %w", err)
	}

	// Enveloped-signature transform: canonicalize the parent element with
	// the Signature subtree itself excluded.
	canonicalTarget, err := canonicalize(doc, raw, parentStart, parentEnd, map[int]bool{sigStart: true})
	if err != nil {
		return err
	}
	gotDigest := hashBytes(digestHash, canonicalTarget)
	if !hmacEqual(gotDigest, wantDigest) {
		return errors.New("digest mismatch: signed content does not match Reference DigestValue")
	}

	smStart, _, ok := doc.findDirectChild(siStart, siEnd, dsNS, "SignatureMethod")
	if !ok {
		return errors.New("SignedInfo missing SignatureMethod")
	}
	smSE := doc.tokens[smStart].(xml.StartElement)
	sigAlgURI, _ := attrValue(smSE, "Algorithm")
	sigHash, ok := sigAlgByURI[sigAlgURI]
	if !ok {
		return fmt.Errorf("unsupported SignatureMethod algorithm %q", sigAlgURI)
	}

	svStart, svEnd, ok := doc.findDirectChild(sigStart, sigEnd, dsNS, "SignatureValue")
	if !ok {
		return errors.New("Signature missing SignatureValue")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(elementText(doc, svStart, svEnd)))
	if err != nil {
		return fmt.Errorf("invalid SignatureValue base64: %w", err)
	}

	canonicalSignedInfo, err := canonicalize(doc, raw, siStart, siEnd, nil)
	if err != nil {
		return err
	}
	digest := hashBytes(sigHash, canonicalSignedInfo)

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("only RSA IdP signing certificates are supported")
	}
	if err := rsa.VerifyPKCS1v15(pub, sigHash, digest, sigBytes); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

func hashBytes(alg crypto.Hash, data []byte) []byte {
	switch alg {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		return h[:]
	}
	return nil
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
