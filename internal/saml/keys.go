package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// LoadOrCreateSPKeyPair reads the SP's signing key/cert from PEM files,
// generating a fresh self-signed key pair on first run if they don't exist
// yet. In production these should be provisioned by real PKI tooling and
// rotated on a schedule; self-generation here just means the gateway can
// come up cleanly on a fresh checkout without a manual openssl step.
func LoadOrCreateSPKeyPair(keyPath, certPath, entityID string) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	keyPEM, keyErr := os.ReadFile(keyPath)
	certPEM, certErr := os.ReadFile(certPath)
	if keyErr == nil && certErr == nil {
		priv, err := parseRSAKeyPEM(keyPEM)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse SP key %s: %w", keyPath, err)
		}
		der, err := parseCertPEM(certPEM)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse SP cert %s: %w", certPath, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, nil, err
		}
		return priv, cert, der, nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: entityID},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), 0600); err != nil {
		return nil, nil, nil, fmt.Errorf("write SP key: %w", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return nil, nil, nil, fmt.Errorf("write SP cert: %w", err)
	}
	return priv, cert, der, nil
}

func parseRSAKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PEM key is not an RSA private key")
	}
	return rsaKey, nil
}

func parseCertPEM(data []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return block.Bytes, nil
}
