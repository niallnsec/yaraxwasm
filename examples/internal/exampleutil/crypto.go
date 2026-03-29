package exampleutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// EnsureEd25519KeyPair loads the example Ed25519 key pair if it already exists
// and otherwise generates and persists one under examples/pki/generated.
//
// The export and verify examples share this key pair so they can be run in
// separate commands while still operating on the same signed artifact.
func EnsureEd25519KeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	// Prefer reusing previously generated keys so the matching verify example can
	// always load the public key that corresponds to the export example output.
	if _, err := os.Stat(Ed25519PrivateKeyPath()); err == nil {
		privateKey, err := LoadEd25519PrivateKey(Ed25519PrivateKeyPath())
		if err != nil {
			return nil, nil, err
		}
		publicKey, err := LoadEd25519PublicKey(Ed25519PublicKeyPath())
		if err != nil {
			return nil, nil, err
		}
		return privateKey, publicKey, nil
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}

	if err := EnsureDir(GeneratedPKIDir()); err != nil {
		return nil, nil, err
	}

	// If no fixture keys exist yet, generate a fresh pair and write both halves
	// to disk in standard PEM encodings.
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := WritePrivateKeyPEM(Ed25519PrivateKeyPath(), privateKey); err != nil {
		return nil, nil, err
	}
	if err := WritePublicKeyPEM(Ed25519PublicKeyPath(), publicKey); err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

// LoadEd25519PrivateKey loads an Ed25519 private key from a PEM file.
func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	key, err := LoadSigner(path)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an Ed25519 private key", path)
	}
	return privateKey, nil
}

// LoadEd25519PublicKey loads an Ed25519 public key from a PEM file.
func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	block, err := readPEMBlock(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an Ed25519 public key", path)
	}
	return ed25519Key, nil
}

// LoadSigner loads a PEM-encoded private key and returns it as a crypto.Signer.
//
// The examples accept PKCS#8, SEC1 EC, and PKCS#1 RSA private keys so the
// helper remains convenient even if the fixture generation method changes.
func LoadSigner(path string) (crypto.Signer, error) {
	block, err := readPEMBlock(path, "")
	if err != nil {
		return nil, err
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s does not contain a signing private key", path)
		}
		return signer, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key from %s", path)
}

// LoadCertificatesFromPEMFile parses every CERTIFICATE block from a PEM file.
//
// This is used for both signer chains and TSA chains, where the file contains
// more than one certificate in leaf-first order.
func LoadCertificatesFromPEMFile(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for len(raw) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		raw = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return certs, nil
}

// LoadCertPool loads one or more PEM certificates into a new trust pool.
func LoadCertPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

// WritePrivateKeyPEM stores a private key in PKCS#8 PEM format.
func WritePrivateKeyPEM(path string, key any) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEMFile(path, "PRIVATE KEY", der)
}

// WritePublicKeyPEM stores a public key in PKIX PEM format.
func WritePublicKeyPEM(path string, key any) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	return writePEMFile(path, "PUBLIC KEY", der)
}

// WriteCertificatesPEM writes one or more certificates to a PEM file.
func WriteCertificatesPEM(path string, certs ...*x509.Certificate) error {
	if err := EnsureDir(filepathDir(path)); err != nil {
		return err
	}
	var raw []byte
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		raw = append(raw, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if len(raw) == 0 {
		return errors.New("no certificates to write")
	}
	return os.WriteFile(path, raw, 0o644)
}

// WriteJSON writes an indented JSON file terminated by a trailing newline so it
// is convenient to inspect in a terminal or editor.
func WriteJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := EnsureDir(filepathDir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

// readPEMBlock reads the first PEM block from a file and optionally enforces an
// expected block type.
func readPEMBlock(path string, expectedType string) (*pem.Block, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", path)
	}
	if expectedType != "" && block.Type != expectedType {
		return nil, fmt.Errorf("expected %s PEM block in %s, got %s", expectedType, path, block.Type)
	}
	return block, nil
}

// writePEMFile writes one PEM block to disk, creating parent directories as
// needed. Private keys use restrictive file permissions because they are
// intended to be loaded directly by the example programs.
func writePEMFile(path string, blockType string, der []byte) error {
	if err := EnsureDir(filepathDir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600)
}

// filepathDir is a tiny local equivalent of filepath.Dir that keeps the helper
// package dependency surface intentionally small and easy to follow in the
// examples.
func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == os.PathSeparator {
			if i == 0 {
				return string(os.PathSeparator)
			}
			return path[:i]
		}
	}
	return "."
}

// signerDescription returns a short human-readable name for a signer key type.
// It is mainly useful when debugging or extending the examples.
func signerDescription(signer crypto.Signer) string {
	switch signer.(type) {
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case *rsa.PrivateKey:
		return "RSA"
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", signer)
	}
}
