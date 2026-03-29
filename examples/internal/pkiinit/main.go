package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"path/filepath"
	"time"

	"github.com/niallnsec/yaraxwasm/examples/internal/exampleutil"
)

type manifest struct {
	GeneratedAt          string            `json:"generatedAt"`
	CustomRulesSignerEKU string            `json:"customRulesSignerEKU"`
	Files                map[string]string `json:"files"`
}

type serialCounter struct {
	next int64
}

func main() {
	outDir := flag.String("out", exampleutil.GeneratedPKIDir(), "directory to write generated PKI files into")
	flag.Parse()

	// This generator builds a small self-contained PKI purely for the examples.
	// The output includes:
	//   - a root CA
	//   - a signing intermediate and leaf certificate for rules signing
	//   - a TSA intermediate and leaf certificate for RFC3161 timestamping
	//   - an Ed25519 keypair for the generic signature examples
	if err := exampleutil.EnsureDir(*outDir); err != nil {
		log.Fatal(err)
	}

	now := time.Now().UTC().Round(0).Truncate(time.Second)
	serials := &serialCounter{next: 1}

	// Create a long-lived self-signed root CA that anchors both chains.
	rootKey := mustECDSAKey()
	rootTemplate := &x509.Certificate{
		SerialNumber:          serials.Next(),
		Subject:               pkix.Name{CommonName: "yaraxwasm examples root CA", Organization: []string{"yaraxwasm examples"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          mustSubjectKeyID(&rootKey.PublicKey),
	}
	root := mustCreateCertificate(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	// Create the intermediate CA used to issue the rules-signing certificate.
	signingIntermediateKey := mustECDSAKey()
	signingIntermediateTemplate := &x509.Certificate{
		SerialNumber:          serials.Next(),
		Subject:               pkix.Name{CommonName: "yaraxwasm examples signing intermediate", Organization: []string{"yaraxwasm examples"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		SubjectKeyId:          mustSubjectKeyID(&signingIntermediateKey.PublicKey),
		AuthorityKeyId:        root.SubjectKeyId,
	}
	signingIntermediate := mustCreateCertificate(signingIntermediateTemplate, root, &signingIntermediateKey.PublicKey, rootKey)

	// Create a separate intermediate for timestamping so the TSA chain is
	// distinct from the rules-signing chain.
	tsaIntermediateKey := mustECDSAKey()
	tsaIntermediateTemplate := &x509.Certificate{
		SerialNumber:          serials.Next(),
		Subject:               pkix.Name{CommonName: "yaraxwasm examples TSA intermediate", Organization: []string{"yaraxwasm examples"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		SubjectKeyId:          mustSubjectKeyID(&tsaIntermediateKey.PublicKey),
		AuthorityKeyId:        root.SubjectKeyId,
	}
	tsaIntermediate := mustCreateCertificate(tsaIntermediateTemplate, root, &tsaIntermediateKey.PublicKey, rootKey)

	// Issue the leaf certificate used to sign compiled rules. It includes both
	// the normal code-signing EKU and the custom EKU demonstrated by the examples.
	rulesSignerKey := mustECDSAKey()
	rulesSignerTemplate := &x509.Certificate{
		SerialNumber:          serials.Next(),
		Subject:               pkix.Name{CommonName: "yaraxwasm examples rules signer", Organization: []string{"yaraxwasm examples"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{exampleutil.CustomRulesSignerEKU},
		SubjectKeyId:          mustSubjectKeyID(&rulesSignerKey.PublicKey),
		AuthorityKeyId:        signingIntermediate.SubjectKeyId,
	}
	rulesSigner := mustCreateCertificate(rulesSignerTemplate, signingIntermediate, &rulesSignerKey.PublicKey, signingIntermediateKey)

	// Issue the TSA leaf used by the local in-memory RFC3161 timestamp service.
	tsaKey := mustECDSAKey()
	tsaTemplate := &x509.Certificate{
		SerialNumber:          serials.Next(),
		Subject:               pkix.Name{CommonName: "yaraxwasm examples TSA", Organization: []string{"yaraxwasm examples"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		SubjectKeyId:          mustSubjectKeyID(&tsaKey.PublicKey),
		AuthorityKeyId:        tsaIntermediate.SubjectKeyId,
	}
	tsa := mustCreateCertificate(tsaTemplate, tsaIntermediate, &tsaKey.PublicKey, tsaIntermediateKey)

	// Generate a simple Ed25519 key pair for the generic signed-rules examples.
	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// Write PEM files in the layout expected by the example helper package.
	must(exampleutil.WriteCertificatesPEM(filepath.Join(*outDir, "roots.pem"), root))
	must(exampleutil.WriteCertificatesPEM(filepath.Join(*outDir, "rules-signer.pem"), rulesSigner))
	must(exampleutil.WritePrivateKeyPEM(filepath.Join(*outDir, "rules-signer-key.pem"), rulesSignerKey))
	must(exampleutil.WriteCertificatesPEM(filepath.Join(*outDir, "rules-signer-chain.pem"), rulesSigner, signingIntermediate))
	must(exampleutil.WriteCertificatesPEM(filepath.Join(*outDir, "tsa.pem"), tsa))
	must(exampleutil.WritePrivateKeyPEM(filepath.Join(*outDir, "tsa-key.pem"), tsaKey))
	must(exampleutil.WriteCertificatesPEM(filepath.Join(*outDir, "tsa-chain.pem"), tsa, tsaIntermediate))
	must(exampleutil.WriteCertificatesPEM(filepath.Join(*outDir, "signing-intermediate.pem"), signingIntermediate))
	must(exampleutil.WriteCertificatesPEM(filepath.Join(*outDir, "tsa-intermediate.pem"), tsaIntermediate))
	must(exampleutil.WritePrivateKeyPEM(filepath.Join(*outDir, "ed25519-private.pem"), ed25519PrivateKey))
	must(exampleutil.WritePublicKeyPEM(filepath.Join(*outDir, "ed25519-public.pem"), ed25519PublicKey))

	// Record the generated file locations in a small manifest so someone poking
	// around the examples directory can quickly see what was created.
	files := map[string]string{
		"roots":                 filepath.Join(*outDir, "roots.pem"),
		"rulesSignerCert":       filepath.Join(*outDir, "rules-signer.pem"),
		"rulesSignerKey":        filepath.Join(*outDir, "rules-signer-key.pem"),
		"rulesSignerChain":      filepath.Join(*outDir, "rules-signer-chain.pem"),
		"tsaCert":               filepath.Join(*outDir, "tsa.pem"),
		"tsaKey":                filepath.Join(*outDir, "tsa-key.pem"),
		"tsaChain":              filepath.Join(*outDir, "tsa-chain.pem"),
		"ed25519PrivateKey":     filepath.Join(*outDir, "ed25519-private.pem"),
		"ed25519PublicKey":      filepath.Join(*outDir, "ed25519-public.pem"),
		"signingIntermediate":   filepath.Join(*outDir, "signing-intermediate.pem"),
		"timestampIntermediate": filepath.Join(*outDir, "tsa-intermediate.pem"),
	}
	must(exampleutil.WriteJSON(filepath.Join(*outDir, "manifest.json"), manifest{
		GeneratedAt:          now.Format(time.RFC3339),
		CustomRulesSignerEKU: exampleutil.CustomRulesSignerEKU.String(),
		Files:                files,
	}))

	manifestJSON, err := json.MarshalIndent(manifest{
		GeneratedAt:          now.Format(time.RFC3339),
		CustomRulesSignerEKU: exampleutil.CustomRulesSignerEKU.String(),
		Files:                files,
	}, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	// Print the manifest to stdout so running the script doubles as a quick
	// inspection step for the generated example PKI.
	fmt.Printf("wrote example PKI to %s\n", *outDir)
	fmt.Printf("custom signer EKU: %s\n", exampleutil.CustomRulesSignerEKU.String())
	fmt.Printf("%s\n", manifestJSON)
}

func (c *serialCounter) Next() *big.Int {
	serial := big.NewInt(c.next)
	c.next++
	return serial
}

func mustECDSAKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func mustCreateCertificate(template *x509.Certificate, parent *x509.Certificate, publicKey crypto.PublicKey, signerKey crypto.Signer) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signerKey)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func mustSubjectKeyID(publicKey crypto.PublicKey) []byte {
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}
	sum := sha1.Sum(spki)
	return sum[:]
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
