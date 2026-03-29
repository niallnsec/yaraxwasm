// Package exampleutil contains shared helpers used by the runnable examples.
//
// The goal of this package is to keep the example entrypoints small and focused
// on the signed-rules workflow itself. Path resolution, fixture loading, and
// local timestamp-authority support live here so each example can read more
// like a tutorial than a plumbing exercise.
package exampleutil

import (
	"encoding/asn1"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

var (
	// CustomRulesSignerEKU is the private extended-key-usage OID carried by the
	// example rules-signing certificate. The x509 verification example requires
	// this in addition to the standard code-signing EKU.
	CustomRulesSignerEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2312, 19, 1}
	// TimestampPolicyOID is the RFC3161 policy OID written into timestamps
	// produced by the local example TSA.
	TimestampPolicyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2312, 19, 2}
)

const (
	// ExampleRuleSource is the tiny ruleset shared by the export and verify
	// examples. Using one central copy keeps the examples aligned.
	ExampleRuleSource = `rule signed_example {
	strings:
		$needle = "signed-example"
	condition:
		$needle
}`
	// ExampleScanInput is the sample payload scanned after successful
	// verification/loading.
	ExampleScanInput = "this payload contains signed-example bytes"
)

// ExamplesRoot resolves the examples directory at runtime using the location of
// this source file, so the helper works no matter which directory `go run` is
// invoked from.
func ExamplesRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("exampleutil: failed to resolve examples root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// RepoRoot returns the repository root that contains the examples directory.
func RepoRoot() string {
	return filepath.Clean(filepath.Join(ExamplesRoot(), ".."))
}

// PKIDir is the parent directory that stores example PKI assets.
func PKIDir() string {
	return filepath.Join(ExamplesRoot(), "pki")
}

// GeneratedPKIDir is where the PKI bootstrap writes generated certificates,
// keys, and the manifest consumed by the examples.
func GeneratedPKIDir() string {
	return filepath.Join(PKIDir(), "generated")
}

// OutputDir is where the signing examples write signed compiled-rules files.
func OutputDir() string {
	return filepath.Join(ExamplesRoot(), "out")
}

// ManifestPath points at the JSON manifest emitted by the PKI generator.
func ManifestPath() string {
	return filepath.Join(GeneratedPKIDir(), "manifest.json")
}

// Ed25519PrivateKeyPath is the PEM file used by the generic Ed25519 export
// example.
func Ed25519PrivateKeyPath() string {
	return filepath.Join(GeneratedPKIDir(), "ed25519-private.pem")
}

// Ed25519PublicKeyPath is the PEM file consumed by the generic Ed25519 verify
// example.
func Ed25519PublicKeyPath() string {
	return filepath.Join(GeneratedPKIDir(), "ed25519-public.pem")
}

// RootsPath points at the PEM bundle containing the example trust anchor.
func RootsPath() string {
	return filepath.Join(GeneratedPKIDir(), "roots.pem")
}

// RulesSignerKeyPath points at the private key used to CMS-sign compiled rules.
func RulesSignerKeyPath() string {
	return filepath.Join(GeneratedPKIDir(), "rules-signer-key.pem")
}

// RulesSignerChainPath points at the signer leaf plus issuing intermediate.
func RulesSignerChainPath() string {
	return filepath.Join(GeneratedPKIDir(), "rules-signer-chain.pem")
}

// TSAKeyPath points at the private key used by the local timestamp authority.
func TSAKeyPath() string {
	return filepath.Join(GeneratedPKIDir(), "tsa-key.pem")
}

// TSAChainPath points at the TSA leaf plus issuing intermediate.
func TSAChainPath() string {
	return filepath.Join(GeneratedPKIDir(), "tsa-chain.pem")
}

// Ed25519SignedRulesPath is the output file written by the Ed25519 export
// example and consumed by the matching verify example.
func Ed25519SignedRulesPath() string {
	return filepath.Join(OutputDir(), "signed-rules-ed25519.bin")
}

// X509SignedRulesPath is the output file written by the x509 export example and
// consumed by the matching verify example.
func X509SignedRulesPath() string {
	return filepath.Join(OutputDir(), "signed-rules-x509.bin")
}

// EnsureDir creates a directory tree used by the examples.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

// EnsureOutputDir creates the shared example output directory if needed.
func EnsureOutputDir() error {
	return EnsureDir(OutputDir())
}

// RequireX509ExamplePKI checks that the files needed by the x509 examples have
// been generated already and returns a helpful "run init-pki.sh" error when
// they have not.
func RequireX509ExamplePKI() error {
	for _, path := range []string{
		RootsPath(),
		RulesSignerKeyPath(),
		RulesSignerChainPath(),
		TSAKeyPath(),
		TSAChainPath(),
	} {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("missing %s; run %s first", path, filepath.Join(ExamplesRoot(), "init-pki.sh"))
			}
			return err
		}
	}
	return nil
}

// RequiredCustomRulesSignerEKUs returns a copy of the custom EKU slice used by
// the x509 verification example. Returning a copy keeps callers from mutating
// the shared package-level OID by accident.
func RequiredCustomRulesSignerEKUs() []asn1.ObjectIdentifier {
	return []asn1.ObjectIdentifier{append(asn1.ObjectIdentifier(nil), CustomRulesSignerEKU...)}
}
