package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/niallnsec/yaraxwasm"
	"github.com/niallnsec/yaraxwasm/examples/internal/exampleutil"
)

func main() {
	// The x509 verification example expects the PKI and signed artifact produced
	// by ./examples/init-pki.sh and ./examples/x509_export_sign.
	if err := exampleutil.RequireX509ExamplePKI(); err != nil {
		log.Fatal(err)
	}

	// Load the root CA bundle that should be trusted for both the rules-signing
	// chain and the TSA chain.
	roots, err := exampleutil.LoadCertPool(exampleutil.RootsPath())
	if err != nil {
		log.Fatal(err)
	}
	// Read the x509/CMS-backed signed compiled-rules binary from disk.
	signedRules, err := os.ReadFile(exampleutil.X509SignedRulesPath())
	if err != nil {
		log.Fatal(err)
	}

	// Configure verification policy.
	//
	// This example requires:
	//   - a valid chain to the configured roots
	//   - the standard code-signing EKU
	//   - the custom rules-signing EKU OID carried by the example signer cert
	//   - a valid RFC3161 timestamp token chaining to the same root bundle
	verifyOptions := yaraxwasm.X509VerifyOptions{
		Roots:               roots,
		RequiredEKUs:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		RequiredUnknownEKUs: exampleutil.RequiredCustomRulesSignerEKUs(),
		TimestampPolicy:     yaraxwasm.X509TimestampPolicyRequireRFC3161,
		TSARoots:            roots,
	}

	// VerifyX509SignedFrom exposes the parsed container plus rich x509 results so
	// callers can inspect the signer identity, chain, and verified timestamp.
	verified, result, err := yaraxwasm.VerifyX509SignedFrom(bytes.NewReader(signedRules), verifyOptions)
	if err != nil {
		log.Fatal(err)
	}

	// ReadX509SignedFrom is the "verify then load" convenience API for x509/CMS
	// signed containers. It verifies the signature and policies above, checks the
	// compiled-rules architecture, and then deserializes the verified rules.
	rules, err := yaraxwasm.ReadX509SignedFrom(bytes.NewReader(signedRules), verifyOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer rules.Destroy()

	// Demonstrate that the verified rules are now ready for ordinary scanning.
	results, err := rules.Scan([]byte(exampleutil.ExampleScanInput))
	if err != nil {
		log.Fatal(err)
	}

	// Print the signer identity and trusted timestamp so the x509-specific parts
	// of the workflow are visible when the example runs.
	fmt.Printf("verified x509 signature for %s compiled rules\n", verified.Header.CompiledArch)
	fmt.Printf("signer subject: %s\n", result.Signer.Subject.String())
	fmt.Printf("timestamp: %s\n", result.TimestampTime.Format(time.RFC3339))
	for _, rule := range results.MatchingRules() {
		fmt.Printf("matched rule: %s\n", rule.Identifier())
	}
}
