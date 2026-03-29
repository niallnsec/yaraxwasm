package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/niallnsec/yaraxwasm"
	"github.com/niallnsec/yaraxwasm/examples/internal/exampleutil"
)

func main() {
	// The x509 examples depend on the local fixture PKI produced by
	// ./examples/init-pki.sh. That script creates a root, intermediates, a leaf
	// certificate for rule signing, and a second leaf certificate for timestamping.
	if err := exampleutil.RequireX509ExamplePKI(); err != nil {
		log.Fatal(err)
	}
	// The signed binary is written into examples/out so the verify example can
	// consume the exact file produced here.
	if err := exampleutil.EnsureOutputDir(); err != nil {
		log.Fatal(err)
	}

	// Load the private key and the certificate chain used to sign the compiled
	// rules. The chain contains the signer leaf first, followed by its issuing
	// intermediate. Roots are intentionally not embedded.
	signer, err := exampleutil.LoadSigner(exampleutil.RulesSignerKeyPath())
	if err != nil {
		log.Fatal(err)
	}
	signerChain, err := exampleutil.LoadCertificatesFromPEMFile(exampleutil.RulesSignerChainPath())
	if err != nil {
		log.Fatal(err)
	}

	// Load a separate TSA certificate and key. The x509 helper expects an
	// RFC3161 timestamp authority, so this example creates a tiny local in-memory
	// TSA rather than depending on an external timestamping service.
	tsaSigner, err := exampleutil.LoadSigner(exampleutil.TSAKeyPath())
	if err != nil {
		log.Fatal(err)
	}
	tsaChain, err := exampleutil.LoadCertificatesFromPEMFile(exampleutil.TSAChainPath())
	if err != nil {
		log.Fatal(err)
	}

	// The signing time recorded in the signed header is also used as the TSA
	// generation time here so the example has a deterministic relationship
	// between the file header and the timestamp token.
	signingTime := time.Now().UTC().Round(0).Truncate(time.Second)
	timestampAuthority, err := exampleutil.NewLocalTimestampAuthority(tsaSigner, tsaChain, signingTime)
	if err != nil {
		log.Fatal(err)
	}

	// Compile the example ruleset into YARA-X's serialized native format.
	rules, err := yaraxwasm.Compile(exampleutil.ExampleRuleSource)
	if err != nil {
		log.Fatal(err)
	}
	defer rules.Destroy()

	// Create the signed container output file.
	out, err := os.Create(exampleutil.X509SignedRulesPath())
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	// WriteX509SignedTo wraps the compiled rules in the signed container format
	// and appends a detached CMS signature. This example also:
	//   - embeds small application metadata
	//   - records explicit generation/signing times in the header
	//   - obtains an RFC3161 timestamp token from the local TSA
	if _, err := rules.WriteX509SignedTo(
		out,
		signer,
		signerChain,
		yaraxwasm.WithSignedMetadata([]byte(`{"signer":"examples-x509"}`)),
		yaraxwasm.WithGenerationTime(signingTime.Add(-30*time.Second)),
		yaraxwasm.WithSigningTime(signingTime),
		yaraxwasm.WithTimestampAuthority(timestampAuthority),
	); err != nil {
		log.Fatal(err)
	}

	// The generated signer certificate carries both the standard code-signing EKU
	// and a custom EKU OID. The matching verification example requires both.
	fmt.Printf("wrote x509-signed compiled rules to %s\n", exampleutil.X509SignedRulesPath())
	fmt.Printf("signer subject: %s\n", signerChain[0].Subject.String())
	fmt.Printf("required custom EKU OID: %s\n", exampleutil.CustomRulesSignerEKU.String())
}
