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
	// The Ed25519 example keeps its key pair under examples/pki/generated.
	// EnsureEd25519KeyPair creates one on first run and then reuses it so that
	// the matching verification example can load the same public key later.
	privateKey, _, err := exampleutil.EnsureEd25519KeyPair()
	if err != nil {
		log.Fatal(err)
	}
	// Store the signed compiled rules under examples/out so the verify example
	// can load the exact file produced here.
	if err := exampleutil.EnsureOutputDir(); err != nil {
		log.Fatal(err)
	}

	// Compile a small sample ruleset into YARA-X's native serialized format.
	// At this point we only have compiled rules bytes, not a signed container.
	rules, err := yaraxwasm.Compile(exampleutil.ExampleRuleSource)
	if err != nil {
		log.Fatal(err)
	}
	defer rules.Destroy()

	// Create the output file that will receive:
	//   signed header || compiled rules || metadata || signature
	out, err := os.Create(exampleutil.Ed25519SignedRulesPath())
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	// The signed container records both generation and signing timestamps.
	// In this simple example we use the same current UTC time for both.
	now := time.Now().UTC().Round(0).Truncate(time.Second)
	// WriteSignedTo wraps the compiled rules in the signed transport format and
	// signs the header + payload with the Ed25519 private key.
	//
	// The metadata field is optional and opaque to the generic API. Here we use
	// a tiny JSON blob just to show where application-specific metadata can go.
	if _, err := rules.WriteSignedTo(
		out,
		yaraxwasm.Ed25519SignedRulesSigner{PrivateKey: privateKey},
		yaraxwasm.WithSignedMetadata([]byte(`{"signer":"examples-ed25519"}`)),
		yaraxwasm.WithGenerationTime(now),
		yaraxwasm.WithSigningTime(now),
	); err != nil {
		log.Fatal(err)
	}

	// Print the file locations so a reader can immediately run the matching
	// verification example against the generated artifact.
	fmt.Printf("wrote Ed25519-signed compiled rules to %s\n", exampleutil.Ed25519SignedRulesPath())
	fmt.Printf("public key written to %s\n", exampleutil.Ed25519PublicKeyPath())
}
