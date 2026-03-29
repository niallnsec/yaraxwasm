package main

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"github.com/niallnsec/yaraxwasm"
	"github.com/niallnsec/yaraxwasm/examples/internal/exampleutil"
)

func main() {
	// Load the public key that matches the private key used by the export/sign
	// example. This key is all we need to verify the generic Ed25519 signature.
	publicKey, err := exampleutil.LoadEd25519PublicKey(exampleutil.Ed25519PublicKeyPath())
	if err != nil {
		log.Fatal(err)
	}

	// Read the signed compiled-rules binary produced by
	// go run ./examples/ed25519_export_sign.
	signedRules, err := os.ReadFile(exampleutil.Ed25519SignedRulesPath())
	if err != nil {
		log.Fatal(err)
	}

	// VerifySignedFrom validates the signed container and returns the parsed
	// header, metadata, signature, and compiled-rules payload without yet loading
	// the compiled rules into a scanner-ready Rules object.
	verifier := yaraxwasm.Ed25519SignedRulesVerifier{PublicKey: publicKey}
	verified, err := yaraxwasm.VerifySignedFrom(bytes.NewReader(signedRules), verifier)
	if err != nil {
		log.Fatal(err)
	}

	// ReadSignedFrom performs verification again and then deserializes the
	// verified compiled-rules payload into a usable Rules value. This is the API
	// to use when you want a single "verify then load" step.
	rules, err := yaraxwasm.ReadSignedFrom(bytes.NewReader(signedRules), verifier)
	if err != nil {
		log.Fatal(err)
	}
	defer rules.Destroy()

	// Scan some sample content to show that the verified rules can now be used
	// like any other compiled rules object.
	results, err := rules.Scan([]byte(exampleutil.ExampleScanInput))
	if err != nil {
		log.Fatal(err)
	}

	// Print a few key facts from the verified header plus the scan result so the
	// full workflow is visible when the example is run.
	fmt.Printf("verified Ed25519 signature for %s compiled rules\n", verified.Header.CompiledArch)
	for _, rule := range results.MatchingRules() {
		fmt.Printf("matched rule: %s\n", rule.Identifier())
	}
}
