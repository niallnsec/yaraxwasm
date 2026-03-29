package yaraxwasm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	cmsoid "github.com/github/smimesign/ietf-cms/oid"
	cmsprotocol "github.com/github/smimesign/ietf-cms/protocol"
	cmstimestamp "github.com/github/smimesign/ietf-cms/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignedRulesEd25519RoundTrip(t *testing.T) {
	rules, err := Compile(`rule signed_test { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	generationTime := time.Unix(1_700_000_000, 0).UTC()
	signingTime := generationTime.Add(2 * time.Minute)
	metadata := []byte(`{"kid":"test-ed25519"}`)

	var buf bytes.Buffer
	_, err = rules.WriteSignedTo(
		&buf,
		Ed25519SignedRulesSigner{PrivateKey: privateKey},
		WithSignedMetadata(metadata),
		WithGenerationTime(generationTime),
		WithSigningTime(signingTime),
	)
	require.NoError(t, err)

	verified, err := VerifySignedFrom(bytes.NewReader(buf.Bytes()), Ed25519SignedRulesVerifier{PublicKey: publicKey})
	require.NoError(t, err)
	assert.Equal(t, runtime.GOARCH, verified.Header.CompiledArch)
	assert.Equal(t, generationTime, verified.Header.GenerationTime)
	assert.Equal(t, signingTime, verified.Header.SigningTime)
	assert.Equal(t, SignatureTypeEd25519Raw, verified.Header.SignatureType)
	assert.Equal(t, SignatureHashAlgorithmNone, verified.Header.SignatureHashAlgorithm)
	assert.Equal(t, metadata, verified.Metadata)

	loaded, err := ReadSignedFrom(bytes.NewReader(buf.Bytes()), Ed25519SignedRulesVerifier{PublicKey: publicKey})
	require.NoError(t, err)
	defer loaded.Destroy()

	results, err := loaded.Scan(nil)
	require.NoError(t, err)
	require.Len(t, results.MatchingRules(), 1)
	assert.Equal(t, "signed_test", results.MatchingRules()[0].Identifier())
}

func TestSignedRulesVerifierFuncAdapter(t *testing.T) {
	expectedErr := errors.New("verify boom")
	called := false

	verifier := SignedRulesVerifierFunc(func(header SignedRulesHeader, metadata []byte, signedBytes []byte, signature []byte) error {
		called = true
		assert.Equal(t, SignatureTypeEd25519Raw, header.SignatureType)
		assert.Equal(t, []byte("meta"), metadata)
		assert.Equal(t, []byte("payload"), signedBytes)
		assert.Equal(t, []byte("sig"), signature)
		return expectedErr
	})

	err := verifier.VerifySignedRules(
		SignedRulesHeader{SignatureType: SignatureTypeEd25519Raw},
		[]byte("meta"),
		[]byte("payload"),
		[]byte("sig"),
	)
	require.ErrorIs(t, err, expectedErr)
	assert.True(t, called)

	var nilVerifier SignedRulesVerifierFunc
	err = nilVerifier.VerifySignedRules(SignedRulesHeader{}, nil, nil, nil)
	require.EqualError(t, err, "signed rules verifier is nil")
}

func TestSignedRulesSignerFuncAdapter(t *testing.T) {
	expectedSignature := []byte("signature")
	expectedErr := errors.New("sign boom")
	called := false

	signer := SignedRulesSignerFunc{
		SignatureTypeValue: SignatureTypeCMSDetachedX509,
		HashAlgorithmValue: SignatureHashAlgorithmSHA256,
		SignFunc: func(header SignedRulesHeader, metadata []byte, signedBytes []byte) ([]byte, error) {
			called = true
			assert.Equal(t, SignatureHashAlgorithmSHA256, header.SignatureHashAlgorithm)
			assert.Equal(t, []byte("meta"), metadata)
			assert.Equal(t, []byte("payload"), signedBytes)
			return expectedSignature, expectedErr
		},
	}

	assert.Equal(t, SignatureTypeCMSDetachedX509, signer.SignatureType())
	assert.Equal(t, SignatureHashAlgorithmSHA256, signer.HashAlgorithm())

	signature, err := signer.SignSignedRules(
		SignedRulesHeader{SignatureHashAlgorithm: SignatureHashAlgorithmSHA256},
		[]byte("meta"),
		[]byte("payload"),
	)
	assert.Equal(t, expectedSignature, signature)
	require.ErrorIs(t, err, expectedErr)
	assert.True(t, called)

	signer.SignFunc = nil
	signature, err = signer.SignSignedRules(SignedRulesHeader{}, nil, nil)
	assert.Nil(t, signature)
	require.EqualError(t, err, "signed rules signer is nil")
}

func TestSignedRulesTamperDetection(t *testing.T) {
	rules, err := Compile(`rule signed_test { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signedBytes := mustBuildSignedRulesBytes(
		t,
		rules,
		[]byte("metadata"),
		time.Unix(1_700_000_000, 0).UTC(),
		time.Unix(1_700_000_060, 0).UTC(),
		Ed25519SignedRulesSigner{PrivateKey: privateKey},
		nil,
	)
	header, err := parseSignedRulesHeader(signedBytes[:signedRulesHeaderSize])
	require.NoError(t, err)
	metadataOffset, err := intFromUint64(header.MetadataOffset, "signed rules metadata offset")
	require.NoError(t, err)

	tests := []struct {
		name   string
		offset int
	}{
		{name: "header", offset: 60},
		{name: "payload", offset: signedRulesHeaderSize + 1},
		{name: "metadata", offset: metadataOffset + 1},
		{name: "signature", offset: len(signedBytes) - 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := append([]byte(nil), signedBytes...)
			tampered[tc.offset] ^= 0xFF

			_, err := VerifySignedFrom(bytes.NewReader(tampered), Ed25519SignedRulesVerifier{PublicKey: publicKey})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSignedRulesSignatureVerification)
		})
	}
}

func TestSignedRulesEd25519WrongPublicKeyFails(t *testing.T) {
	rules, err := Compile(`rule signed_test { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	wrongPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NotEqual(t, []byte(publicKey), []byte(wrongPublicKey))

	var buf bytes.Buffer
	_, err = rules.WriteSignedTo(
		&buf,
		Ed25519SignedRulesSigner{PrivateKey: privateKey},
		WithSignedMetadata([]byte(`{"kid":"test-ed25519"}`)),
	)
	require.NoError(t, err)

	_, err = VerifySignedFrom(bytes.NewReader(buf.Bytes()), Ed25519SignedRulesVerifier{PublicKey: wrongPublicKey})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSignedRulesSignatureVerification)
}

func TestReadSignedFromArchMismatch(t *testing.T) {
	rules, err := Compile(`rule signed_test { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	foreignArch := "amd64"
	if runtime.GOARCH == foreignArch {
		foreignArch = "arm64"
	}

	signedBytes := mustBuildSignedRulesBytes(
		t,
		rules,
		nil,
		time.Unix(1_700_000_000, 0).UTC(),
		time.Unix(1_700_000_060, 0).UTC(),
		Ed25519SignedRulesSigner{PrivateKey: privateKey},
		func(header *SignedRulesHeader) {
			header.CompiledArch = foreignArch
		},
	)

	_, err = VerifySignedFrom(bytes.NewReader(signedBytes), Ed25519SignedRulesVerifier{PublicKey: publicKey})
	require.NoError(t, err)

	_, err = ReadSignedFrom(bytes.NewReader(signedBytes), Ed25519SignedRulesVerifier{PublicKey: publicKey})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSignedRulesArchMismatch)
}

func TestX509SignedRulesRoundTrip(t *testing.T) {
	now := time.Now().UTC().Round(0)
	signingPKI := newTestCertificateChain(t, now.Add(-2*time.Hour), now.Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	rules, err := Compile(`rule x509_test { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	applicationMetadata := []byte(`{"kid":"cms-leaf"}`)
	var buf bytes.Buffer
	_, err = rules.WriteX509SignedTo(
		&buf,
		signingPKI.leafKey,
		signingPKI.chainWithoutRoot(),
		WithSignedMetadata(applicationMetadata),
	)
	require.NoError(t, err)

	verified, result, err := VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
		Roots:        signingPKI.rootPool(),
		RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, signingPKI.leaf.SerialNumber, result.Signer.SerialNumber)
	require.NotEmpty(t, result.Chain)

	var envelope x509SignedMetadataEnvelope
	require.NoError(t, json.Unmarshal(verified.Metadata, &envelope))
	assert.Equal(t, x509SignedMetadataVersion, envelope.Version)
	assert.Equal(t, applicationMetadata, envelope.ApplicationMetadata)
	require.Len(t, envelope.SignerChainDER, 2)

	loaded, err := ReadX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
		Roots:        signingPKI.rootPool(),
		RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	require.NoError(t, err)
	defer loaded.Destroy()

	results, err := loaded.Scan(nil)
	require.NoError(t, err)
	require.Len(t, results.MatchingRules(), 1)
	assert.Equal(t, "x509_test", results.MatchingRules()[0].Identifier())
}

func TestX509SignedRulesTamperDetection(t *testing.T) {
	now := time.Now().UTC().Round(0)
	signingPKI := newTestCertificateChain(t, now.Add(-2*time.Hour), now.Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	rules, err := Compile(`rule x509_tamper_test { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	var buf bytes.Buffer
	_, err = rules.WriteX509SignedTo(
		&buf,
		signingPKI.leafKey,
		signingPKI.chainWithoutRoot(),
		WithSignedMetadata([]byte(`{"kid":"cms-leaf"}`)),
		WithGenerationTime(time.Unix(1_700_000_000, 0).UTC()),
		WithSigningTime(time.Unix(1_700_000_060, 0).UTC()),
	)
	require.NoError(t, err)

	signedBytes := buf.Bytes()
	header, err := parseSignedRulesHeader(signedBytes[:signedRulesHeaderSize])
	require.NoError(t, err)
	metadataOffset, err := intFromUint64(header.MetadataOffset, "signed rules metadata offset")
	require.NoError(t, err)

	tests := []struct {
		name   string
		offset int
	}{
		{name: "header", offset: 60},
		{name: "payload", offset: signedRulesHeaderSize + 1},
		{name: "metadata", offset: metadataOffset + 1},
		{name: "signature", offset: len(signedBytes) - 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := append([]byte(nil), signedBytes...)
			tampered[tc.offset] ^= 0xFF

			_, _, err := VerifyX509SignedFrom(bytes.NewReader(tampered), X509VerifyOptions{
				Roots:        signingPKI.rootPool(),
				RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			})
			require.Error(t, err)
		})
	}
}

func TestX509SignedRulesEKUMismatch(t *testing.T) {
	now := time.Now().UTC().Round(0)
	signingPKI := newTestCertificateChain(t, now.Add(-2*time.Hour), now.Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	rules, err := Compile(`rule x509_test { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	var buf bytes.Buffer
	_, err = rules.WriteX509SignedTo(&buf, signingPKI.leafKey, signingPKI.chainWithoutRoot())
	require.NoError(t, err)

	_, _, err = VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
		Roots:        signingPKI.rootPool(),
		RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	})
	require.Error(t, err)
}

func TestX509SignedRulesCustomEKURequirement(t *testing.T) {
	now := time.Now().UTC().Round(0)
	customOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2312, 19, 1}
	signingPKI := newTestCertificateChain(
		t,
		now.Add(-2*time.Hour),
		now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		customOID,
	)

	rules, err := Compile(`rule x509_custom_eku { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	var buf bytes.Buffer
	_, err = rules.WriteX509SignedTo(&buf, signingPKI.leafKey, signingPKI.chainWithoutRoot())
	require.NoError(t, err)

	_, _, err = VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
		Roots:               signingPKI.rootPool(),
		RequiredEKUs:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		RequiredUnknownEKUs: []asn1.ObjectIdentifier{customOID},
	})
	require.NoError(t, err)

	_, _, err = VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
		Roots:               signingPKI.rootPool(),
		RequiredEKUs:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		RequiredUnknownEKUs: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 2312, 19, 2}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required extended key usage")
}

func TestX509SignedRulesCRLPolicies(t *testing.T) {
	now := time.Now().UTC().Round(0)
	signingPKI := newTestCertificateChain(t, now.Add(-2*time.Hour), now.Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	rules, err := Compile(`rule x509_test { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	leafCRL := signingPKI.createCRL(t, signingPKI.intermediate, signingPKI.intermediateKey, nil, now.Add(-10*time.Minute), now.Add(time.Hour))
	intermediateCRL := signingPKI.createCRL(t, signingPKI.root, signingPKI.rootKey, nil, now.Add(-10*time.Minute), now.Add(time.Hour))
	revokedLeafCRL := signingPKI.createCRL(t, signingPKI.intermediate, signingPKI.intermediateKey, []*x509.Certificate{signingPKI.leaf}, now.Add(-10*time.Minute), now.Add(time.Hour))

	t.Run("require complete with valid CRLs", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := rules.WriteX509SignedTo(
			&buf,
			signingPKI.leafKey,
			signingPKI.chainWithoutRoot(),
			WithX509CRLs(leafCRL, intermediateCRL),
		)
		require.NoError(t, err)

		_, _, err = VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
			Roots:        signingPKI.rootPool(),
			RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			CRLPolicy:    X509CRLPolicyRequireComplete,
		})
		require.NoError(t, err)
	})

	t.Run("missing CRL fails", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := rules.WriteX509SignedTo(
			&buf,
			signingPKI.leafKey,
			signingPKI.chainWithoutRoot(),
			WithX509CRLs(leafCRL),
		)
		require.NoError(t, err)

		_, _, err = VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
			Roots:        signingPKI.rootPool(),
			RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			CRLPolicy:    X509CRLPolicyRequireComplete,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrX509SignedRulesCRLRequired)
	})

	t.Run("revoked leaf fails", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := rules.WriteX509SignedTo(
			&buf,
			signingPKI.leafKey,
			signingPKI.chainWithoutRoot(),
			WithX509CRLs(revokedLeafCRL, intermediateCRL),
		)
		require.NoError(t, err)

		_, _, err = VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
			Roots:        signingPKI.rootPool(),
			RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			CRLPolicy:    X509CRLPolicyRequireComplete,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("invalid embedded CRL fails", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := rules.WriteX509SignedTo(
			&buf,
			signingPKI.leafKey,
			signingPKI.chainWithoutRoot(),
			WithX509CRLs([]byte("bad-crl")),
		)
		require.NoError(t, err)

		_, _, err = VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
			Roots:        signingPKI.rootPool(),
			RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			CRLPolicy:    X509CRLPolicyUseIfPresent,
		})
		require.Error(t, err)
	})
}

func TestX509SignedRulesTimestampVerification(t *testing.T) {
	now := time.Now().UTC().Round(0)
	signingPKI := newTestCertificateChain(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})
	tsaPKI := newTestCertificateChain(t, now.Add(-48*time.Hour), now.Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})
	timestampTime := now.Add(-36 * time.Hour).UTC().Round(0).Truncate(time.Second)
	tsa := &testTimestampAuthority{
		t:      t,
		pki:    tsaPKI,
		now:    timestampTime,
		policy: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
	}

	rules, err := Compile(`rule x509_timestamp { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp, err := tsa.Timestamp(body)
		if !assert.NoError(t, err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, err = w.Write(resp)
		assert.NoError(t, err)
	}))
	defer server.Close()

	writeSigned := func(t *testing.T, extraOpts ...X509SignOption) []byte {
		t.Helper()
		var buf bytes.Buffer
		opts := make([]X509SignOption, 0, 3+len(extraOpts))
		opts = append(opts,
			WithGenerationTime(timestampTime.Add(-time.Minute)),
			WithSigningTime(timestampTime),
			WithTimestampAuthority(NewHTTPTimestampAuthority(server.URL, server.Client())),
		)
		opts = append(opts, extraOpts...)
		_, err := rules.WriteX509SignedTo(&buf, signingPKI.leafKey, signingPKI.chainWithoutRoot(), opts...)
		require.NoError(t, err)
		return buf.Bytes()
	}

	t.Run("historical timestamp succeeds", func(t *testing.T) {
		signedBytes := writeSigned(t)

		verified, result, err := VerifyX509SignedFrom(bytes.NewReader(signedBytes), X509VerifyOptions{
			Roots:           signingPKI.rootPool(),
			RequiredEKUs:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			TimestampPolicy: X509TimestampPolicyRequireRFC3161,
			TSARoots:        tsaPKI.rootPool(),
		})
		require.NoError(t, err)
		require.NotNil(t, verified)
		require.NotNil(t, result)
		assert.True(t, result.TimestampVerified)
		assert.Equal(t, timestampTime, result.TimestampTime)

		_, _, err = VerifyX509SignedFrom(bytes.NewReader(signedBytes), X509VerifyOptions{
			Roots:        signingPKI.rootPool(),
			RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		})
		require.Error(t, err)
	})

	t.Run("missing timestamp fails when required", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := rules.WriteX509SignedTo(
			&buf,
			signingPKI.leafKey,
			signingPKI.chainWithoutRoot(),
			WithGenerationTime(timestampTime.Add(-time.Minute)),
			WithSigningTime(timestampTime),
		)
		require.NoError(t, err)

		_, _, err = VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
			Roots:           signingPKI.rootPool(),
			RequiredEKUs:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			TimestampPolicy: X509TimestampPolicyRequireRFC3161,
			TSARoots:        tsaPKI.rootPool(),
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrX509SignedRulesTimestampRequired)
	})

	t.Run("wrong TSA root fails", func(t *testing.T) {
		signedBytes := writeSigned(t)

		_, _, err := VerifyX509SignedFrom(bytes.NewReader(signedBytes), X509VerifyOptions{
			Roots:           signingPKI.rootPool(),
			RequiredEKUs:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			TimestampPolicy: X509TimestampPolicyRequireRFC3161,
			TSARoots:        signingPKI.rootPool(),
		})
		require.Error(t, err)
	})

	t.Run("timestamp with invalid message imprint fails", func(t *testing.T) {
		badTSA := &testTimestampAuthority{
			t:      t,
			pki:    tsaPKI,
			now:    timestampTime,
			policy: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			mutateInfo: func(info *cmstimestamp.Info) {
				info.MessageImprint.HashedMessage = append([]byte(nil), info.MessageImprint.HashedMessage...)
				info.MessageImprint.HashedMessage[0] ^= 0xFF
			},
		}
		signedBytes := writeSigned(t)
		tamperedTimestampBytes := mustReplaceTimestampToken(t, signedBytes, badTSA)

		_, _, err := VerifyX509SignedFrom(bytes.NewReader(tamperedTimestampBytes), X509VerifyOptions{
			Roots:           signingPKI.rootPool(),
			RequiredEKUs:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			TimestampPolicy: X509TimestampPolicyRequireRFC3161,
			TSARoots:        tsaPKI.rootPool(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "message imprint")
	})

	t.Run("timestamp TSA EKU mismatch fails", func(t *testing.T) {
		badTSAPKI := newTestCertificateChain(t, now.Add(-48*time.Hour), now.Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})
		badTSA := &testTimestampAuthority{
			t:      t,
			pki:    badTSAPKI,
			now:    timestampTime,
			policy: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if !assert.NoError(t, err) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp, err := badTSA.Timestamp(body)
			if !assert.NoError(t, err) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/timestamp-reply")
			_, err = w.Write(resp)
			assert.NoError(t, err)
		}))
		defer server.Close()

		var buf bytes.Buffer
		_, err := rules.WriteX509SignedTo(
			&buf,
			signingPKI.leafKey,
			signingPKI.chainWithoutRoot(),
			WithGenerationTime(timestampTime.Add(-time.Minute)),
			WithSigningTime(timestampTime),
			WithTimestampAuthority(NewHTTPTimestampAuthority(server.URL, server.Client())),
		)
		require.NoError(t, err)

		_, _, err = VerifyX509SignedFrom(bytes.NewReader(buf.Bytes()), X509VerifyOptions{
			Roots:           signingPKI.rootPool(),
			RequiredEKUs:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			TimestampPolicy: X509TimestampPolicyRequireRFC3161,
			TSARoots:        badTSAPKI.rootPool(),
		})
		require.Error(t, err)
	})

	t.Run("timestamp skew exceeded fails", func(t *testing.T) {
		signedBytes := writeSigned(t, WithSigningTime(timestampTime.Add(10*time.Minute)))

		_, _, err := VerifyX509SignedFrom(bytes.NewReader(signedBytes), X509VerifyOptions{
			Roots:           signingPKI.rootPool(),
			RequiredEKUs:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			TimestampPolicy: X509TimestampPolicyRequireRFC3161,
			TSARoots:        tsaPKI.rootPool(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "allowed clock skew")
	})
}

func TestHTTPTimestampAuthorityUsesDefaultClientAndValidatesResponses(t *testing.T) {
	t.Run("uses default client when nil", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, timestampQueryContentType, r.Header.Get("Content-Type"))
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			assert.Equal(t, []byte("request"), body)
			w.Header().Set("Content-Type", "application/timestamp-reply")
			_, err = w.Write([]byte("reply"))
			assert.NoError(t, err)
		}))
		defer server.Close()

		authority := NewHTTPTimestampAuthority(server.URL, nil)
		require.NotNil(t, authority)

		response, err := authority.Timestamp([]byte("request"))
		require.NoError(t, err)
		assert.Equal(t, []byte("reply"), response)
	})

	t.Run("rejects empty url", func(t *testing.T) {
		authority := NewHTTPTimestampAuthority("", http.DefaultClient)
		_, err := authority.Timestamp([]byte("request"))
		require.EqualError(t, err, "timestamp authority URL is empty")
	})

	t.Run("rejects non-success status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusBadGateway)
		}))
		defer server.Close()

		authority := NewHTTPTimestampAuthority(server.URL, server.Client())
		_, err := authority.Timestamp([]byte("request"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timestamp authority returned HTTP 502")
	})

	t.Run("rejects unexpected content type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte("reply"))
			assert.NoError(t, err)
		}))
		defer server.Close()

		authority := NewHTTPTimestampAuthority(server.URL, server.Client())
		_, err := authority.Timestamp([]byte("request"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unexpected timestamp authority content type "application/json"`)
	})
}

func TestX509HelperHashAndTimeUtilities(t *testing.T) {
	t.Run("signature hash mapping", func(t *testing.T) {
		tests := []struct {
			name string
			hash crypto.Hash
			want SignatureHashAlgorithm
		}{
			{name: "none", hash: 0, want: SignatureHashAlgorithmNone},
			{name: "sha256", hash: crypto.SHA256, want: SignatureHashAlgorithmSHA256},
			{name: "sha384", hash: crypto.SHA384, want: SignatureHashAlgorithmSHA384},
			{name: "sha512", hash: crypto.SHA512, want: SignatureHashAlgorithmSHA512},
			{name: "unsupported", hash: crypto.SHA3_256, want: SignatureHashAlgorithmUnknown},
			{name: "unknown enum", hash: crypto.Hash(255), want: SignatureHashAlgorithmUnknown},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, signatureHashAlgorithmFromCryptoHash(tc.hash))
			})
		}
	})

	t.Run("effective verification time uses now when zero", func(t *testing.T) {
		before := time.Now().UTC()
		got := effectiveVerificationTime(time.Time{})
		after := time.Now().UTC()

		assert.False(t, got.IsZero())
		assert.Equal(t, time.UTC, got.Location())
		assert.False(t, got.Before(before.Add(-time.Second)))
		assert.False(t, got.After(after.Add(time.Second)))
	})

	t.Run("effective verification time normalizes to utc", func(t *testing.T) {
		input := time.Date(2025, time.January, 2, 3, 4, 5, 6, time.FixedZone("offset", 2*60*60))
		assert.Equal(t, input.UTC().Round(0), effectiveVerificationTime(input))
	})

	t.Run("allowed clock skew", func(t *testing.T) {
		got, err := allowedClockSkew(0)
		require.NoError(t, err)
		assert.Equal(t, defaultTimestampClockSkew, got)

		got, err = allowedClockSkew(3 * time.Second)
		require.NoError(t, err)
		assert.Equal(t, 3*time.Second, got)

		_, err = allowedClockSkew(-time.Second)
		require.EqualError(t, err, "allowed clock skew must be non-negative")
	})
}

func TestX509HelperDigestAlgorithms(t *testing.T) {
	p256Key := mustECDSAKey(t)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name          string
		publicKey     crypto.PublicKey
		wantDigestOID asn1.ObjectIdentifier
		wantHash      crypto.Hash
		wantSignature SignatureHashAlgorithm
		wantErr       string
	}{
		{
			name:          "ecdsa p256",
			publicKey:     &p256Key.PublicKey,
			wantDigestOID: cmsoid.DigestAlgorithmSHA256,
			wantHash:      crypto.SHA256,
			wantSignature: SignatureHashAlgorithmSHA256,
		},
		{
			name:          "ecdsa p384",
			publicKey:     &p384Key.PublicKey,
			wantDigestOID: cmsoid.DigestAlgorithmSHA384,
			wantHash:      crypto.SHA384,
			wantSignature: SignatureHashAlgorithmSHA384,
		},
		{
			name:          "ecdsa p521",
			publicKey:     &p521Key.PublicKey,
			wantDigestOID: cmsoid.DigestAlgorithmSHA512,
			wantHash:      crypto.SHA512,
			wantSignature: SignatureHashAlgorithmSHA512,
		},
		{
			name:          "rsa",
			publicKey:     &rsaKey.PublicKey,
			wantDigestOID: cmsoid.DigestAlgorithmSHA256,
			wantHash:      crypto.SHA256,
			wantSignature: SignatureHashAlgorithmSHA256,
		},
		{
			name:      "unsupported",
			publicKey: ed25519Key.Public(),
			wantErr:   "unsupported CMS signer public key type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotOID, gotHash, gotSignature, err := cmsDigestAlgorithmForPublicKey(tc.publicKey)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.True(t, gotOID.Algorithm.Equal(tc.wantDigestOID))
			assert.Equal(t, tc.wantHash, gotHash)
			assert.Equal(t, tc.wantSignature, gotSignature)
		})
	}

	sha256 := pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA256}
	sha384 := pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA384}

	algorithms := appendDigestAlgorithm(nil, sha256)
	require.Len(t, algorithms, 1)
	assert.True(t, algorithms[0].Algorithm.Equal(cmsoid.DigestAlgorithmSHA256))

	algorithms = appendDigestAlgorithm(algorithms, sha256)
	assert.Len(t, algorithms, 1)

	algorithms = appendDigestAlgorithm(algorithms, sha384)
	assert.Len(t, algorithms, 2)
	assert.True(t, algorithms[1].Algorithm.Equal(cmsoid.DigestAlgorithmSHA384))
}

func TestX509HelperCRLsEKUsAndSignerInfo(t *testing.T) {
	now := time.Now().UTC().Round(0)
	pki := newTestCertificateChain(t, now.Add(-time.Hour), now.Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	t.Run("parse revocation lists deduplicates and rejects empty blobs", func(t *testing.T) {
		crl := pki.createCRL(t, pki.intermediate, pki.intermediateKey, nil, now.Add(-time.Minute), now.Add(time.Hour))

		lists, err := parseRevocationLists([][]byte{crl, crl})
		require.NoError(t, err)
		require.Len(t, lists, 1)

		_, err = parseRevocationLists([][]byte{{}})
		require.EqualError(t, err, "CRL blob is empty")
	})

	t.Run("verify unknown ext key usages", func(t *testing.T) {
		required := []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		certWithOID := &x509.Certificate{UnknownExtKeyUsage: append([]asn1.ObjectIdentifier(nil), required...)}

		require.NoError(t, verifyUnknownExtKeyUsages(certWithOID, required))
		require.NoError(t, verifyUnknownExtKeyUsages(certWithOID, nil))
		require.EqualError(t, verifyUnknownExtKeyUsages(nil, required), "x509 signer certificate is nil")

		err := verifyUnknownExtKeyUsages(&x509.Certificate{}, required)
		require.Error(t, err)
		assert.Contains(t, err.Error(), required[0].String())
	})

	t.Run("signer info helpers", func(t *testing.T) {
		eci, err := cmsprotocol.NewDataEncapsulatedContentInfo([]byte("payload"))
		require.NoError(t, err)

		signedData, err := cmsprotocol.NewSignedData(eci)
		require.NoError(t, err)
		require.NoError(t, addSignerInfoWithTime(signedData, pki.leafKey, pki.chainWithoutRoot(), now))
		require.Len(t, signedData.SignerInfos, 1)

		signatureAlgorithm, err := signerInfoSignatureAlgorithm(signedData.SignerInfos[0])
		require.NoError(t, err)
		assert.NotEqual(t, x509.UnknownSignatureAlgorithm, signatureAlgorithm)

		hasTimestamp, err := signerInfoHasTimestamp(cmsprotocol.SignerInfo{})
		require.NoError(t, err)
		assert.False(t, hasTimestamp)

		timestampAttr, err := cmsprotocol.NewAttribute(cmsoid.AttributeTimeStampToken, []byte("token"))
		require.NoError(t, err)
		hasTimestamp, err = signerInfoHasTimestamp(cmsprotocol.SignerInfo{
			UnsignedAttrs: cmsprotocol.Attributes{timestampAttr},
		})
		require.NoError(t, err)
		assert.True(t, hasTimestamp)

		_, err = signerInfoHasTimestamp(cmsprotocol.SignerInfo{
			UnsignedAttrs: cmsprotocol.Attributes{{
				Type:     cmsoid.AttributeTimeStampToken,
				RawValue: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("bad")},
			}},
		})
		require.Error(t, err)

		_, err = signerInfoSignatureAlgorithm(cmsprotocol.SignerInfo{})
		require.ErrorIs(t, err, cmsprotocol.ErrUnsupported)
	})
}

func mustBuildSignedRulesBytes(
	t *testing.T,
	rules *Rules,
	metadata []byte,
	generationTime time.Time,
	signingTime time.Time,
	signer SignedRulesSigner,
	mutateHeader func(*SignedRulesHeader),
) []byte {
	t.Helper()

	compiledRules, err := rules.serializeBytes()
	require.NoError(t, err)

	header, err := buildSignedRulesHeader(compiledRules, metadata, generationTime, signingTime, signer)
	require.NoError(t, err)
	if mutateHeader != nil {
		mutateHeader(&header)
	}

	headerBytes, err := marshalSignedRulesHeader(header)
	require.NoError(t, err)

	signedBytes := make([]byte, 0, len(headerBytes)+len(compiledRules)+len(metadata))
	signedBytes = append(signedBytes, headerBytes...)
	signedBytes = append(signedBytes, compiledRules...)
	signedBytes = append(signedBytes, metadata...)

	signature, err := signer.SignSignedRules(header, metadata, signedBytes)
	require.NoError(t, err)

	return append(signedBytes, signature...)
}

func mustReplaceTimestampToken(t *testing.T, signedRules []byte, authority TimestampAuthority) []byte {
	t.Helper()

	container, err := parseSignedRulesContainer(signedRules)
	require.NoError(t, err)

	ci, err := cmsprotocol.ParseContentInfo(container.verified.Signature)
	require.NoError(t, err)
	psd, err := ci.SignedDataContent()
	require.NoError(t, err)
	require.Len(t, psd.SignerInfos, 1)

	request, err := buildTimestampRequest(psd.SignerInfos[0])
	require.NoError(t, err)
	requestDER, err := asn1.Marshal(request)
	require.NoError(t, err)

	responseDER, err := authority.Timestamp(requestDER)
	require.NoError(t, err)
	response, err := cmstimestamp.ParseResponse(responseDER)
	require.NoError(t, err)

	attribute, err := cmsprotocol.NewAttribute(cmsoid.AttributeTimeStampToken, response.TimeStampToken)
	require.NoError(t, err)

	replaced := false
	unsignedAttrs := append(cmsprotocol.Attributes(nil), psd.SignerInfos[0].UnsignedAttrs...)
	for i := range unsignedAttrs {
		if unsignedAttrs[i].Type.Equal(cmsoid.AttributeTimeStampToken) {
			unsignedAttrs[i] = attribute
			replaced = true
		}
	}
	require.True(t, replaced, "timestamp token attribute not found")

	psd.SignerInfos[0].UnsignedAttrs = unsignedAttrs
	signature, err := psd.ContentInfoDER()
	require.NoError(t, err)

	out := append([]byte(nil), container.signedBytes...)
	out = append(out, signature...)
	return out
}

type testCertificateChain struct {
	rootKey         *ecdsa.PrivateKey
	root            *x509.Certificate
	intermediateKey *ecdsa.PrivateKey
	intermediate    *x509.Certificate
	leafKey         *ecdsa.PrivateKey
	leaf            *x509.Certificate
}

func newTestCertificateChain(
	t *testing.T,
	leafNotBefore time.Time,
	leafNotAfter time.Time,
	leafEKUs []x509.ExtKeyUsage,
	leafUnknownEKUs ...asn1.ObjectIdentifier,
) *testCertificateChain {
	t.Helper()

	now := time.Now().UTC().Round(0)

	rootKey := mustECDSAKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "yarax-test-root"},
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          []byte("yarax-test-root-ski"),
	}
	root := mustCreateCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	intermediateKey := mustECDSAKey(t)
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "yarax-test-intermediate"},
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		SubjectKeyId:          []byte("yarax-test-intermediate-ski"),
	}
	intermediate := mustCreateCertificate(t, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)

	leafKey := mustECDSAKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "yarax-test-leaf"},
		NotBefore:             leafNotBefore,
		NotAfter:              leafNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage:           append([]x509.ExtKeyUsage(nil), leafEKUs...),
		UnknownExtKeyUsage:    append([]asn1.ObjectIdentifier(nil), leafUnknownEKUs...),
		SubjectKeyId:          []byte("yarax-test-leaf-ski"),
	}
	leaf := mustCreateCertificate(t, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)

	return &testCertificateChain{
		rootKey:         rootKey,
		root:            root,
		intermediateKey: intermediateKey,
		intermediate:    intermediate,
		leafKey:         leafKey,
		leaf:            leaf,
	}
}

func (c *testCertificateChain) chainWithoutRoot() []*x509.Certificate {
	return []*x509.Certificate{c.leaf, c.intermediate}
}

func (c *testCertificateChain) rootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.root)
	return pool
}

func (c *testCertificateChain) createCRL(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	revoked []*x509.Certificate,
	thisUpdate time.Time,
	nextUpdate time.Time,
) []byte {
	t.Helper()

	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, cert := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: thisUpdate.Add(-time.Minute),
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, issuer, issuerKey)
	require.NoError(t, err)
	return der
}

type testTimestampAuthority struct {
	t          *testing.T
	pki        *testCertificateChain
	now        time.Time
	policy     asn1.ObjectIdentifier
	mutateInfo func(*cmstimestamp.Info)
}

func (a *testTimestampAuthority) Timestamp(requestDER []byte) ([]byte, error) {
	a.t.Helper()

	var request cmstimestamp.Request
	_, err := asn1.Unmarshal(requestDER, &request)
	require.NoError(a.t, err)

	info := cmstimestamp.Info{
		Version:        1,
		Policy:         a.policy,
		MessageImprint: request.MessageImprint,
		SerialNumber:   big.NewInt(1),
		GenTime:        a.now,
		Nonce:          request.Nonce,
	}
	if a.mutateInfo != nil {
		a.mutateInfo(&info)
	}

	infoDER, err := asn1.Marshal(info)
	require.NoError(a.t, err)

	eci, err := cmsprotocol.NewEncapsulatedContentInfo(cmsoid.ContentTypeTSTInfo, infoDER)
	require.NoError(a.t, err)

	signedData, err := cmsprotocol.NewSignedData(eci)
	require.NoError(a.t, err)
	require.NoError(a.t, addSignerInfoWithTime(signedData, a.pki.leafKey, a.pki.chainWithoutRoot(), a.now))

	contentInfo, err := signedData.ContentInfo()
	require.NoError(a.t, err)

	return asn1.Marshal(cmstimestamp.Response{
		Status:         cmstimestamp.PKIStatusInfo{Status: 0},
		TimeStampToken: contentInfo,
	})
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func mustCreateCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey *ecdsa.PublicKey,
	signerKey *ecdsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
