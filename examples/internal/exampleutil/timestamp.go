package exampleutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	cmsoid "github.com/github/smimesign/ietf-cms/oid"
	cmsprotocol "github.com/github/smimesign/ietf-cms/protocol"
	cmstimestamp "github.com/github/smimesign/ietf-cms/timestamp"
)

// LocalTimestampAuthority is a minimal in-memory RFC3161 timestamp authority
// used by the runnable x509 examples.
//
// The library API expects a TimestampAuthority implementation, and the example
// wants to stay fully local and reproducible. Instead of making network calls
// to a real TSA, this helper signs timestamp responses with the fixture TSA
// certificate created by examples/init-pki.sh.
type LocalTimestampAuthority struct {
	signer        crypto.Signer
	chain         []*x509.Certificate
	timestampTime time.Time
}

// NewLocalTimestampAuthority builds a timestamp authority backed by the given
// signer key and certificate chain.
func NewLocalTimestampAuthority(signer crypto.Signer, chain []*x509.Certificate, timestampTime time.Time) (*LocalTimestampAuthority, error) {
	if signer == nil {
		return nil, errors.New("timestamp signer is nil")
	}
	if len(chain) == 0 {
		return nil, errors.New("timestamp signer chain is empty")
	}
	return &LocalTimestampAuthority{
		signer:        signer,
		chain:         append([]*x509.Certificate(nil), chain...),
		timestampTime: timestampTime.UTC().Round(0),
	}, nil
}

// Timestamp implements the yaraxwasm TimestampAuthority contract.
//
// It accepts an RFC3161 request, copies the caller's message imprint into a new
// timestamp token, and returns a CMS-signed RFC3161 response.
func (a *LocalTimestampAuthority) Timestamp(requestDER []byte) ([]byte, error) {
	if a == nil {
		return nil, errors.New("timestamp authority is nil")
	}

	// Decode the incoming timestamp request so we can preserve the message
	// imprint and nonce in the response.
	var request cmstimestamp.Request
	if _, err := asn1.Unmarshal(requestDER, &request); err != nil {
		return nil, err
	}

	// Use the configured time when provided so example output is predictable.
	// Otherwise fall back to the current time.
	timestampTime := a.timestampTime
	if timestampTime.IsZero() {
		timestampTime = time.Now().UTC().Round(0)
	}

	// Build the TSTInfo payload that will be wrapped by CMS.
	info := cmstimestamp.Info{
		Version:        1,
		Policy:         TimestampPolicyOID,
		MessageImprint: request.MessageImprint,
		SerialNumber:   big.NewInt(timestampTime.UnixNano()),
		GenTime:        timestampTime,
		Nonce:          request.Nonce,
	}

	infoDER, err := asn1.Marshal(info)
	if err != nil {
		return nil, err
	}

	// RFC3161 timestamps are CMS signed-data objects whose content type is
	// id-ct-TSTInfo rather than ordinary data.
	eci, err := cmsprotocol.NewEncapsulatedContentInfo(cmsoid.ContentTypeTSTInfo, infoDER)
	if err != nil {
		return nil, err
	}

	signedData, err := cmsprotocol.NewSignedData(eci)
	if err != nil {
		return nil, err
	}
	if err := addSignedDataSignerInfo(signedData, a.signer, a.chain, timestampTime); err != nil {
		return nil, err
	}

	contentInfo, err := signedData.ContentInfo()
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(cmstimestamp.Response{
		Status:         cmstimestamp.PKIStatusInfo{Status: 0},
		TimeStampToken: contentInfo,
	})
}

// addSignedDataSignerInfo attaches a CMS SignerInfo to the timestamp token.
//
// The logic mirrors what the library does for detached CMS rule signatures, but
// is kept local to the examples so the example TSA can be understood in one
// place without needing access to yaraxwasm internals.
func addSignedDataSignerInfo(sd *cmsprotocol.SignedData, signer crypto.Signer, chain []*x509.Certificate, signingTime time.Time) error {
	cert, signatureAlgorithmID, digestAlgorithmID, hashAlgorithm, err := resolveSignerAlgorithms(signer, chain)
	if err != nil {
		return err
	}

	// Embed the signer certificate chain in the timestamp token so the verifier
	// can build the TSA chain from the token contents plus its configured roots.
	for _, chainCert := range chain {
		if err := sd.AddCertificate(chainCert); err != nil && err.Error() != "certificate already added" {
			return err
		}
	}

	sid, err := cmsprotocol.NewIssuerAndSerialNumber(cert)
	if err != nil {
		return err
	}

	content, err := sd.EncapContentInfo.EContentValue()
	if err != nil {
		return err
	}
	if content == nil {
		return errors.New("timestamp content is already detached")
	}

	// Compute the CMS messageDigest attribute over the encapsulated TSTInfo.
	digest := hashAlgorithm.New()
	if _, err := digest.Write(content); err != nil {
		return err
	}

	signingTimeAttr, err := cmsprotocol.NewAttribute(cmsoid.AttributeSigningTime, signingTime.UTC().Round(0))
	if err != nil {
		return err
	}
	messageDigestAttr, err := cmsprotocol.NewAttribute(cmsoid.AttributeMessageDigest, digest.Sum(nil))
	if err != nil {
		return err
	}
	contentTypeAttr, err := cmsprotocol.NewAttribute(cmsoid.AttributeContentType, sd.EncapContentInfo.EContentType)
	if err != nil {
		return err
	}

	signedAttrs, err := sortAttributes(signingTimeAttr, messageDigestAttr, contentTypeAttr)
	if err != nil {
		return err
	}

	// CMS signs the DER encoding of the signed attributes rather than the raw
	// content whenever SignedAttrs are present.
	signedMessage, err := signedAttrs.MarshaledForSigning()
	if err != nil {
		return err
	}

	toSign := signedMessage
	if hashAlgorithm != 0 {
		// For algorithms like ECDSA and RSA the signer expects a digest of the
		// signed-attributes blob, not the blob itself.
		sum := hashAlgorithm.New()
		if _, err := sum.Write(signedMessage); err != nil {
			return err
		}
		toSign = sum.Sum(nil)
	}

	signature, err := signer.Sign(rand.Reader, toSign, hashAlgorithm)
	if err != nil {
		return err
	}

	sd.DigestAlgorithms = appendDigestAlgorithm(sd.DigestAlgorithms, digestAlgorithmID)
	sd.SignerInfos = append(sd.SignerInfos, cmsprotocol.SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlgorithmID,
		SignedAttrs:        signedAttrs,
		SignatureAlgorithm: signatureAlgorithmID,
		Signature:          signature,
	})

	return nil
}

// resolveSignerAlgorithms finds the certificate that matches the supplied
// private key and derives the digest/signature algorithm identifiers needed for
// CMS signing.
func resolveSignerAlgorithms(signer crypto.Signer, chain []*x509.Certificate) (*x509.Certificate, pkix.AlgorithmIdentifier, pkix.AlgorithmIdentifier, crypto.Hash, error) {
	signerPublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, 0, err
	}

	var signerCert *x509.Certificate
	for _, cert := range chain {
		certPublicKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, 0, err
		}
		if bytes.Equal(signerPublicKey, certPublicKey) {
			signerCert = cert
			break
		}
	}
	if signerCert == nil {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, 0, errors.New("signer certificate does not match timestamp signing key")
	}

	digestAlgorithmID, digestAlgorithm, err := digestAlgorithmForPublicKey(signer.Public())
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, 0, err
	}

	signatureAlgorithmMap, ok := cmsoid.X509PublicKeyAndDigestAlgorithmToSignatureAlgorithm[signerCert.PublicKeyAlgorithm]
	if !ok {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, 0, fmt.Errorf("unsupported timestamp public key algorithm %s", signerCert.PublicKeyAlgorithm)
	}
	signatureAlgorithmOID, ok := signatureAlgorithmMap[digestAlgorithmID.Algorithm.String()]
	if !ok {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, 0, fmt.Errorf("unsupported timestamp digest algorithm %s", digestAlgorithmID.Algorithm)
	}

	return signerCert, pkix.AlgorithmIdentifier{Algorithm: signatureAlgorithmOID}, digestAlgorithmID, digestAlgorithm, nil
}

// digestAlgorithmForPublicKey chooses a sensible CMS digest based on the key
// type and curve size used by the example signer.
func digestAlgorithmForPublicKey(publicKey crypto.PublicKey) (pkix.AlgorithmIdentifier, crypto.Hash, error) {
	if ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey); ok {
		switch ecdsaPublicKey.Curve.Params().BitSize {
		case 384:
			return pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA384}, crypto.SHA384, nil
		case 521:
			return pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA512}, crypto.SHA512, nil
		}
	}

	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA256}, crypto.SHA256, nil
	case *rsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA256}, crypto.SHA256, nil
	default:
		return pkix.AlgorithmIdentifier{}, 0, errors.New("unsupported timestamp signer public key type")
	}
}

// sortAttributes keeps CMS signed attributes in canonical DER order before
// signing.
func sortAttributes(attrs ...cmsprotocol.Attribute) (cmsprotocol.Attributes, error) {
	sort.Slice(attrs, func(i, j int) bool {
		return bytes.Compare(attrs[i].RawValue.FullBytes, attrs[j].RawValue.FullBytes) < 0
	})
	return attrs, nil
}

// appendDigestAlgorithm adds the digest algorithm identifier once even if the
// caller tries to add the same one multiple times.
func appendDigestAlgorithm(existing []pkix.AlgorithmIdentifier, algorithm pkix.AlgorithmIdentifier) []pkix.AlgorithmIdentifier {
	for _, current := range existing {
		if current.Algorithm.Equal(algorithm.Algorithm) {
			return existing
		}
	}
	return append(existing, algorithm)
}
