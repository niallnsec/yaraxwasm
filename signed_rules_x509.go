package yaraxwasm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
	cmsoid "github.com/github/smimesign/ietf-cms/oid"
	cmsprotocol "github.com/github/smimesign/ietf-cms/protocol"
	cmstimestamp "github.com/github/smimesign/ietf-cms/timestamp"
)

const (
	x509SignedMetadataVersion   = 1
	defaultTimestampClockSkew   = 5 * time.Minute
	timestampQueryContentType   = "application/timestamp-query"
	timestampReplyContentPrefix = "application/timestamp-reply"
)

var (
	ErrX509SignedRulesInvalidMetadata   = errors.New("invalid x509 signed rules metadata")
	ErrX509SignedRulesTimestampRequired = errors.New("x509 signed rules timestamp is required")
	ErrX509SignedRulesCRLRequired       = errors.New("x509 signed rules CRL is required")
)

// X509CRLPolicy controls how CRLs are enforced during x509 verification.
type X509CRLPolicy uint8

const (
	X509CRLPolicyDisabled X509CRLPolicy = iota
	X509CRLPolicyUseIfPresent
	X509CRLPolicyRequireComplete
)

// X509TimestampPolicy controls RFC3161 timestamp enforcement during x509
// verification.
type X509TimestampPolicy uint8

const (
	X509TimestampPolicyDisabled X509TimestampPolicy = iota
	X509TimestampPolicyVerifyIfPresent
	X509TimestampPolicyRequireRFC3161
)

// X509VerifyOptions configures [VerifyX509SignedFrom].
type X509VerifyOptions struct {
	Roots                   *x509.CertPool
	AdditionalIntermediates *x509.CertPool
	RequiredEKUs            []x509.ExtKeyUsage
	RequiredUnknownEKUs     []asn1.ObjectIdentifier
	CurrentTime             time.Time
	CRLPolicy               X509CRLPolicy
	AdditionalCRLs          [][]byte
	TimestampPolicy         X509TimestampPolicy
	TSARoots                *x509.CertPool
	TSAIntermediates        *x509.CertPool
	AllowedClockSkew        time.Duration
}

// X509VerificationResult describes the signer and timestamp state for a
// verified x509/CMS signed rules container.
type X509VerificationResult struct {
	Signer            *x509.Certificate
	Chain             []*x509.Certificate
	TimestampVerified bool
	TimestampTime     time.Time
}

// TimestampAuthority acquires RFC3161 timestamp responses for detached CMS
// signatures.
type TimestampAuthority interface {
	Timestamp(requestDER []byte) ([]byte, error)
}

// X509SignOption configures [Rules.WriteX509SignedTo].
type X509SignOption interface {
	applyX509SignOption(*x509SignOptions) error
}

type x509SignOptions struct {
	applicationMetadata []byte
	generationTime      time.Time
	signingTime         time.Time
	crlsDER             [][]byte
	timestampAuthority  TimestampAuthority
}

type x509CRLsOption struct {
	crls [][]byte
}

func (o x509CRLsOption) applyX509SignOption(opts *x509SignOptions) error {
	opts.crlsDER = cloneByteSlices(o.crls)
	return nil
}

type x509TimestampAuthorityOption struct {
	authority TimestampAuthority
}

func (o x509TimestampAuthorityOption) applyX509SignOption(opts *x509SignOptions) error {
	if o.authority == nil {
		return errors.New("timestamp authority is nil")
	}
	opts.timestampAuthority = o.authority
	return nil
}

// WithX509CRLs embeds CRL DER blobs in the x509 metadata envelope written by
// [Rules.WriteX509SignedTo].
func WithX509CRLs(crls ...[]byte) X509SignOption {
	return x509CRLsOption{crls: cloneByteSlices(crls)}
}

// WithTimestampAuthority configures an RFC3161 timestamp authority for
// [Rules.WriteX509SignedTo].
func WithTimestampAuthority(authority TimestampAuthority) X509SignOption {
	return x509TimestampAuthorityOption{authority: authority}
}

type x509SignedMetadataEnvelope struct {
	Version             int      `json:"version"`
	ApplicationMetadata []byte   `json:"applicationMetadata,omitempty"`
	SignerChainDER      [][]byte `json:"signerChainDER,omitempty"`
	CRLsDER             [][]byte `json:"crlsDER,omitempty"`
}

type cmsDetachedX509Signer struct {
	signer             crypto.Signer
	chain              []*x509.Certificate
	hashAlgorithm      SignatureHashAlgorithm
	timestampAuthority TimestampAuthority
}

// SignatureType implements [SignedRulesSigner].
func (s *cmsDetachedX509Signer) SignatureType() SignatureType {
	return SignatureTypeCMSDetachedX509
}

// HashAlgorithm implements [SignedRulesSigner].
func (s *cmsDetachedX509Signer) HashAlgorithm() SignatureHashAlgorithm {
	return s.hashAlgorithm
}

// SignSignedRules implements [SignedRulesSigner].
func (s *cmsDetachedX509Signer) SignSignedRules(header SignedRulesHeader, _ []byte, signedBytes []byte) ([]byte, error) {
	return buildDetachedCMSSignature(signedBytes, s.signer, s.chain, header.SigningTime, s.timestampAuthority)
}

// WriteX509SignedTo writes the compiled rules into an x509/CMS-backed signed
// rules container.
func (r *Rules) WriteX509SignedTo(w io.Writer, signer crypto.Signer, chain []*x509.Certificate, opts ...X509SignOption) (int64, error) {
	if signer == nil {
		return 0, errors.New("x509 signed rules signer is nil")
	}

	compiledRules, err := r.serializeBytes()
	if err != nil {
		return 0, err
	}

	cfg, err := newX509SignOptions(opts...)
	if err != nil {
		return 0, err
	}

	filteredChain := stripSelfSignedRoots(chain)
	if len(filteredChain) == 0 {
		return 0, errors.New("x509 signer chain is empty")
	}

	envelope := x509SignedMetadataEnvelope{
		Version:             x509SignedMetadataVersion,
		ApplicationMetadata: append([]byte(nil), cfg.applicationMetadata...),
		SignerChainDER:      certificatesToDER(filteredChain),
		CRLsDER:             cloneByteSlices(cfg.crlsDER),
	}
	metadata, err := json.Marshal(envelope)
	if err != nil {
		return 0, err
	}

	cmsSigner, err := newCMSDetachedX509Signer(signer, filteredChain, cfg.timestampAuthority)
	if err != nil {
		return 0, err
	}

	return writeSignedRules(w, compiledRules, metadata, cfg.generationTime, cfg.signingTime, cmsSigner)
}

// VerifyX509SignedFrom verifies an x509/CMS-backed signed rules container.
func VerifyX509SignedFrom(r io.Reader, opts X509VerifyOptions) (*VerifiedSignedRules, *X509VerificationResult, error) {
	container, err := readAndParseSignedRules(r)
	if err != nil {
		return nil, nil, err
	}

	envelope, certs, err := parseX509MetadataEnvelope(container.verified.Metadata)
	if err != nil {
		return nil, nil, err
	}

	result, err := verifyDetachedCMSSignedRules(
		container.verified.Header,
		container.signedBytes,
		container.verified.Signature,
		certs,
		append(cloneByteSlices(envelope.CRLsDER), cloneByteSlices(opts.AdditionalCRLs)...),
		opts,
	)
	if err != nil {
		return nil, nil, err
	}

	return container.verified, result, nil
}

// ReadX509SignedFrom verifies an x509/CMS-backed signed rules container and
// loads the verified compiled rules.
func ReadX509SignedFrom(r io.Reader, opts X509VerifyOptions) (*Rules, error) {
	verified, _, err := VerifyX509SignedFrom(r, opts)
	if err != nil {
		return nil, err
	}
	if verified.Header.CompiledArch != runtime.GOARCH {
		return nil, fmt.Errorf("%w: file=%q runtime=%q", ErrSignedRulesArchMismatch, verified.Header.CompiledArch, runtime.GOARCH)
	}
	return readRulesFromBytes(verified.CompiledRules)
}

// NewHTTPTimestampAuthority returns a [TimestampAuthority] that fetches RFC3161
// timestamps over HTTP.
func NewHTTPTimestampAuthority(url string, client *http.Client) TimestampAuthority {
	if client == nil {
		client = http.DefaultClient
	}
	return &httpTimestampAuthority{
		url:    url,
		client: client,
	}
}

type httpTimestampAuthority struct {
	url    string
	client *http.Client
}

func (a *httpTimestampAuthority) Timestamp(requestDER []byte) ([]byte, error) {
	if a == nil {
		return nil, errors.New("timestamp authority is nil")
	}
	if a.url == "" {
		return nil, errors.New("timestamp authority URL is empty")
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, a.url, bytes.NewReader(requestDER))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", timestampQueryContentType)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("timestamp authority returned HTTP %s", resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, timestampReplyContentPrefix) {
		return nil, fmt.Errorf("unexpected timestamp authority content type %q", ct)
	}

	return io.ReadAll(resp.Body)
}

func newX509SignOptions(opts ...X509SignOption) (*x509SignOptions, error) {
	now := time.Now().UTC().Round(0)
	cfg := &x509SignOptions{
		generationTime: now,
		signingTime:    now,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("nil X509SignOption")
		}
		if err := opt.applyX509SignOption(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.generationTime.After(cfg.signingTime) {
		return nil, ErrSignedRulesInvalidTimeRange
	}
	return cfg, nil
}

func newCMSDetachedX509Signer(signer crypto.Signer, chain []*x509.Certificate, authority TimestampAuthority) (*cmsDetachedX509Signer, error) {
	if len(chain) == 0 {
		return nil, errors.New("x509 signer chain is empty")
	}
	_, _, _, hashAlgorithm, _, err := resolveCMSSignerAlgorithms(signer, chain)
	if err != nil {
		return nil, err
	}
	return &cmsDetachedX509Signer{
		signer:             signer,
		chain:              append([]*x509.Certificate(nil), chain...),
		hashAlgorithm:      hashAlgorithm,
		timestampAuthority: authority,
	}, nil
}

func buildDetachedCMSSignature(data []byte, signer crypto.Signer, chain []*x509.Certificate, signingTime time.Time, authority TimestampAuthority) ([]byte, error) {
	eci, err := cmsprotocol.NewDataEncapsulatedContentInfo(data)
	if err != nil {
		return nil, err
	}

	sd, err := cmsprotocol.NewSignedData(eci)
	if err != nil {
		return nil, err
	}

	if err := addSignerInfoWithTime(sd, signer, chain, signingTime); err != nil {
		return nil, err
	}
	if authority != nil {
		if err := addTimestampAuthorityTokens(sd, authority); err != nil {
			return nil, err
		}
	}

	sd.EncapContentInfo.EContent = asn1.RawValue{}
	return sd.ContentInfoDER()
}

func addSignerInfoWithTime(sd *cmsprotocol.SignedData, signer crypto.Signer, chain []*x509.Certificate, signingTime time.Time) error {
	cert, sigAlgorithmID, hashAlgorithmID, _, hashAlgorithm, err := resolveCMSSignerAlgorithms(signer, chain)
	if err != nil {
		return err
	}

	for _, c := range chain {
		if err := sd.AddCertificate(c); err != nil && err.Error() != "certificate already added" {
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
		return errors.New("already detached")
	}

	messageDigest := hashAlgorithm.New()
	if _, err := messageDigest.Write(content); err != nil {
		return err
	}

	signingTimeAttr, err := cmsprotocol.NewAttribute(cmsoid.AttributeSigningTime, signingTime.UTC().Round(0))
	if err != nil {
		return err
	}
	messageDigestAttr, err := cmsprotocol.NewAttribute(cmsoid.AttributeMessageDigest, messageDigest.Sum(nil))
	if err != nil {
		return err
	}
	contentTypeAttr, err := cmsprotocol.NewAttribute(cmsoid.AttributeContentType, sd.EncapContentInfo.EContentType)
	if err != nil {
		return err
	}

	signedAttrs := sortCMSAttributes(signingTimeAttr, messageDigestAttr, contentTypeAttr)
	signedMessage, err := signedAttrs.MarshaledForSigning()
	if err != nil {
		return err
	}

	toSign := signedMessage
	signOpts := crypto.SignerOpts(hashAlgorithm)
	if hashAlgorithm != 0 {
		hashedAttrs := hashAlgorithm.New()
		if _, err := hashedAttrs.Write(signedMessage); err != nil {
			return err
		}
		toSign = hashedAttrs.Sum(nil)
	}

	signature, err := signer.Sign(rand.Reader, toSign, signOpts)
	if err != nil {
		return err
	}

	sd.DigestAlgorithms = appendDigestAlgorithm(sd.DigestAlgorithms, hashAlgorithmID)
	sd.SignerInfos = append(sd.SignerInfos, cmsprotocol.SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    hashAlgorithmID,
		SignedAttrs:        signedAttrs,
		SignatureAlgorithm: sigAlgorithmID,
		Signature:          signature,
	})

	return nil
}

func addTimestampAuthorityTokens(sd *cmsprotocol.SignedData, authority TimestampAuthority) error {
	attrs := make([]cmsprotocol.Attribute, len(sd.SignerInfos))
	for i, si := range sd.SignerInfos {
		attr, err := fetchTimestampAuthorityToken(si, authority)
		if err != nil {
			return err
		}
		attrs[i] = attr
	}
	for i := range attrs {
		sd.SignerInfos[i].UnsignedAttrs = append(sd.SignerInfos[i].UnsignedAttrs, attrs[i])
	}
	return nil
}

func fetchTimestampAuthorityToken(si cmsprotocol.SignerInfo, authority TimestampAuthority) (cmsprotocol.Attribute, error) {
	req, err := buildTimestampRequest(si)
	if err != nil {
		return cmsprotocol.Attribute{}, err
	}
	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return cmsprotocol.Attribute{}, err
	}

	respDER, err := authority.Timestamp(reqDER)
	if err != nil {
		return cmsprotocol.Attribute{}, err
	}
	resp, err := cmstimestamp.ParseResponse(respDER)
	if err != nil {
		return cmsprotocol.Attribute{}, err
	}
	info, err := resp.Info()
	if err != nil {
		return cmsprotocol.Attribute{}, err
	}
	if !req.Matches(info) {
		return cmsprotocol.Attribute{}, errors.New("timestamp authority returned an invalid message imprint")
	}

	return cmsprotocol.NewAttribute(cmsoid.AttributeTimeStampToken, resp.TimeStampToken)
}

func buildTimestampRequest(si cmsprotocol.SignerInfo) (cmstimestamp.Request, error) {
	hash, err := si.Hash()
	if err != nil {
		return cmstimestamp.Request{}, err
	}
	messageImprint, err := cmstimestamp.NewMessageImprint(hash, bytes.NewReader(si.Signature))
	if err != nil {
		return cmstimestamp.Request{}, err
	}
	return cmstimestamp.Request{
		Version:        1,
		MessageImprint: messageImprint,
		Nonce:          cmstimestamp.GenerateNonce(),
		CertReq:        true,
	}, nil
}

func parseX509MetadataEnvelope(metadata []byte) (*x509SignedMetadataEnvelope, []*x509.Certificate, error) {
	if len(metadata) == 0 {
		return nil, nil, ErrX509SignedRulesInvalidMetadata
	}

	var envelope x509SignedMetadataEnvelope
	if err := json.Unmarshal(metadata, &envelope); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrX509SignedRulesInvalidMetadata, err)
	}
	if envelope.Version != x509SignedMetadataVersion {
		return nil, nil, ErrX509SignedRulesInvalidMetadata
	}

	certs, err := parseCertificatesDER(envelope.SignerChainDER)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrX509SignedRulesInvalidMetadata, err)
	}
	if len(certs) == 0 {
		return nil, nil, ErrX509SignedRulesInvalidMetadata
	}

	return &envelope, certs, nil
}

func verifyDetachedCMSSignedRules(
	header SignedRulesHeader,
	signedBytes []byte,
	signature []byte,
	metadataChain []*x509.Certificate,
	crlDER [][]byte,
	opts X509VerifyOptions,
) (*X509VerificationResult, error) {
	if header.SignatureType != SignatureTypeCMSDetachedX509 {
		return nil, ErrSignedRulesUnsupportedSignature
	}

	ci, err := cmsprotocol.ParseContentInfo(signature)
	if err != nil {
		return nil, err
	}
	psd, err := ci.SignedDataContent()
	if err != nil {
		return nil, err
	}
	if psd.EncapContentInfo.EContent.Bytes != nil {
		return nil, errors.New("x509 signature is not detached")
	}
	if len(psd.SignerInfos) != 1 {
		return nil, fmt.Errorf("expected exactly one CMS signer, got %d", len(psd.SignerInfos))
	}

	cmsCerts, err := psd.X509Certificates()
	if err != nil {
		return nil, err
	}
	candidateCerts := dedupeCertificates(append(append([]*x509.Certificate(nil), metadataChain...), cmsCerts...))

	si := psd.SignerInfos[0]
	hashAlgorithm, err := si.Hash()
	if err != nil {
		return nil, err
	}
	if header.SignatureHashAlgorithm != signatureHashAlgorithmFromCryptoHash(hashAlgorithm) {
		return nil, ErrSignedRulesUnsupportedSignature
	}

	signedMessage, err := signerInfoSignedMessage(psd, si, signedBytes)
	if err != nil {
		return nil, err
	}

	signerCert, err := si.FindCertificate(candidateCerts)
	if err != nil {
		return nil, err
	}

	signatureAlgorithm, err := signerInfoSignatureAlgorithm(si)
	if err != nil {
		return nil, err
	}
	if err := signerCert.CheckSignature(signatureAlgorithm, signedMessage, si.Signature); err != nil {
		return nil, err
	}

	validationTime := effectiveVerificationTime(opts.CurrentTime)
	result := &X509VerificationResult{
		Signer: signerCert,
	}

	hasTimestamp, err := signerInfoHasTimestamp(si)
	if err != nil {
		return nil, err
	}

	switch opts.TimestampPolicy {
	case X509TimestampPolicyDisabled:
		// Ignore timestamps entirely.
	case X509TimestampPolicyVerifyIfPresent, X509TimestampPolicyRequireRFC3161:
		if !hasTimestamp {
			if opts.TimestampPolicy == X509TimestampPolicyRequireRFC3161 {
				return nil, ErrX509SignedRulesTimestampRequired
			}
		} else {
			timestampInfo, err := verifySignerInfoTimestamp(si, opts)
			if err != nil {
				return nil, err
			}
			skew, err := allowedClockSkew(opts.AllowedClockSkew)
			if err != nil {
				return nil, err
			}
			if header.SigningTime.After(timestampInfo.GenTime.Add(skew)) {
				return nil, fmt.Errorf("signed rules signing time %s exceeds RFC3161 timestamp time %s plus allowed clock skew %s", header.SigningTime, timestampInfo.GenTime, skew)
			}
			validationTime = timestampInfo.GenTime.UTC().Round(0)
			result.TimestampVerified = true
			result.TimestampTime = validationTime
		}
	default:
		return nil, fmt.Errorf("unknown x509 timestamp policy %d", opts.TimestampPolicy)
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: cloneCertPool(opts.AdditionalIntermediates),
		CurrentTime:   validationTime,
		KeyUsages:     signerVerifyKeyUsages(opts.RequiredEKUs),
	}
	if verifyOpts.Intermediates == nil {
		verifyOpts.Intermediates = x509.NewCertPool()
	}
	for _, cert := range candidateCerts {
		if !bytes.Equal(cert.Raw, signerCert.Raw) {
			verifyOpts.Intermediates.AddCert(cert)
		}
	}

	chains, err := signerCert.Verify(verifyOpts)
	if err != nil {
		return nil, err
	}
	if len(chains) == 0 {
		return nil, errors.New("x509 verification returned no chains")
	}
	result.Chain = append([]*x509.Certificate(nil), chains[0]...)
	if err := verifyUnknownExtKeyUsages(signerCert, opts.RequiredUnknownEKUs); err != nil {
		return nil, err
	}

	if opts.CRLPolicy != X509CRLPolicyDisabled {
		crls, err := parseRevocationLists(crlDER)
		if err != nil {
			return nil, err
		}
		if err := verifyCertificateChainCRLs(result.Chain, crls, validationTime, opts.CRLPolicy); err != nil {
			return nil, err
		}
	}

	return result, nil
}

func signerInfoSignedMessage(psd *cmsprotocol.SignedData, si cmsprotocol.SignerInfo, message []byte) ([]byte, error) {
	if si.SignedAttrs == nil {
		if !psd.EncapContentInfo.IsTypeData() {
			return nil, cmsprotocol.ASN1Error{Message: "missing SignedAttrs"}
		}
		return message, nil
	}

	contentType, err := si.GetContentTypeAttribute()
	if err != nil {
		return nil, err
	}
	if !contentType.Equal(psd.EncapContentInfo.EContentType) {
		return nil, cmsprotocol.ASN1Error{Message: "invalid SignerInfo ContentType attribute"}
	}

	hash, err := si.Hash()
	if err != nil {
		return nil, err
	}
	actualDigest := hash.New()
	if _, err := actualDigest.Write(message); err != nil {
		return nil, err
	}

	expectedDigest, err := si.GetMessageDigestAttribute()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(expectedDigest, actualDigest.Sum(nil)) {
		return nil, errors.New("invalid message digest")
	}

	return si.SignedAttrs.MarshaledForVerification()
}

func signerInfoSignatureAlgorithm(si cmsprotocol.SignerInfo) (x509.SignatureAlgorithm, error) {
	signatureAlgorithm := si.X509SignatureAlgorithm()
	if signatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return x509.UnknownSignatureAlgorithm, cmsprotocol.ErrUnsupported
	}
	return signatureAlgorithm, nil
}

func signerInfoHasTimestamp(si cmsprotocol.SignerInfo) (bool, error) {
	values, err := si.UnsignedAttrs.GetValues(cmsoid.AttributeTimeStampToken)
	if err != nil {
		return false, err
	}
	return len(values) > 0, nil
}

func verifySignerInfoTimestamp(si cmsprotocol.SignerInfo, opts X509VerifyOptions) (*cmstimestamp.Info, error) {
	rawValue, err := si.UnsignedAttrs.GetOnlyAttributeValueBytes(cmsoid.AttributeTimeStampToken)
	if err != nil {
		return nil, err
	}

	token, err := cms.ParseSignedData(rawValue.FullBytes)
	if err != nil {
		return nil, err
	}

	tokenCI, err := cmsprotocol.ParseContentInfo(rawValue.FullBytes)
	if err != nil {
		return nil, err
	}
	tokenSD, err := tokenCI.SignedDataContent()
	if err != nil {
		return nil, err
	}
	info, err := cmstimestamp.ParseInfo(tokenSD.EncapContentInfo)
	if err != nil {
		return nil, err
	}
	if info.Version != 1 {
		return nil, cmsprotocol.ErrUnsupported
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         opts.TSARoots,
		Intermediates: cloneCertPool(opts.TSAIntermediates),
		CurrentTime:   info.GenTime.UTC().Round(0),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, err := token.Verify(verifyOpts); err != nil {
		return nil, err
	}

	hash, err := info.MessageImprint.Hash()
	if err != nil {
		return nil, err
	}
	messageImprint, err := cmstimestamp.NewMessageImprint(hash, bytes.NewReader(si.Signature))
	if err != nil {
		return nil, err
	}
	if !messageImprint.Equal(info.MessageImprint) {
		return nil, errors.New("invalid timestamp message imprint")
	}

	return &info, nil
}

func verifyCertificateChainCRLs(chain []*x509.Certificate, crls []*x509.RevocationList, validationTime time.Time, policy X509CRLPolicy) error {
	if len(chain) < 2 {
		return nil
	}

	for i := range len(chain) - 1 {
		cert := chain[i]
		issuer := chain[i+1]
		validCRLFound := false

		for _, crl := range crls {
			if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
				continue
			}
			if err := crl.CheckSignatureFrom(issuer); err != nil {
				return fmt.Errorf("invalid CRL for issuer %q: %w", issuer.Subject.String(), err)
			}
			if validationTime.Before(crl.ThisUpdate) {
				return fmt.Errorf("CRL for issuer %q is not yet valid", issuer.Subject.String())
			}
			if !crl.NextUpdate.IsZero() && validationTime.After(crl.NextUpdate) {
				return fmt.Errorf("CRL for issuer %q is expired", issuer.Subject.String())
			}
			validCRLFound = true
			if certificateRevokedByCRL(cert, crl) {
				return fmt.Errorf("certificate with serial %s is revoked", cert.SerialNumber)
			}
		}

		if policy == X509CRLPolicyRequireComplete && !validCRLFound {
			return fmt.Errorf("%w: issuer %q", ErrX509SignedRulesCRLRequired, issuer.Subject.String())
		}
	}

	return nil
}

func certificateRevokedByCRL(cert *x509.Certificate, crl *x509.RevocationList) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

func parseRevocationLists(rawCRLs [][]byte) ([]*x509.RevocationList, error) {
	lists := make([]*x509.RevocationList, 0, len(rawCRLs))
	seen := map[string]struct{}{}
	for _, raw := range rawCRLs {
		if len(raw) == 0 {
			return nil, errors.New("CRL blob is empty")
		}
		key := string(raw)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		list, err := x509.ParseRevocationList(raw)
		if err != nil {
			return nil, err
		}
		lists = append(lists, list)
	}
	return lists, nil
}

func resolveCMSSignerAlgorithms(signer crypto.Signer, chain []*x509.Certificate) (*x509.Certificate, pkix.AlgorithmIdentifier, pkix.AlgorithmIdentifier, SignatureHashAlgorithm, crypto.Hash, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, SignatureHashAlgorithmUnknown, 0, err
	}

	var signerCert *x509.Certificate
	for _, cert := range chain {
		certPublicKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, SignatureHashAlgorithmUnknown, 0, err
		}
		if bytes.Equal(publicKey, certPublicKey) {
			signerCert = cert
			break
		}
	}
	if signerCert == nil {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, SignatureHashAlgorithmUnknown, 0, cmsprotocol.ErrNoCertificate
	}

	hashAlgorithmID, hashAlgorithm, signatureHashAlgorithm, err := cmsDigestAlgorithmForPublicKey(signer.Public())
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, SignatureHashAlgorithmUnknown, 0, err
	}

	oidMap, ok := cmsoid.X509PublicKeyAndDigestAlgorithmToSignatureAlgorithm[signerCert.PublicKeyAlgorithm]
	if !ok {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, SignatureHashAlgorithmUnknown, 0, errors.New("unsupported certificate public key algorithm")
	}
	signatureAlgorithmOID, ok := oidMap[hashAlgorithmID.Algorithm.String()]
	if !ok {
		return nil, pkix.AlgorithmIdentifier{}, pkix.AlgorithmIdentifier{}, SignatureHashAlgorithmUnknown, 0, errors.New("unsupported certificate public key algorithm")
	}

	return signerCert, pkix.AlgorithmIdentifier{Algorithm: signatureAlgorithmOID}, hashAlgorithmID, signatureHashAlgorithm, hashAlgorithm, nil
}

func cmsDigestAlgorithmForPublicKey(publicKey crypto.PublicKey) (pkix.AlgorithmIdentifier, crypto.Hash, SignatureHashAlgorithm, error) {
	if ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey); ok {
		switch ecdsaPublicKey.Curve.Params().BitSize {
		case 384:
			return pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA384}, crypto.SHA384, SignatureHashAlgorithmSHA384, nil
		case 521:
			return pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA512}, crypto.SHA512, SignatureHashAlgorithmSHA512, nil
		}
	}

	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA256}, crypto.SHA256, SignatureHashAlgorithmSHA256, nil
	case *rsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: cmsoid.DigestAlgorithmSHA256}, crypto.SHA256, SignatureHashAlgorithmSHA256, nil
	default:
		return pkix.AlgorithmIdentifier{}, 0, SignatureHashAlgorithmUnknown, errors.New("unsupported CMS signer public key type")
	}
}

func sortCMSAttributes(attrs ...cmsprotocol.Attribute) cmsprotocol.Attributes {
	sort.Slice(attrs, func(i, j int) bool {
		return bytes.Compare(attrs[i].RawValue.FullBytes, attrs[j].RawValue.FullBytes) < 0
	})
	return attrs
}

func appendDigestAlgorithm(existing []pkix.AlgorithmIdentifier, algorithm pkix.AlgorithmIdentifier) []pkix.AlgorithmIdentifier {
	for _, current := range existing {
		if current.Algorithm.Equal(algorithm.Algorithm) {
			return existing
		}
	}
	return append(existing, algorithm)
}

func certificatesToDER(certs []*x509.Certificate) [][]byte {
	out := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		out = append(out, append([]byte(nil), cert.Raw...))
	}
	return out
}

func parseCertificatesDER(rawCerts [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func stripSelfSignedRoots(chain []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(chain))
	for _, cert := range chain {
		if cert == nil {
			continue
		}
		if isSelfSignedRoot(cert) {
			continue
		}
		out = append(out, cert)
	}
	return out
}

func isSelfSignedRoot(cert *x509.Certificate) bool {
	if cert == nil || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

func dedupeCertificates(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(certs))
	seen := map[string]struct{}{}
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		key := string(cert.Raw)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cert)
	}
	return out
}

func cloneCertPool(pool *x509.CertPool) *x509.CertPool {
	if pool == nil {
		return nil
	}
	return pool.Clone()
}

func signerVerifyKeyUsages(required []x509.ExtKeyUsage) []x509.ExtKeyUsage {
	if len(required) == 0 {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	return append([]x509.ExtKeyUsage(nil), required...)
}

func verifyUnknownExtKeyUsages(cert *x509.Certificate, required []asn1.ObjectIdentifier) error {
	if len(required) == 0 {
		return nil
	}
	if cert == nil {
		return errors.New("x509 signer certificate is nil")
	}
	for _, requiredOID := range required {
		found := false
		for _, certOID := range cert.UnknownExtKeyUsage {
			if certOID.Equal(requiredOID) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("signer certificate is missing required extended key usage OID %s", requiredOID.String())
		}
	}
	return nil
}

func signatureHashAlgorithmFromCryptoHash(hash crypto.Hash) SignatureHashAlgorithm {
	switch hash {
	case 0:
		return SignatureHashAlgorithmNone
	case crypto.MD4,
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA224,
		crypto.MD5SHA1,
		crypto.RIPEMD160,
		crypto.SHA3_224,
		crypto.SHA3_256,
		crypto.SHA3_384,
		crypto.SHA3_512,
		crypto.SHA512_224,
		crypto.SHA512_256,
		crypto.BLAKE2s_256,
		crypto.BLAKE2b_256,
		crypto.BLAKE2b_384,
		crypto.BLAKE2b_512:
		return SignatureHashAlgorithmUnknown
	case crypto.SHA256:
		return SignatureHashAlgorithmSHA256
	case crypto.SHA384:
		return SignatureHashAlgorithmSHA384
	case crypto.SHA512:
		return SignatureHashAlgorithmSHA512
	default:
		return SignatureHashAlgorithmUnknown
	}
}

func effectiveVerificationTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC().Round(0)
	}
	return t.UTC().Round(0)
}

func allowedClockSkew(skew time.Duration) (time.Duration, error) {
	if skew < 0 {
		return 0, errors.New("allowed clock skew must be non-negative")
	}
	if skew == 0 {
		return defaultTimestampClockSkew, nil
	}
	return skew, nil
}

func cloneByteSlices(src [][]byte) [][]byte {
	out := make([][]byte, 0, len(src))
	for _, item := range src {
		out = append(out, append([]byte(nil), item...))
	}
	return out
}
