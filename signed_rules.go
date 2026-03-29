package yaraxwasm

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"
)

const (
	signedRulesMagic         = "YRXSRULE"
	signedRulesHeaderVersion = 1
	signedRulesHeaderSize    = 80
	signedRulesArchFieldSize = 16
)

var (
	ErrSignedRulesInvalidHeader         = errors.New("invalid signed rules header")
	ErrSignedRulesBadMagic              = errors.New("signed rules file magic mismatch")
	ErrSignedRulesUnsupportedVersion    = errors.New("unsupported signed rules header version")
	ErrSignedRulesInvalidCompiledArch   = errors.New("invalid compiled rules architecture")
	ErrSignedRulesArchMismatch          = errors.New("compiled rules architecture mismatch")
	ErrSignedRulesInvalidMetadataLayout = errors.New("invalid signed rules metadata layout")
	ErrSignedRulesMissingSignature      = errors.New("signed rules file is missing a signature")
	ErrSignedRulesUnsupportedSignature  = errors.New("unsupported signed rules signature scheme")
	ErrSignedRulesSignatureVerification = errors.New("signed rules signature verification failed")
	ErrSignedRulesInvalidTimeRange      = errors.New("signed rules generation time must be before or equal to signing time")
)

// SignatureType identifies the signing envelope used for signed compiled rules.
type SignatureType uint16

const (
	SignatureTypeUnknown SignatureType = iota
	SignatureTypeEd25519Raw
	SignatureTypeCMSDetachedX509
)

// SignatureHashAlgorithm identifies the digest or hash selection associated
// with the signature.
type SignatureHashAlgorithm uint16

const (
	SignatureHashAlgorithmUnknown SignatureHashAlgorithm = iota
	SignatureHashAlgorithmNone
	SignatureHashAlgorithmSHA256
	SignatureHashAlgorithmSHA384
	SignatureHashAlgorithmSHA512
)

// SignedRulesHeader describes the fixed header stored ahead of signed compiled
// rules binaries.
type SignedRulesHeader struct {
	HeaderVersion          uint32
	HeaderSize             uint32
	CompiledArch           string
	RuleDataSize           uint64
	MetadataOffset         uint64
	MetadataSize           uint64
	GenerationTime         time.Time
	SigningTime            time.Time
	SignatureType          SignatureType
	SignatureHashAlgorithm SignatureHashAlgorithm
}

// VerifiedSignedRules contains a verified signed-rules container.
type VerifiedSignedRules struct {
	Header        SignedRulesHeader
	Metadata      []byte
	Signature     []byte
	CompiledRules []byte
}

// SignedRulesSigner signs the header and payload bytes of a signed rules file.
type SignedRulesSigner interface {
	SignatureType() SignatureType
	HashAlgorithm() SignatureHashAlgorithm
	SignSignedRules(header SignedRulesHeader, metadata []byte, signedBytes []byte) ([]byte, error)
}

// SignedRulesVerifier verifies a signed rules payload.
type SignedRulesVerifier interface {
	VerifySignedRules(header SignedRulesHeader, metadata []byte, signedBytes []byte, signature []byte) error
}

// SignedRulesVerifierFunc adapts a function into a [SignedRulesVerifier].
type SignedRulesVerifierFunc func(header SignedRulesHeader, metadata []byte, signedBytes []byte, signature []byte) error

// VerifySignedRules implements [SignedRulesVerifier].
func (fn SignedRulesVerifierFunc) VerifySignedRules(header SignedRulesHeader, metadata []byte, signedBytes []byte, signature []byte) error {
	if fn == nil {
		return errors.New("signed rules verifier is nil")
	}
	return fn(header, metadata, signedBytes, signature)
}

// SignedRulesSignerFunc adapts a function into a [SignedRulesSigner].
type SignedRulesSignerFunc struct {
	SignatureTypeValue SignatureType
	HashAlgorithmValue SignatureHashAlgorithm
	SignFunc           func(header SignedRulesHeader, metadata []byte, signedBytes []byte) ([]byte, error)
}

// SignatureType implements [SignedRulesSigner].
func (fn SignedRulesSignerFunc) SignatureType() SignatureType {
	return fn.SignatureTypeValue
}

// HashAlgorithm implements [SignedRulesSigner].
func (fn SignedRulesSignerFunc) HashAlgorithm() SignatureHashAlgorithm {
	return fn.HashAlgorithmValue
}

// SignSignedRules implements [SignedRulesSigner].
func (fn SignedRulesSignerFunc) SignSignedRules(header SignedRulesHeader, metadata []byte, signedBytes []byte) ([]byte, error) {
	if fn.SignFunc == nil {
		return nil, errors.New("signed rules signer is nil")
	}
	return fn.SignFunc(header, metadata, signedBytes)
}

// Ed25519SignedRulesSigner signs signed-rules payloads with an Ed25519 key.
type Ed25519SignedRulesSigner struct {
	PrivateKey ed25519.PrivateKey
}

// SignatureType implements [SignedRulesSigner].
func (s Ed25519SignedRulesSigner) SignatureType() SignatureType {
	return SignatureTypeEd25519Raw
}

// HashAlgorithm implements [SignedRulesSigner].
func (s Ed25519SignedRulesSigner) HashAlgorithm() SignatureHashAlgorithm {
	return SignatureHashAlgorithmNone
}

// SignSignedRules implements [SignedRulesSigner].
func (s Ed25519SignedRulesSigner) SignSignedRules(_ SignedRulesHeader, _ []byte, signedBytes []byte) ([]byte, error) {
	if err := validateEd25519PrivateKey(s.PrivateKey); err != nil {
		return nil, err
	}
	return ed25519.Sign(s.PrivateKey, signedBytes), nil
}

// Ed25519SignedRulesVerifier verifies signed-rules payloads with an Ed25519
// public key.
type Ed25519SignedRulesVerifier struct {
	PublicKey ed25519.PublicKey
}

// VerifySignedRules implements [SignedRulesVerifier].
func (v Ed25519SignedRulesVerifier) VerifySignedRules(header SignedRulesHeader, _ []byte, signedBytes []byte, signature []byte) error {
	if header.SignatureType != SignatureTypeEd25519Raw || header.SignatureHashAlgorithm != SignatureHashAlgorithmNone {
		return ErrSignedRulesUnsupportedSignature
	}
	if len(v.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key length %d", len(v.PublicKey))
	}
	if !ed25519.Verify(v.PublicKey, signedBytes, signature) {
		return ErrSignedRulesSignatureVerification
	}
	return nil
}

// SignedRulesWriteOption configures [Rules.WriteSignedTo].
type SignedRulesWriteOption interface {
	applySignedRulesWriteOption(*signedRulesWriteOptions) error
}

type signedRulesWriteOptions struct {
	metadata       []byte
	generationTime time.Time
	signingTime    time.Time
}

type signedMetadataOption []byte

func (o signedMetadataOption) applySignedRulesWriteOption(opts *signedRulesWriteOptions) error {
	opts.metadata = append([]byte(nil), []byte(o)...)
	return nil
}

func (o signedMetadataOption) applyX509SignOption(opts *x509SignOptions) error {
	opts.applicationMetadata = append([]byte(nil), []byte(o)...)
	return nil
}

type signedTimeOption struct {
	value time.Time
	kind  signedTimeOptionKind
}

type signedTimeOptionKind uint8

const (
	signedTimeOptionGeneration signedTimeOptionKind = iota
	signedTimeOptionSigning
)

func (o signedTimeOption) applySignedRulesWriteOption(opts *signedRulesWriteOptions) error {
	normalized, err := normalizeSignedRulesTime(o.value)
	if err != nil {
		return err
	}
	switch o.kind {
	case signedTimeOptionGeneration:
		opts.generationTime = normalized
	case signedTimeOptionSigning:
		opts.signingTime = normalized
	default:
		return errors.New("unknown signed time option")
	}
	return nil
}

func (o signedTimeOption) applyX509SignOption(opts *x509SignOptions) error {
	normalized, err := normalizeSignedRulesTime(o.value)
	if err != nil {
		return err
	}
	switch o.kind {
	case signedTimeOptionGeneration:
		opts.generationTime = normalized
	case signedTimeOptionSigning:
		opts.signingTime = normalized
	default:
		return errors.New("unknown x509 signed time option")
	}
	return nil
}

// WithSignedMetadata embeds opaque metadata in the signed rules container.
func WithSignedMetadata(metadata []byte) signedMetadataOption {
	return signedMetadataOption(append([]byte(nil), metadata...))
}

// WithGenerationTime sets the generation time written into the signed rules
// header.
func WithGenerationTime(t time.Time) signedTimeOption {
	return signedTimeOption{value: t, kind: signedTimeOptionGeneration}
}

// WithSigningTime sets the signing time written into the signed rules header.
func WithSigningTime(t time.Time) signedTimeOption {
	return signedTimeOption{value: t, kind: signedTimeOptionSigning}
}

// WriteSignedTo writes the compiled rules to w inside a signed container.
func (r *Rules) WriteSignedTo(w io.Writer, signer SignedRulesSigner, opts ...SignedRulesWriteOption) (int64, error) {
	if signer == nil {
		return 0, errors.New("signed rules signer is nil")
	}

	data, err := r.serializeBytes()
	if err != nil {
		return 0, err
	}

	cfg, err := newSignedRulesWriteOptions(opts...)
	if err != nil {
		return 0, err
	}

	return writeSignedRules(w, data, cfg.metadata, cfg.generationTime, cfg.signingTime, signer)
}

// VerifySignedFrom verifies a signed compiled rules container using the
// provided verifier.
func VerifySignedFrom(r io.Reader, verifier SignedRulesVerifier) (*VerifiedSignedRules, error) {
	if verifier == nil {
		return nil, errors.New("signed rules verifier is nil")
	}

	container, err := readAndParseSignedRules(r)
	if err != nil {
		return nil, err
	}

	if err := verifier.VerifySignedRules(container.verified.Header, container.verified.Metadata, container.signedBytes, container.verified.Signature); err != nil {
		return nil, err
	}

	return container.verified, nil
}

// ReadSignedFrom verifies a signed container and loads the verified compiled
// rules into a [Rules] value.
func ReadSignedFrom(r io.Reader, verifier SignedRulesVerifier) (*Rules, error) {
	verified, err := VerifySignedFrom(r, verifier)
	if err != nil {
		return nil, err
	}
	if verified.Header.CompiledArch != runtime.GOARCH {
		return nil, fmt.Errorf("%w: file=%q runtime=%q", ErrSignedRulesArchMismatch, verified.Header.CompiledArch, runtime.GOARCH)
	}
	return readRulesFromBytes(verified.CompiledRules)
}

func writeSignedRules(
	w io.Writer,
	compiledRules []byte,
	metadata []byte,
	generationTime time.Time,
	signingTime time.Time,
	signer SignedRulesSigner,
) (int64, error) {
	header, err := buildSignedRulesHeader(compiledRules, metadata, generationTime, signingTime, signer)
	if err != nil {
		return 0, err
	}

	headerBytes, err := marshalSignedRulesHeader(header)
	if err != nil {
		return 0, err
	}

	signedBytes := make([]byte, 0, len(headerBytes)+len(compiledRules)+len(metadata))
	signedBytes = append(signedBytes, headerBytes...)
	signedBytes = append(signedBytes, compiledRules...)
	signedBytes = append(signedBytes, metadata...)

	signature, err := signer.SignSignedRules(header, metadata, signedBytes)
	if err != nil {
		return 0, err
	}
	if len(signature) == 0 {
		return 0, ErrSignedRulesMissingSignature
	}

	total := int64(0)
	for _, chunk := range [][]byte{signedBytes, signature} {
		n, err := writeAll(w, chunk)
		total += n
		if err != nil {
			return total, err
		}
	}

	return total, nil
}

type parsedSignedRulesContainer struct {
	verified    *VerifiedSignedRules
	signedBytes []byte
}

func readAndParseSignedRules(r io.Reader) (*parsedSignedRulesContainer, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseSignedRulesContainer(data)
}

func parseSignedRulesContainer(data []byte) (*parsedSignedRulesContainer, error) {
	if len(data) < signedRulesHeaderSize {
		return nil, ErrSignedRulesInvalidHeader
	}

	header, err := parseSignedRulesHeader(data[:signedRulesHeaderSize])
	if err != nil {
		return nil, err
	}

	headerSize := uint64(header.HeaderSize)
	ruleEndOffset, ok := addUint64(headerSize, header.RuleDataSize)
	if !ok {
		return nil, ErrSignedRulesInvalidHeader
	}
	signedEnd, ok := addUint64(ruleEndOffset, header.MetadataSize)
	if !ok {
		return nil, ErrSignedRulesInvalidHeader
	}
	if signedEnd > uint64(len(data)) {
		return nil, ErrSignedRulesInvalidHeader
	}

	if header.MetadataSize > 0 {
		expectedMetadataOffset, ok := addUint64(headerSize, header.RuleDataSize)
		if !ok {
			return nil, ErrSignedRulesInvalidMetadataLayout
		}
		if header.MetadataOffset != expectedMetadataOffset {
			return nil, ErrSignedRulesInvalidMetadataLayout
		}
	} else if header.MetadataOffset != 0 {
		return nil, ErrSignedRulesInvalidMetadataLayout
	}

	signatureOffset := signedEnd
	if signatureOffset == uint64(len(data)) {
		return nil, ErrSignedRulesMissingSignature
	}

	ruleStart, err := intFromUint64(headerSize, "signed rules data start")
	if err != nil {
		return nil, ErrSignedRulesInvalidHeader
	}
	ruleEnd, err := intFromUint64(ruleEndOffset, "signed rules data end")
	if err != nil {
		return nil, ErrSignedRulesInvalidHeader
	}
	signatureStart, err := intFromUint64(signatureOffset, "signed rules signature start")
	if err != nil {
		return nil, ErrSignedRulesInvalidHeader
	}
	metadata := []byte(nil)
	if header.MetadataSize > 0 {
		metadataEndOffset, ok := addUint64(header.MetadataOffset, header.MetadataSize)
		if !ok {
			return nil, ErrSignedRulesInvalidMetadataLayout
		}
		metadataStart, err := intFromUint64(header.MetadataOffset, "signed rules metadata start")
		if err != nil {
			return nil, ErrSignedRulesInvalidMetadataLayout
		}
		metadataEnd, err := intFromUint64(metadataEndOffset, "signed rules metadata end")
		if err != nil {
			return nil, ErrSignedRulesInvalidMetadataLayout
		}
		metadata = append([]byte(nil), data[metadataStart:metadataEnd]...)
	}

	return &parsedSignedRulesContainer{
		verified: &VerifiedSignedRules{
			Header:        header,
			CompiledRules: append([]byte(nil), data[ruleStart:ruleEnd]...),
			Metadata:      metadata,
			Signature:     append([]byte(nil), data[signatureStart:]...),
		},
		signedBytes: append([]byte(nil), data[:signatureStart]...),
	}, nil
}

func newSignedRulesWriteOptions(opts ...SignedRulesWriteOption) (*signedRulesWriteOptions, error) {
	now := time.Now().UTC().Round(0)
	cfg := &signedRulesWriteOptions{
		generationTime: now,
		signingTime:    now,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("nil SignedRulesWriteOption")
		}
		if err := opt.applySignedRulesWriteOption(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.generationTime.After(cfg.signingTime) {
		return nil, ErrSignedRulesInvalidTimeRange
	}
	return cfg, nil
}

func buildSignedRulesHeader(
	compiledRules []byte,
	metadata []byte,
	generationTime time.Time,
	signingTime time.Time,
	signer SignedRulesSigner,
) (SignedRulesHeader, error) {
	arch, err := normalizeSignedRulesArch(runtime.GOARCH)
	if err != nil {
		return SignedRulesHeader{}, err
	}

	generationTime, err = normalizeSignedRulesTime(generationTime)
	if err != nil {
		return SignedRulesHeader{}, err
	}
	signingTime, err = normalizeSignedRulesTime(signingTime)
	if err != nil {
		return SignedRulesHeader{}, err
	}
	if generationTime.After(signingTime) {
		return SignedRulesHeader{}, ErrSignedRulesInvalidTimeRange
	}

	header := SignedRulesHeader{
		HeaderVersion:          signedRulesHeaderVersion,
		HeaderSize:             signedRulesHeaderSize,
		CompiledArch:           arch,
		RuleDataSize:           uint64(len(compiledRules)),
		GenerationTime:         generationTime,
		SigningTime:            signingTime,
		SignatureType:          signer.SignatureType(),
		SignatureHashAlgorithm: signer.HashAlgorithm(),
	}

	if len(metadata) > 0 {
		header.MetadataOffset = signedRulesHeaderSize + uint64(len(compiledRules))
		header.MetadataSize = uint64(len(metadata))
	}

	return header, nil
}

func marshalSignedRulesHeader(header SignedRulesHeader) ([]byte, error) {
	if header.HeaderVersion != signedRulesHeaderVersion {
		return nil, ErrSignedRulesUnsupportedVersion
	}
	if header.HeaderSize != signedRulesHeaderSize {
		return nil, ErrSignedRulesInvalidHeader
	}
	archField, err := encodeSignedRulesArch(header.CompiledArch)
	if err != nil {
		return nil, err
	}
	if header.GenerationTime.After(header.SigningTime) {
		return nil, ErrSignedRulesInvalidTimeRange
	}

	buf := make([]byte, signedRulesHeaderSize)
	copy(buf[:8], []byte(signedRulesMagic))
	binary.LittleEndian.PutUint32(buf[8:12], header.HeaderVersion)
	binary.LittleEndian.PutUint32(buf[12:16], header.HeaderSize)
	copy(buf[16:32], archField[:])
	binary.LittleEndian.PutUint64(buf[32:40], header.RuleDataSize)
	binary.LittleEndian.PutUint64(buf[40:48], header.MetadataOffset)
	binary.LittleEndian.PutUint64(buf[48:56], header.MetadataSize)
	generationTimeNanos, err := u64FromInt64(header.GenerationTime.UTC().Round(0).UnixNano(), "signed rules generation time")
	if err != nil {
		return nil, err
	}
	signingTimeNanos, err := u64FromInt64(header.SigningTime.UTC().Round(0).UnixNano(), "signed rules signing time")
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(buf[56:64], generationTimeNanos)
	binary.LittleEndian.PutUint64(buf[64:72], signingTimeNanos)
	binary.LittleEndian.PutUint16(buf[72:74], uint16(header.SignatureType))
	binary.LittleEndian.PutUint16(buf[74:76], uint16(header.SignatureHashAlgorithm))
	binary.LittleEndian.PutUint32(buf[76:80], 0)
	return buf, nil
}

func parseSignedRulesHeader(data []byte) (SignedRulesHeader, error) {
	if len(data) < signedRulesHeaderSize {
		return SignedRulesHeader{}, ErrSignedRulesInvalidHeader
	}
	if string(data[:8]) != signedRulesMagic {
		return SignedRulesHeader{}, ErrSignedRulesBadMagic
	}

	generationTimeNanos, err := i64FromUint64(binary.LittleEndian.Uint64(data[56:64]), "signed rules generation time")
	if err != nil {
		return SignedRulesHeader{}, ErrSignedRulesInvalidHeader
	}
	signingTimeNanos, err := i64FromUint64(binary.LittleEndian.Uint64(data[64:72]), "signed rules signing time")
	if err != nil {
		return SignedRulesHeader{}, ErrSignedRulesInvalidHeader
	}
	header := SignedRulesHeader{
		HeaderVersion:          binary.LittleEndian.Uint32(data[8:12]),
		HeaderSize:             binary.LittleEndian.Uint32(data[12:16]),
		RuleDataSize:           binary.LittleEndian.Uint64(data[32:40]),
		MetadataOffset:         binary.LittleEndian.Uint64(data[40:48]),
		MetadataSize:           binary.LittleEndian.Uint64(data[48:56]),
		GenerationTime:         time.Unix(0, generationTimeNanos).UTC(),
		SigningTime:            time.Unix(0, signingTimeNanos).UTC(),
		SignatureType:          SignatureType(binary.LittleEndian.Uint16(data[72:74])),
		SignatureHashAlgorithm: SignatureHashAlgorithm(binary.LittleEndian.Uint16(data[74:76])),
	}
	if header.HeaderVersion != signedRulesHeaderVersion {
		return SignedRulesHeader{}, ErrSignedRulesUnsupportedVersion
	}
	if header.HeaderSize != signedRulesHeaderSize {
		return SignedRulesHeader{}, ErrSignedRulesInvalidHeader
	}
	if binary.LittleEndian.Uint32(data[76:80]) != 0 {
		return SignedRulesHeader{}, ErrSignedRulesInvalidHeader
	}
	arch, err := decodeSignedRulesArch(data[16:32])
	if err != nil {
		return SignedRulesHeader{}, err
	}
	header.CompiledArch = arch
	if header.GenerationTime.After(header.SigningTime) {
		return SignedRulesHeader{}, ErrSignedRulesInvalidTimeRange
	}
	return header, nil
}

func encodeSignedRulesArch(arch string) ([signedRulesArchFieldSize]byte, error) {
	var field [signedRulesArchFieldSize]byte
	normalized, err := normalizeSignedRulesArch(arch)
	if err != nil {
		return field, err
	}
	copy(field[:], normalized)
	return field, nil
}

func decodeSignedRulesArch(field []byte) (string, error) {
	if len(field) != signedRulesArchFieldSize {
		return "", ErrSignedRulesInvalidCompiledArch
	}

	end := len(field)
	for end > 0 && field[end-1] == 0 {
		end--
	}
	if end == 0 {
		return "", ErrSignedRulesInvalidCompiledArch
	}
	for i := range end {
		if field[i] == 0 || field[i] > 0x7f {
			return "", ErrSignedRulesInvalidCompiledArch
		}
	}
	for i := end; i < len(field); i++ {
		if field[i] != 0 {
			return "", ErrSignedRulesInvalidCompiledArch
		}
	}
	return string(field[:end]), nil
}

func normalizeSignedRulesArch(arch string) (string, error) {
	if len(arch) == 0 || len(arch) > signedRulesArchFieldSize {
		return "", ErrSignedRulesInvalidCompiledArch
	}
	for i := range arch {
		if arch[i] == 0 || arch[i] > 0x7f {
			return "", ErrSignedRulesInvalidCompiledArch
		}
	}
	return arch, nil
}

func normalizeSignedRulesTime(t time.Time) (time.Time, error) {
	if t.IsZero() {
		return time.Time{}, errors.New("signed rules time must be non-zero")
	}
	return t.UTC().Round(0), nil
}

func validateEd25519PrivateKey(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key length %d", len(key))
	}
	return nil
}

func addUint64(a uint64, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum >= a
}

func writeAll(w io.Writer, data []byte) (int64, error) {
	written := int64(0)
	for len(data) > 0 {
		n, err := w.Write(data)
		written += int64(n)
		data = data[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
