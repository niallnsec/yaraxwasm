# Signed Rules Examples

This directory contains runnable examples for exporting, signing, verifying, and
loading compiled rule binaries.

## Initialise Example PKI

The x509 examples expect a small local PKI and TSA fixture set under
`examples/pki/generated`.

The bundled init script uses the in-repo Go generator so the examples stay
fully runnable without requiring external PKI tooling. If you prefer to manage
the certificates yourself, you can generate equivalent roots, intermediates,
signer, and TSA assets with external tooling such as `cfssl` as long as the
same file layout is written under `examples/pki/generated`.

Run:

```bash
./examples/init-pki.sh
```

This writes:

- an Ed25519 key pair for the raw-signature examples
- a root CA
- a signing intermediate and leaf certificate
- a TSA intermediate and leaf certificate
- a manifest describing the generated files

The x509 signer leaf includes:

- `ExtKeyUsageCodeSigning`
- custom EKU OID `1.3.6.1.4.1.2312.19.1`

## Run The Examples

Export and sign with Ed25519:

```bash
go run ./examples/ed25519_export_sign
```

Export and sign with x509, RFC3161 timestamping, and a custom EKU-bearing
signer certificate:

```bash
go run ./examples/x509_export_sign
```

Verify and load Ed25519-signed compiled rules:

```bash
go run ./examples/ed25519_verify_load
```

Verify and load x509-signed compiled rules while requiring both code-signing
EKU and the custom rules-signing EKU:

```bash
go run ./examples/x509_verify_load
```
