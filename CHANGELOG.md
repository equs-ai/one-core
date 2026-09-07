# Changelog

Changes made in this fork of [Procivis One Core](https://github.com/procivis/one-core),
kept per Apache-2.0 §4(b). Baseline: upstream `v1.74.2` (`7505afb41`, 2026-03-31).

## Unreleased

### Added

- `lib/one-core-portable`: new crate holding the WASM-compatible parts of `one-core`
  (config, models, DTOs, key algorithms, data types, DCQL, mdoc formatter), so they can
  be built for `wasm32`. `one-core` re-exports from it instead of defining them twice.
- JWE `ECDH-ES+A256KW` decryption in `one-crypto`: the key-agreement algorithm is read
  from the protected header, the KEK is derived via Concat KDF and the CEK is unwrapped
  with AES-256 key wrap. `ECDH-ES` remains the default when `alg` is absent.
- `OID4VPFinal1_0Handover::compute_for_dc_api` for the Digital Credentials API
  `OpenID4VPDCAPIHandover` transcript; used for OpenID4VP Final 1.0 when `response_uri`
  is absent. Deserialization accepts both handover identifiers.
- Certificate revocation and trusted-root validation for `mso_mdoc` presentations.
- `Default` impls for `CertificateValidatorImpl`, `MsoMdocPresentationFormatter` and
  `DidMethodProviderImpl` so they can be constructed without a full core.

### Changed

- `did:tdw` renamed to `did:webvh` across the provider, config, test data and tests.
  `DidValue::from_str` normalizes a `did:tdw:` prefix to `did:webvh:` for compatibility.
- CRL signer check: parent SKI and CRL AKI are compared only when both extensions are
  present; a missing identifier no longer fails the check, the signature is always verified.
- Widened visibility of `certificate_validator` (`Error`, `CertificateValidator`,
  `CertificateValidationOptions`, `LeafValidation`, `CertificateValidatorImpl`),
  `validator::x509` and `DidMethodProviderImpl` for external consumers.
- Minimum supported Rust version raised to 1.95.0.
