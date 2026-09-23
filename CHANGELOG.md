# Changelog

Changes made in this fork, kept per Apache-2.0 §4(b).

This is a fork of [Procivis One Core](https://github.com/procivis/one-core),
diverged at `7505afb41`.

### Added

- `lib/one-core-portable`, holding the WASM-compatible parts of `one-core` so
  they can be built for `wasm32`; `one-core` re-exports from it.
- JWE `ECDH-ES+A256KW` decryption in `one-crypto`.
- Digital Credentials API handover transcript support for OpenID4VP 1.0.
- Certificate revocation and trusted-root validation for `mso_mdoc` presentations.
- `validate_chain_against_trust_anchors`: validates a chain up to one of a set
  of trust-anchor PEMs, rejecting self-signed leaves.

### Changed

- `did:tdw` renamed to `did:webvh`, with the old prefix normalized for
  compatibility.
- CRL signer check tolerates a missing key identifier on either side.
- Minimum supported Rust version raised to 1.95.0.
- `mso_mdoc` issuer trust now requires a signature path from the Document
  Signer to a trusted IACA PEM; a matching Authority Key Identifier alone no
  longer grants trust. `ExtractPresentationCtx.trusted_certs_skids` is replaced
  by `trusted_certs` (Subject Key Identifier → PEM); `None` or an empty map
  skips the check, as before.
