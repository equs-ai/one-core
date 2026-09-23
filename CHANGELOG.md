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

### Changed

- `did:tdw` renamed to `did:webvh`, with the old prefix normalized for
  compatibility.
- CRL signer check tolerates a missing key identifier on either side.
- Minimum supported Rust version raised to 1.95.0.
