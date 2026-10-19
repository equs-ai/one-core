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
- ETSI TS 119 612 trusted list subscriber (`ETSI_LOTL`), ported from upstream
  `procivis/one-core` at `8b701da84`: follows an EU LoTL to its member TSLs,
  verifies each XAdES signature against pinned `trustAnchors` or the pointer's
  certificate, and hands non-TSL pointers to `delegateSubscribers`. Only services
  with status granted or recognised at national level are indexed.
- XAdES enveloped-signature creation and verification, with exclusive and
  inclusive C14N (`proto::xades`), and the TS 119 612, TS 119 602 XML and
  XML-DSig/XAdES types in `standardized-types`. SHA-512 hasher in `one-crypto`.
- `ETSI_LOTE` subscriber brought to upstream: XAdES-signed XML LoTEs alongside
  JWT, `PointersToOtherLoTE` following bounded by `maxPointerDepth`, and
  `resolve_certificate` / `resolve_public_key` on `TrustListSubscriber`.
- `ErrorCode::BR_0410` (certificate not trusted).

### Changed

- `did:tdw` renamed to `did:webvh`, with the old prefix normalized for
  compatibility.
- CRL signer check tolerates a missing key identifier on either side.
- Minimum supported Rust version raised to 1.95.0.
- `standardized_types::x509::AuthorityKeyIdentifier` is renamed to
  `KeyIdentifier`; the old name remains as a type alias.
- TS 119 602 JSON types follow upstream: `scheme_territory`,
  `service_type_identifier` and the extension lists are optional.
- `TrustListValidationSuccess.role` is optional: a list may not declare a role,
  in which case subscription creation falls back to the requested one. LoTL
  subscriptions still cannot be created through the database-backed service,
  whose role check requires a role the LoTL does not declare.
- LoTE subscriber parameter `leeway` is now `leewaySeconds`; `leeway` is still
  accepted. Public keys on a LoTE are indexed in the key algorithm provider's
  raw form, so keys it cannot parse (e.g. RSA) are not matched by public key.
- `x5c_into_pem_chain` ignores whitespace in the base64 certificates.
- `mso_mdoc` issuer trust now requires a signature path from the Document
  Signer to a trusted IACA PEM; a matching Authority Key Identifier alone no
  longer grants trust. `ExtractPresentationCtx.trusted_certs_skids` is replaced
  by `trusted_certs` (Subject Key Identifier → PEM); `None` or an empty map
  skips the check, as before.
- BBS+ moved off draft-06. `pairing_crypto` was pinned to `0ec3629` to hold the
  draft-06 implementation; it is now the published `equs-pairing-crypto 0.1.0`,
  built from upstream master, which reverted draft-06. Signatures and proofs are
  not interoperable with the previous build, and the `bbs-2023` data integrity
  suite no longer parses the example proof from the W3C VC-DI-BBS specification.
  `test_verify_derived_proof` is ignored for that reason.
