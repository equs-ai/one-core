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
- `mso_mdoc` MSO `status` is decoded: `status_list` becomes a `TokenStatusListEntry`. Without one, other mechanisms (e.g. `identifier_list`) become entries typed by their name, which a verifier rejects as unsupported; a holder accepts the credential without a revocation method ([#10]).
- Trust-list signer pinning: roots against `trustAnchors`, members against their pointer's certificates ([#10]).
- Trust-list fetch limits: document size, pointer budget, https-only pointers, per-document timeout (also for a pointed-to list a collection starts from), export deadline ([#10]).
- `trust_list_subscriber::export::TrustListExporter`: database-free export of the anchors a LoTL or LoTE grants ([#10]).
- `proto::spki_signature`: verification-only RSA and ECDSA P-384 for trust-list signatures; RSA credentials stay rejected ([#10]).
- `ReqwestClient::hardened`, `ReqwestClient::for_revocation_data` and `ReqwestClientOptions` ([#10]).
- `http_client::Error::Transport` and `http_client::Error::BodyTooLarge` ([#10]).
- `CachingLoader::with_clock` ([#10]).
- SHA-384 XML-DSig digest, `standardized_types::xades::SHA384_DIGEST_URI` ([#10]).

### Changed

- Versions: `equs-one-core`, `-portable`, `-standardized-types`, `-dcql` 0.2.0; `equs-one-core-crypto` 0.1.1, which `equs-one-core` requires ([#10]).
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
- `x5c_into_pem_chain` is strict again; `wrapped_certs_into_pem_chain` decodes line-wrapped XML certificates ([#10]).
- `EtsiLoteResolver` / `EtsiLotlResolver` take an options struct; trust-list caches take a resolver per lookup (`get_with`) ([#10]).
- `TrustListSubscriber` gains `resolve_certificate_pinned` ([#10]).
- `EtsiLoteResolver::new` and `TrustListExporter::new` no longer take a `DidMethodProvider` ([#10]).
- Base configuration pins the root LoTE (`allowUnpinnedRoot: false`); unpinned roots log a warning ([#10]).
- A TSL signature must cover the whole document and its SignedProperties; a list without `NextUpdate` is rejected ([#10]).
- A pointed-to LoTE must be of the type its pointer declares ([#10]).
- Trust-list cache keys cover location, pin and resolver settings; `m20261007_120000_clear_trust_list_cache` drops old entries ([#10]).
- LoTE service status follows TS 119 602: a missing status is trusted except on a PuB-EAA providers list ([#10]).
- A LoTE `…/Revocation` service grants trust only while its entity has an active `…/Issuance` service of the same kind ([#10]).
- `CertificateValidationOptions::verify_only_keys` (`with_verify_only_keys`): RSA and P-384 leaf keys parse only where asked for, on the trust-list paths ([#10]).
- Revocation is checked only where the CRL signer is known (`CrlMode::ValidityOnly`, `CrlMode::X509BelowAnchor`) ([#10]).
- Revocation runs after every chain link verifies; an unusable CRL fails as `CRLCheckFailed` ([#10]).
- Trust-list signers are checked for integrity and validity, and for revocation once pinned ([#10]).
- An anchor a signer chains to must allow `digitalSignature`; a chain without AKIs is tried against every anchor ([#10]).
- Trust-list `Content-Type` is compared by media type; a TSL without one is rejected ([#10]).
- EUDI pilot LoTEs are read: wrapped JWT LoTEs, list-valued `LoTEQualifiers`, pilot content types, PID service type ([#10]).
- `Identifier::active_certs` also covers certificate-authority identifiers, as upstream does ([#10]).
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
- `zip` raised from 7 to 9 for RUSTSEC-2026-0367, -0368 and -0369, without the
  `lzma` feature. Backups are written with Deflate; an LZMA-compressed backup
  can no longer be restored.

### Fixed

- `mso_mdoc` without trust anchors verifies `issuerAuth` with the Document
  Signer key checked for its links, validity and `digitalSignature` usage, no
  longer through `KeyVerification`'s revocation check. That check needs the
  IACA that signs the DS CRL, which an `x5chain` does not carry (ISO/IEC
  18013-5 §9.1.2.4), so every DS naming a CRL failed with `CRL signer
  certificate is not present in the chain`. Revocation is still checked once
  the chain reaches an anchor.

[#10]: https://github.com/equs-ai/one-core/pull/10
