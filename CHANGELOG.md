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
- The `mso_mdoc` MSO `status` (ISO/IEC 18013-5 2nd edition): `DetailCredential.status`
  carries its `status_list` as a `TokenStatusListEntry`, then every other mechanism
  (e.g. `identifier_list`) as an entry typed by its name, its `uri` kept verbatim.
  A `status` that is `null`, names no mechanism, or holds a malformed `status_list`
  fails MSO decoding; issued MSOs are unchanged. One-core's own flows look up a
  revocation method for each entry, so the OpenID4VP proof validator now refuses an
  mdoc carrying an `identifier_list` (no revocation method for that type), and the
  OpenID4VCI draft 13 holder refuses one carrying only an `identifier_list`.
- Trust-list signer pinning (fork hardening, beyond upstream):
  - every list is authenticated under an explicit pin: root lists against configured `trustAnchors`
    (equal to, or chaining to, an anchor) and member lists against **all** certificates their pointer
    names, so a list signed during key rollover still authenticates;
  - LoTEs reached through a LoTL pointer are pinned to that pointer's certificates (upstream dropped
    them and accepted any signer);
  - a root with no anchors is refused unless `allowUnpinnedRoot` is set, and its index is marked
    `unpinned`;
  - cache entries are keyed by location and pin, so a list accepted under a weaker pin never answers a
    stricter lookup. Migration `m20261007_120000_clear_trust_list_cache` drops the old entries.
- TSL signature scope: the signature must cover the whole document (`URI=""` or `#<root Id>`, with the
  enveloped-signature transform) and its SignedProperties. A list without `NextUpdate` is rejected as
  closed, for both TSL and LoTE.
- Fetch limits for trust lists: maximum document size, maximum pointers followed, `https`-only pointers,
  a per-document timeout (default 30 s) and one deadline for the whole export, delegated LoTEs
  included. The root not authenticated within the deadline fails; a member over its document timeout is skipped
  as `unreachable`, and members not done by the deadline as `deadline`. Skipped members are recorded
  with a reason (`signer_mismatch`, `invalid_signature`, `unsupported_algorithm`, `expired`, `closed`,
  `unreachable`, `invalid_document`, `size_limit`, `pointer_limit`, `deadline`).
- `ReqwestClient::hardened(max_body_bytes)` for documents from locations the caller does not control
  (`https` only, no redirects, TLS 1.2 or later, at most one byte past the limit read), and
  `ReqwestClient::with_max_body_bytes`.
- `http_client::Error::Transport`, for an adapted client's failure with its cause.
- LoTE services whose `ServiceStatus` is present and not `active` are not indexed.
- `CachingLoader::with_clock`, so cache freshness follows an injected `Clock`.
- Verification-only RSA (PKCS#1 v1.5 and PSS, SHA-256/384/512) and ECDSA P-384 (`proto::spki_signature`,
  on `aws-lc-rs`, already in the tree via `rcgen` and `x509-parser`). Certificate parsing gives RSA and
  P-384 keys a verify-only key handle; XAdES (`rsa-sha*`, `sha*-rsa-MGF1`, `ecdsa-sha384`) and LoTE JWS
  (`RS*`, `PS*`, `ES384`) verify them with the certificate key. There is no RSA key algorithm, key
  storage or DID support; credentials signed with RSA are still rejected. SHA-384 hasher and XML-DSig
  digest.
- A pointed-to LoTE must be of the type its pointer declares (LoTE pointer qualifier, or the LoTL
  pointer's `TSLType`).
- Trust-list cache keys also cover the resolving subscriber (kind, content type, depth, limits).
- `trust_list_subscriber::export::TrustListExporter`: database-free export of the anchors a TS 119 612 LoTL
  (with its member TSLs and the LoTEs it points to) or a TS 119 602 LoTE grants. Each anchor carries its PEM,
  SKI, `notAfter`, entity name, role, service status and the URL and `NextUpdate` of the list that granted it;
  the export carries the root sequence number, issue date, skipped members and whether the root was pinned.
- EUDI pilot service type `http://uri.etsi.org/Svc/Svctype/Provider/PID` maps to the PID-provider role.

### Changed

- Versions: `equs-one-core`, `equs-one-core-portable`, `equs-one-core-standardized-types` and
  `equs-one-core-dcql` 0.2.0 (API changes above), `equs-one-core-crypto` 0.1.1 (additions only).

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
- `wrapped_certs_into_pem_chain` decodes line-wrapped base64 certificates (XML-DSig `X509Certificate`,
  trust-list certificate values), ignoring whitespace; `x5c_into_pem_chain` stays strict, as JOSE `x5c`
  carries none.
- A JWT LoTE whose payload wraps the list in a `LoTE` member, as the published EU lists do, is
  accepted alongside the bare form; it was rejected as closed.
- `TrustListAnchor` carries the granting service's type (`service_type`), so that a revocation
  service's certificates, which share the list's role, can be told from an issuance service's.
  `TrustListExport::excluded_services` lists the LoTE services left out for their status. The
  database-backed LoTE subscriber does not use the service type yet: it still indexes a revocation
  service's certificates like an issuance service's.
- A LoTE service is active with TS 119 602's `…/SvcStatus/active` or the TS 119 612 `granted` /
  `recognisedatnationallevel` values that published LoTEs carry; other values still exclude it.
- A JWT LoTE is also accepted as `application/jose` or `application/octet-stream` (the EUDI pilot serves its
  LoTEs as the latter), and an XML LoTE as `text/xml`; the signature, not the header, authenticates a list.
- `LoTEQualifiers` of a JSON `PointersToOtherLoTE` entry is a list, as TS 119 602 and the EUDI pilot lists have it;
  it was read as a single object, so a JSON LoTE with pointers failed to parse.
- A PuB-EAA provider with status `…/19602/PubEAAProvidersList/SvcStatus/notified` is active, as the EUDI pilot list
  publishes it.
- A trust-list signer chain without Authority Key Identifiers is tried against every configured
  anchor; it was tried against none.
- `ReqwestClient::for_revocation_data`: a client for CRL distribution points, with `http`
  allowed, no redirects, and a size and time bound per request.
- Content-Type of a fetched trust list is compared by media type only (`application/xml;
  charset=utf-8` is accepted).
- `EtsiLoteResolver` / `EtsiLotlResolver` take an options struct; the trust-list caches take a resolver
  per lookup (`get_with`) instead of holding one; `EtsiLoteSubscriber` / `EtsiLotlSubscriber` take their
  resolver. `TrustListSubscriber` gains `resolve_certificate_pinned`.
- `Identifier::active_certs` also covers certificate-authority identifiers, as upstream does.
- Base configuration pins the root LoTE (`allowUnpinnedRoot: false`); `config-local.yml` allows unpinned
  roots for development and tests. Unpinned resolutions log a warning.
- A root anchor that a signer chains to must issue a certificate with `digitalSignature`; anchors the
  chain does not name as an issuer are not tried.
- TS 119 602 services count as active only with the exact `…/SvcStatus/active` status, or with no status
  outside a Pub-EAA providers list; a LoTE XML signature must use the enveloped-signature transform on its
  whole-document reference; a TSL served without `Content-Type` is rejected.
- Revocation is checked only where the CRL signer is known. New `CrlMode::ValidityOnly`
  (`CertificateValidationOptions::signature_and_validity`) for a chain not yet connected to an anchor,
  used by the `mso_mdoc` `x5chain` check without anchors; new `CrlMode::X509BelowAnchor`
  (`signature_and_revocation_below_anchor`) for a chain ending in its trust anchor, whose certificates are
  checked against their issuer and whose anchor is not, used for `mso_mdoc` anchors, trust-list signers and
  the certificate index (whose fingerprint fallback, for a listed leaf, uses validity only). Previously the
  topmost certificate of an unanchored chain failed with "CRL signer certificate is not present in the
  chain" whenever it named a CRL distribution point.
- Revocation is checked after every link of the chain is verified, so no CRL is fetched for a path that
  does not verify. A CRL that cannot be fetched or parsed fails as `CRLCheckFailed`.
- Trust-list signers (JWT `x5c` and XAdES `KeyInfo`) and the certificates a LoTE lists are validated for
  integrity and validity only; a signer's revocation is checked when it is pinned, below the configured
  anchor. A signer issued by a CA with a CRL distribution point and presented without that CA no longer
  fails with "CRL signer certificate is not present in the chain". A JWT LoTE is verified with the key of
  its `x5c` leaf directly, so `EtsiLoteResolver::new`, `TrustListExporter::new` and `with_xades` no
  longer take a `DidMethodProvider`, and an algorithm the key algorithm provider does not know fails as
  `unsupported_algorithm` instead of `invalid_signature`.
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
