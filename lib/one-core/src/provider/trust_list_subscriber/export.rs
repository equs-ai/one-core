use std::sync::Arc;

use serde::{Deserialize, Serialize};
use standardized_types::etsi_119_602::json::LoTEPayload;
use standardized_types::etsi_119_612::ServiceStatus;
use time::OffsetDateTime;
use url::Url;

pub use super::etsi_lote::LoteContentType;
use super::etsi_lote::preprocessing::{is_active_lote_service, requires_explicit_status};
use super::etsi_lote::resolver::{EtsiLoteResolver, EtsiLoteResolverOptions};
use super::etsi_lotl::model::DelegatedMember;
use super::etsi_lotl::resolver::{CollectedTsl, EtsiLotlResolver, EtsiLotlResolverOptions};
use super::fetch::{FetchError, FetchLimits, SignerPin, SkippedMember};
use crate::mapper::etsi_lotl::role_for_service_type;
use crate::mapper::x509::{subject_key_identifier, wrapped_certs_into_pem_chain};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::clock::Clock;
use crate::proto::http_client::HttpClient;
use crate::proto::xades::{XAdES, XAdESProto};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

/// What a trust list location holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustListKind {
    /// ETSI TS 119 612 List of Trusted Lists, followed to its member Trusted Lists.
    Lotl119612,
    /// ETSI TS 119 602 List of Trusted Entities.
    Lote119602,
}

/// The role an exported anchor is trusted for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorRole {
    PidProvider,
    QeaaProvider,
    PubEaaProvider,
    EaaProvider,
    WalletProvider,
    WrpAcProvider,
    WrpRcProvider,
    Registrar,
}

impl AnchorRole {
    fn from_trust_list_role(role: TrustListRoleEnum) -> Option<Self> {
        Some(match role {
            TrustListRoleEnum::PidProvider => Self::PidProvider,
            TrustListRoleEnum::QeaaProvider => Self::QeaaProvider,
            TrustListRoleEnum::PubEeaProvider => Self::PubEaaProvider,
            TrustListRoleEnum::Issuer => Self::EaaProvider,
            TrustListRoleEnum::WalletProvider => Self::WalletProvider,
            TrustListRoleEnum::WrpAcProvider => Self::WrpAcProvider,
            TrustListRoleEnum::WrpRcProvider => Self::WrpRcProvider,
            TrustListRoleEnum::NationalRegistryRegistrar => Self::Registrar,
            TrustListRoleEnum::QesrcProvider | TrustListRoleEnum::Verifier => return None,
        })
    }
}

/// A certificate a trust list grants trust to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustListAnchor {
    pub pem: String,
    /// Subject Key Identifier, colon-separated lower-case hex.
    pub ski: Option<String>,
    pub not_after: OffsetDateTime,
    pub entity_name: Option<String>,
    pub role: Option<AnchorRole>,
    /// The granting service's `ServiceTypeIdentifier`.
    pub service_type: Option<String>,
    pub service_status: Option<String>,
    /// The list that granted the anchor.
    pub source_url: String,
    /// `NextUpdate` of that list.
    pub source_next_update: OffsetDateTime,
}

/// A LoTE service that granted no anchor because of its status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcludedService {
    /// The list that names the service.
    pub source_url: String,
    pub entity_name: Option<String>,
    pub service_type: Option<String>,
    /// `None` when the list requires an explicit status and the service has none.
    pub service_status: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustListExport {
    pub anchors: Vec<TrustListAnchor>,
    pub sequence_number: u64,
    pub issued_at: OffsetDateTime,
    /// `NextUpdate` of the root list; an anchor is stale at the earlier of this and its own.
    pub next_update: OffsetDateTime,
    pub skipped_members: Vec<SkippedMember>,
    /// LoTE services left out for their status (TSL services are not listed).
    pub excluded_services: Vec<ExcludedService>,
    /// The root was accepted on its own embedded signer.
    pub unpinned: bool,
}

#[derive(Clone, Debug)]
pub struct ExportPolicy {
    /// PEMs the root list's signer must equal or chain to.
    pub trust_anchors: Vec<String>,
    pub allow_unpinned_root: bool,
    pub leeway: time::Duration,
    pub limits: FetchLimits,
    /// Format of a root LoTE.
    pub lote_content_type: LoteContentType,
    /// Maximum `PointersToOtherLoTE` depth.
    pub max_pointer_depth: Option<usize>,
}

impl Default for ExportPolicy {
    fn default() -> Self {
        Self {
            trust_anchors: vec![],
            allow_unpinned_root: false,
            leeway: time::Duration::minutes(5),
            limits: FetchLimits::default(),
            lote_content_type: LoteContentType::Jwt,
            max_pointer_depth: Some(5),
        }
    }
}

/// What an export needs; build once, export many lists.
pub struct TrustListExporter {
    clock: Arc<dyn Clock>,
    client: Arc<dyn HttpClient>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    xades_proto: Arc<dyn XAdESProto>,
}

impl TrustListExporter {
    pub fn new(
        clock: Arc<dyn Clock>,
        client: Arc<dyn HttpClient>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        let xades_proto = Arc::new(XAdES::new(certificate_validator.clone()));
        Self::with_xades(
            clock,
            client,
            key_algorithm_provider,
            certificate_validator,
            xades_proto,
        )
    }

    pub(crate) fn with_xades(
        clock: Arc<dyn Clock>,
        client: Arc<dyn HttpClient>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        xades_proto: Arc<dyn XAdESProto>,
    ) -> Self {
        Self {
            clock,
            client,
            key_algorithm_provider,
            certificate_validator,
            xades_proto,
        }
    }

    /// Fetches and authenticates the list at `url` and its members, and returns the anchors they
    /// grant. Only a failing root fails the export; failing members are skipped.
    pub async fn export(
        &self,
        url: &Url,
        kind: TrustListKind,
        policy: &ExportPolicy,
    ) -> Result<TrustListExport, FetchError> {
        let pin = SignerPin::for_root(&policy.trust_anchors, policy.allow_unpinned_root)?;
        match kind {
            TrustListKind::Lote119602 => self
                .export_lote(url.as_str(), policy.lote_content_type.clone(), &pin, policy)
                .await
                .map(|(export, _)| export),
            TrustListKind::Lotl119612 => self.export_lotl(url.as_str(), &pin, policy).await,
        }
    }

    fn lote_resolver(
        &self,
        content_type: LoteContentType,
        policy: &ExportPolicy,
    ) -> EtsiLoteResolver {
        EtsiLoteResolver::new(
            self.clock.clone(),
            self.client.clone(),
            self.key_algorithm_provider.clone(),
            self.certificate_validator.clone(),
            self.xades_proto.clone(),
            EtsiLoteResolverOptions {
                content_type,
                leeway: policy.leeway,
                max_pointer_depth: policy.max_pointer_depth,
                trust_anchors: policy.trust_anchors.clone(),
                allow_unpinned_root: policy.allow_unpinned_root,
                limits: policy.limits.clone(),
            },
        )
    }

    /// The export of the LoTE at `url`, and the pointers it followed.
    async fn export_lote(
        &self,
        url: &str,
        content_type: LoteContentType,
        pin: &SignerPin,
        policy: &ExportPolicy,
    ) -> Result<(TrustListExport, usize), FetchError> {
        let collection = self
            .lote_resolver(content_type, policy)
            .collect(url, pin)
            .await?;
        let root = collection
            .lists
            .first()
            .map(|list| &list.payload.list_and_scheme_information)
            .ok_or_else(|| FetchError::InvalidDocument("empty LoTE collection".to_string()))?;
        let (sequence_number, issued_at, next_update) = (
            root.lote_sequence_number,
            root.list_issue_date_time,
            root.next_update,
        );
        let mut grants = Grants::default();
        for list in &collection.lists {
            lote_anchors(&list.url, &list.payload, &mut grants);
        }
        if !grants.excluded.is_empty() {
            tracing::info!(
                %url,
                excluded = grants.excluded.len(),
                "LoTE services left out for their status"
            );
        }
        Ok((
            TrustListExport {
                anchors: grants.anchors,
                sequence_number,
                issued_at,
                next_update,
                skipped_members: collection.skipped,
                excluded_services: grants.excluded,
                unpinned: collection.unpinned,
            },
            collection.followed,
        ))
    }

    async fn export_lotl(
        &self,
        url: &str,
        pin: &SignerPin,
        policy: &ExportPolicy,
    ) -> Result<TrustListExport, FetchError> {
        let resolver = EtsiLotlResolver::new(
            self.clock.clone(),
            self.client.clone(),
            self.certificate_validator.clone(),
            self.xades_proto.clone(),
            EtsiLotlResolverOptions {
                trust_anchors: policy.trust_anchors.clone(),
                allow_unpinned_root: policy.allow_unpinned_root,
                leeway: policy.leeway,
                limits: policy.limits.clone(),
            },
        );
        let started = tokio::time::Instant::now();
        let collection = resolver.collect(url, pin).await?;
        let mut followed = collection.followed;

        let mut anchors: Vec<TrustListAnchor> =
            collection.members.iter().flat_map(tsl_anchors).collect();
        let mut skipped = collection.skipped;
        let mut excluded = vec![];

        // LoTEs the LoTL points to, pinned to their pointers, within the remaining budget
        for member in &collection.delegated {
            let exported = match remaining_policy(policy, started.elapsed(), followed) {
                Ok(remaining) => self.export_delegated_lote(member, &remaining).await,
                Err(error) => Err(error),
            };
            match exported {
                Ok((export, member_followed)) => {
                    followed += member_followed;
                    anchors.extend(export.anchors);
                    skipped.extend(export.skipped_members);
                    excluded.extend(export.excluded_services);
                }
                Err(error) => {
                    tracing::warn!(url = %member.url, %error, "skipping delegated LoTE");
                    skipped.push(error.skipped(&member.url));
                }
            }
        }

        Ok(TrustListExport {
            anchors,
            sequence_number: collection.sequence_number,
            issued_at: collection.issued_at,
            next_update: collection.next_update,
            skipped_members: skipped,
            excluded_services: excluded,
            unpinned: collection.unpinned,
        })
    }

    async fn export_delegated_lote(
        &self,
        member: &DelegatedMember,
        policy: &ExportPolicy,
    ) -> Result<(TrustListExport, usize), FetchError> {
        let pin = SignerPin::Pointer {
            pems: member.signer_pems.clone(),
            expected_type: member.declared_type.clone(),
        };
        let content_type = match member.mime_type.as_deref() {
            Some(mime) if mime.contains("xml") => LoteContentType::Xml,
            _ => LoteContentType::Jwt,
        };
        self.export_lote(&member.url, content_type, &pin, policy)
            .await
    }
}

/// The policy left for a delegated LoTE after `elapsed` time and `followed` pointers.
fn remaining_policy(
    policy: &ExportPolicy,
    elapsed: std::time::Duration,
    followed: usize,
) -> Result<ExportPolicy, FetchError> {
    let deadline = policy
        .limits
        .deadline
        .checked_sub(elapsed)
        .filter(|left| !left.is_zero())
        .ok_or(FetchError::Deadline)?;
    Ok(ExportPolicy {
        limits: FetchLimits {
            deadline,
            max_pointers: policy.limits.max_pointers.saturating_sub(followed),
            ..policy.limits.clone()
        },
        ..policy.clone()
    })
}

/// Anchors of a member TSL's granted services whose type maps to an issuer role.
fn tsl_anchors(member: &CollectedTsl) -> Vec<TrustListAnchor> {
    let providers = member
        .tsl
        .trust_service_provider_list
        .iter()
        .flat_map(|list| &list.providers);
    let mut anchors = vec![];
    for service in providers.flat_map(|provider| &provider.tsp_services.services) {
        let info = &service.service_information;
        if !matches!(
            info.service_status,
            ServiceStatus::Granted | ServiceStatus::RecognisedAtNationalLevel
        ) {
            continue;
        }
        let Some(role) = role_for_service_type(&info.service_type_identifier)
            .and_then(AnchorRole::from_trust_list_role)
        else {
            continue;
        };
        let entity_name = info
            .service_name
            .names
            .first()
            .map(|name| name.value.clone());
        for cert_b64 in info
            .service_digital_identity
            .digital_ids
            .iter()
            .filter_map(|id| id.x509_certificate.as_ref())
        {
            if let Some(anchor) = anchor_from_b64(
                cert_b64,
                AnchorService {
                    entity_name: entity_name.clone(),
                    role: Some(role),
                    service_type: Some(info.service_type_identifier.to_string()),
                    service_status: Some(info.service_status.to_string()),
                },
                &member.url,
                member.next_update,
            ) {
                anchors.push(anchor);
            }
        }
    }
    anchors
}

/// What a list export grants, and the LoTE services it leaves out for their status.
#[derive(Default)]
struct Grants {
    anchors: Vec<TrustListAnchor>,
    excluded: Vec<ExcludedService>,
}

/// Anchors of the trusted services of an authenticated LoTE, added to `grants`.
fn lote_anchors(url: &str, lote: &LoTEPayload, grants: &mut Grants) {
    let scheme = &lote.list_and_scheme_information;
    let role = scheme
        .lote_type
        .clone()
        .and_then(|lote_type| TrustListRoleEnum::try_from(lote_type).ok())
        .and_then(AnchorRole::from_trust_list_role);
    let requires_explicit_status = requires_explicit_status(scheme.lote_type.as_ref());

    for entity in lote.trusted_entities_list.iter().flatten() {
        let entity_name = entity
            .trusted_entity_information
            .te_name
            .first()
            .map(|name| name.value.clone());
        for service in &entity.trusted_entity_services {
            let info = &service.service_information;
            if !is_active_lote_service(requires_explicit_status, info.service_status.as_deref()) {
                grants.excluded.push(ExcludedService {
                    source_url: url.to_string(),
                    entity_name: entity_name.clone(),
                    service_type: info.service_type_identifier.clone(),
                    service_status: info.service_status.clone(),
                });
                continue;
            }
            let Some(certificates) = info
                .service_digital_identity
                .as_ref()
                .and_then(|identity| identity.x509_certificates.as_ref())
            else {
                continue;
            };
            for certificate in certificates {
                if let Some(anchor) = anchor_from_b64(
                    &certificate.val,
                    AnchorService {
                        entity_name: entity_name.clone(),
                        role,
                        service_type: info.service_type_identifier.clone(),
                        service_status: info.service_status.clone(),
                    },
                    url,
                    scheme.next_update,
                ) {
                    grants.anchors.push(anchor);
                }
            }
        }
    }
}

/// The service an anchor is granted by.
struct AnchorService {
    entity_name: Option<String>,
    role: Option<AnchorRole>,
    service_type: Option<String>,
    service_status: Option<String>,
}

fn anchor_from_b64(
    cert_b64: &str,
    service: AnchorService,
    source_url: &str,
    source_next_update: OffsetDateTime,
) -> Option<TrustListAnchor> {
    let pem = wrapped_certs_into_pem_chain(std::slice::from_ref(&cert_b64.to_string())).ok()?;
    let der = x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes())
        .next()?
        .ok()?
        .contents;
    let (_, certificate) = x509_parser::parse_x509_certificate(&der)
        .inspect_err(|error| tracing::warn!(%error, url = %source_url, "skipping unparseable trust-list certificate"))
        .ok()?;
    Some(TrustListAnchor {
        ski: subject_key_identifier(&certificate).ok().flatten(),
        not_after: certificate.validity().not_after.to_datetime(),
        pem,
        entity_name: service.entity_name,
        role: service.role,
        service_type: service.service_type,
        service_status: service.service_status,
        source_url: source_url.to_string(),
        source_next_update,
    })
}

#[cfg(test)]
mod test;
