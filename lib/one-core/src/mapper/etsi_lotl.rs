use standardized_types::etsi_119_612::ServiceType;

use crate::model::trust_list_role::TrustListRoleEnum;

/// Non-ETSI service type the EUDI pilot TSLs use for PID providers.
pub const EUDI_PILOT_PID_PROVIDER_SERVICE_TYPE: &str =
    "http://uri.etsi.org/Svc/Svctype/Provider/PID";

/// Trust-list role derived from a TSL service type identifier (TS 119 612).
pub fn role_for_service_type(service_type: &ServiceType) -> Option<TrustListRoleEnum> {
    match service_type {
        ServiceType::EaaQ => Some(TrustListRoleEnum::QeaaProvider),
        ServiceType::EaaPubEaa => Some(TrustListRoleEnum::PubEeaProvider),
        ServiceType::Eaa => Some(TrustListRoleEnum::Issuer),
        ServiceType::Other(uri) if uri == EUDI_PILOT_PID_PROVIDER_SERVICE_TYPE => {
            Some(TrustListRoleEnum::PidProvider)
        }
        ServiceType::Other(_) => None,
    }
}
