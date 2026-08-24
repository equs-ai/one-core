use crate::config::core_config::FormatType;
use dcql::CredentialFormat;

impl From<FormatType> for CredentialFormat {
    fn from(value: FormatType) -> Self {
        match value {
            FormatType::Jwt => CredentialFormat::JwtVc,
            FormatType::SdJwt => CredentialFormat::W3cSdJwt,
            FormatType::SdJwtVc => CredentialFormat::SdJwt,
            FormatType::JsonLdClassic => CredentialFormat::LdpVc,
            FormatType::JsonLdBbsPlus => CredentialFormat::LdpVc,
            FormatType::Mdoc => CredentialFormat::MsoMdoc,
        }
    }
}
