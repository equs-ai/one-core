//! Transaction Data
//!
//! Spec <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-transaction-data>

use serde::{Deserialize, Serialize};
use serde_with::{VecSkipError, serde_as, skip_serializing_none};

use crate::iana::HashAlgorithm;

/// Key Binding JWT claim listing the hashes of the authorized `transaction_data` entries.
///
/// Spec <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.3.1>
pub const TRANSACTION_DATA_HASHES: &str = "transaction_data_hashes";

/// Hash algorithms offered in a `transaction_data` entry, and the one used as a Key
/// Binding JWT claim.
///
/// Spec <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.3.1>
pub const TRANSACTION_DATA_HASHES_ALG: &str = "transaction_data_hashes_alg";

/// Entry of the `transaction_data` Authorization Request parameter. `E` holds the
/// fields added by the specification defining the entry's `type`.
///
/// Spec <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-new-parameters>
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionData<E = serde_json::Map<String, serde_json::Value>> {
    pub r#type: String,
    pub credential_ids: Vec<String>,
    /// Added by the SD-JWT VC profile rather than the entry itself; absence means
    /// `sha-256`, and unrecognized algorithms are skipped.
    ///
    /// Spec <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.3.1>
    #[serde_as(as = "Option<VecSkipError<_>>")]
    #[serde(default)]
    pub transaction_data_hashes_alg: Option<Vec<HashAlgorithm>>,
    #[serde(flatten)]
    pub extension: E,
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    fn entry() -> serde_json::Value {
        json!({
            "type": "https://example.com/transaction",
            "credential_ids": ["cred1"],
            "transaction_data_hashes_alg": ["sha-256"]
        })
    }

    #[test]
    fn transaction_data_roundtrips() {
        let example = entry();

        let transaction_data: TransactionData = serde_json::from_value(example.clone()).unwrap();

        assert_eq!(transaction_data.r#type, "https://example.com/transaction");
        assert_eq!(transaction_data.credential_ids, vec!["cred1"]);
        assert_eq!(
            transaction_data.transaction_data_hashes_alg,
            Some(vec![HashAlgorithm::Sha256])
        );

        assert_eq!(serde_json::to_value(&transaction_data).unwrap(), example);
    }

    #[test]
    fn transaction_data_captures_type_specific_fields() {
        let mut example = entry();
        example["payload"] = json!({ "action": "Log in to Online Banking" });

        let transaction_data: TransactionData = serde_json::from_value(example.clone()).unwrap();

        assert_eq!(
            transaction_data.extension["payload"],
            json!({ "action": "Log in to Online Banking" })
        );
        assert_eq!(serde_json::to_value(&transaction_data).unwrap(), example);
    }

    #[test]
    fn transaction_data_hashes_alg_skips_unrecognized_algorithms() {
        let mut example = entry();
        example["transaction_data_hashes_alg"] = json!(["sha3-256", "sha-512"]);

        let transaction_data: TransactionData = serde_json::from_value(example).unwrap();

        assert_eq!(
            transaction_data.transaction_data_hashes_alg,
            Some(vec![HashAlgorithm::Sha512])
        );
    }
}
