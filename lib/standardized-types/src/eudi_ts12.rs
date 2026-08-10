//! EUDI Wallet technical specification TS12 — Electronic payments: Strong Customer
//! Authentication (SCA) implementation with the Wallet.
//!
//! Spec: <https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts12-electronic-payments-SCA-implementation-with-wallet.md>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use strum::Display;

use crate::openid4vp;

/// The basic transaction types (section 4.3), each identifying the shape of an entry's
/// `payload`. Wallet Units may support further types defined outside this specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum TransactionType {
    /// Payload shape of [`PaymentPayload`] (section 4.3.1)
    #[serde(rename = "urn:eudi:sca:payment:1")]
    #[strum(to_string = "urn:eudi:sca:payment:1")]
    Payment,
    /// Payload shape of [`LoginRiskTransactionPayload`] (section 4.3.2)
    #[serde(rename = "urn:eudi:sca:login_risk_transaction:1")]
    #[strum(to_string = "urn:eudi:sca:login_risk_transaction:1")]
    LoginRiskTransaction,
    /// Payload shape of [`AccountAccessPayload`] (section 4.3.3)
    #[serde(rename = "urn:eudi:sca:account_access:1")]
    #[strum(to_string = "urn:eudi:sca:account_access:1")]
    AccountAccess,
    /// Payload shape of [`EmandatePayload`] (section 4.3.4)
    #[serde(rename = "urn:eudi:sca:emandate:1")]
    #[strum(to_string = "urn:eudi:sca:emandate:1")]
    Emandate,
}

pub type TransactionData<P = serde_json::Value> = openid4vp::TransactionData<Payload<P>>;

/// The `payload` TS12 adds to the entry, its shape given by the entry's `type`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Payload<P = serde_json::Value> {
    pub payload: P,
}

/// `payload` object of the `urn:eudi:sca:payment:1` transaction data type (section 4.3.1).
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PaymentPayload {
    /// Unique identifier of the Relying Party's interaction with the User
    pub transaction_id: String,
    pub date_time: Option<String>,
    pub payee: Payee,
    /// Present when the payment is facilitated by a Payment Initiation Service Provider
    pub pisp: Option<Tpp>,
    pub execution_date: Option<String>,
    /// ISO4217 alpha-3 code
    pub currency: String,
    pub amount: f64,
    pub amount_estimated: Option<bool>,
    pub amount_earmarked: Option<bool>,
    pub sct_inst: Option<bool>,
    pub recurrence: Option<Recurrence>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payee {
    pub name: String,
    pub id: String,
    pub logo: Option<String>,
    pub website: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tpp {
    pub legal_name: String,
    pub brand_name: String,
    /// Domain name as secured by the eIDAS QWAC certificate of the TPP
    pub domain_name: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Recurrence {
    /// ISO8601 date of the first payment's execution
    pub start_date: Option<String>,
    /// ISO8601 date of the last payment's execution
    pub end_date: Option<String>,
    pub number: Option<u32>,
    pub frequency: Frequency,
    /// Options for recurring Payee-initiated payments
    pub mit_options: Option<MitOptions>,
}

/// Frequency of a recurring payment, in line with ISO 20022
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frequency {
    #[serde(rename = "INDA")]
    IntraDay,
    #[serde(rename = "DAIL")]
    Daily,
    #[serde(rename = "WEEK")]
    Weekly,
    #[serde(rename = "TOWK")]
    TwoWeekly,
    #[serde(rename = "TWMN")]
    TwiceAMonth,
    #[serde(rename = "MNTH")]
    Monthly,
    #[serde(rename = "TOMN")]
    TwoMonthly,
    #[serde(rename = "QUTR")]
    Quarterly,
    #[serde(rename = "FOMN")]
    FourMonthly,
    #[serde(rename = "SEMI")]
    SemiAnnual,
    #[serde(rename = "YEAR")]
    Yearly,
    #[serde(rename = "TYEA")]
    TwoYearly,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MitOptions {
    pub amount_variable: Option<bool>,
    pub min_amount: Option<f64>,
    pub max_amount: Option<f64>,
    pub total_amount: Option<f64>,
    pub initial_amount: Option<f64>,
    pub initial_amount_number: Option<u32>,
    pub apr: Option<f64>,
}

/// `urn:eudi:sca:login_risk_transaction:1` transaction data type (section 4.3.2)
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRiskTransactionPayload {
    pub transaction_id: String,
    pub date_time: Option<String>,
    pub service: Option<String>,
    pub action: String,
}

/// `urn:eudi:sca:account_access:1` transaction data type (section 4.3.3)
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAccessPayload {
    pub transaction_id: String,
    pub date_time: Option<String>,
    /// Present when the access is facilitated by an Account Information Service Provider
    pub aisp: Option<Tpp>,
    pub description: Option<String>,
}

/// `urn:eudi:sca:emandate:1` transaction data type (section 4.3.4)
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmandatePayload {
    pub transaction_id: String,
    pub date_time: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub reference_number: Option<String>,
    pub creditor_id: Option<String>,
    pub purpose: Option<String>,
    pub payment_payload: Option<PaymentPayload>,
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    fn login_risk_example() -> serde_json::Value {
        json!({
            "type": "urn:eudi:sca:login_risk_transaction:1",
            "credential_ids": ["sca_attestation"],
            "transaction_data_hashes_alg": ["sha-256"],
            "payload": {
                "transaction_id": "3f2a1b7c-8d4e-4f60-9a1b-0c2d3e4f5a6b",
                "date_time": "2026-08-04T12:34:56Z",
                "service": "Superbank Online Banking",
                "action": "Change daily transaction limit from 1,000 EUR to 10,000 EUR"
            }
        })
    }

    #[test]
    fn login_risk_transaction_data_roundtrips() {
        let example = login_risk_example();

        let transaction_data: TransactionData<LoginRiskTransactionPayload> =
            serde_json::from_value(example.clone()).unwrap();

        assert_eq!(
            transaction_data.r#type,
            TransactionType::LoginRiskTransaction.to_string()
        );
        assert_eq!(transaction_data.credential_ids, vec!["sca_attestation"]);
        assert_eq!(
            transaction_data.extension.payload.action,
            "Change daily transaction limit from 1,000 EUR to 10,000 EUR"
        );

        assert_eq!(serde_json::to_value(&transaction_data).unwrap(), example);
    }

    #[test]
    fn login_risk_transaction_data_without_optional_payload_fields() {
        let mut example = login_risk_example();
        let payload = example["payload"].as_object_mut().unwrap();
        payload.remove("date_time");
        payload.remove("service");

        let transaction_data: TransactionData<LoginRiskTransactionPayload> =
            serde_json::from_value(example.clone()).unwrap();

        assert_eq!(transaction_data.extension.payload.date_time, None);
        assert_eq!(transaction_data.extension.payload.service, None);
        assert_eq!(serde_json::to_value(&transaction_data).unwrap(), example);
    }

    fn recurring_payment_example() -> serde_json::Value {
        json!({
            "type": "urn:eudi:sca:payment:1",
            "credential_ids": ["sca_attestation"],
            "transaction_data_hashes_alg": ["sha-256"],
            "payload": {
                "transaction_id": "8D8AC610-566D-4EF0-9C22-186B2A5ED793",
                "payee": {
                    "name": "Demo Shop",
                    "id": "merchant:ch:123456789",
                    "website": "https://demo.example"
                },
                "pisp": {
                    "legal_name": "Pay Initiation AG",
                    "brand_name": "PayInit",
                    "domain_name": "payinit.example"
                },
                "currency": "EUR",
                "amount": 30.0,
                "sct_inst": true,
                "recurrence": {
                    "start_date": "2026-09-01",
                    "number": 12,
                    "frequency": "MNTH",
                    "mit_options": { "amount_variable": true, "max_amount": 50.0 }
                }
            }
        })
    }

    #[test]
    fn payment_transaction_data_roundtrips() {
        let example = recurring_payment_example();

        let transaction_data: TransactionData<PaymentPayload> =
            serde_json::from_value(example.clone()).unwrap();

        let payment = &transaction_data.extension.payload;
        assert_eq!(
            transaction_data.r#type,
            TransactionType::Payment.to_string()
        );
        assert_eq!(payment.payee.name, "Demo Shop");
        assert_eq!(payment.payee.logo, None);
        assert_eq!(payment.amount, 30.0);
        assert_eq!(payment.execution_date, None);

        let recurrence = payment.recurrence.as_ref().unwrap();
        assert_eq!(recurrence.frequency, Frequency::Monthly);
        assert_eq!(recurrence.end_date, None);
        assert_eq!(
            recurrence.mit_options.as_ref().unwrap().max_amount,
            Some(50.0)
        );

        assert_eq!(serde_json::to_value(&transaction_data).unwrap(), example);
    }

    #[test]
    fn emandate_transaction_data_roundtrips_with_a_nested_payment() {
        let mut example = recurring_payment_example();
        example["type"] = json!("urn:eudi:sca:emandate:1");
        let payment = example["payload"].clone();
        example["payload"] = json!({
            "transaction_id": "8D8AC610-566D-4EF0-9C22-186B2A5ED793",
            "creditor_id": "DE98ZZZ09999999999",
            "payment_payload": payment
        });

        let transaction_data: TransactionData<EmandatePayload> =
            serde_json::from_value(example.clone()).unwrap();

        let emandate = &transaction_data.extension.payload;
        assert_eq!(
            transaction_data.r#type,
            TransactionType::Emandate.to_string()
        );
        assert_eq!(emandate.purpose, None);
        assert_eq!(
            emandate.payment_payload.as_ref().unwrap().payee.name,
            "Demo Shop"
        );

        assert_eq!(serde_json::to_value(&transaction_data).unwrap(), example);
    }

    #[test]
    fn account_access_transaction_data_roundtrips() {
        let example = json!({
            "type": "urn:eudi:sca:account_access:1",
            "credential_ids": ["sca_attestation"],
            "transaction_data_hashes_alg": ["sha-256"],
            "payload": {
                "transaction_id": "8D8AC610-566D-4EF0-9C22-186B2A5ED793",
                "aisp": {
                    "legal_name": "Account Insight AG",
                    "brand_name": "AccountInsight",
                    "domain_name": "accountinsight.example"
                },
                "description": "Read the balance and the last 90 days of transactions"
            }
        });

        let transaction_data: TransactionData<AccountAccessPayload> =
            serde_json::from_value(example.clone()).unwrap();

        let access = &transaction_data.extension.payload;
        assert_eq!(
            transaction_data.r#type,
            TransactionType::AccountAccess.to_string()
        );
        assert_eq!(access.aisp.as_ref().unwrap().brand_name, "AccountInsight");
        assert_eq!(access.date_time, None);

        assert_eq!(serde_json::to_value(&transaction_data).unwrap(), example);
    }
}
