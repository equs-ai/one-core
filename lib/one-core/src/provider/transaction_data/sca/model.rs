use one_dto_mapper::{Into, convert_inner};
use serde::Deserialize;
use standardized_types::eudi_ts12::{
    AccountAccessPayload, EmandatePayload, Frequency, LoginRiskTransactionPayload, MitOptions,
    Payee, PaymentPayload, Recurrence, Tpp, TransactionType,
};
use time::{Date, Duration};

use crate::clock;
use crate::config::validator::datatype::DATE_FORMAT;
use crate::provider::transaction_data::error::TransactionDataError;

/// The payload each transaction data type of EUDI TS12 section 4.3 carries
pub(super) trait TransactionTypeExt {
    /// Maps a camelCase request from the proof request endpoint onto the payload.
    fn payload_from_request(
        &self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, TransactionDataError>;

    fn validate_payload(
        &self,
        wire: &serde_json::Value,
        leeway: Duration,
    ) -> Result<(), TransactionDataError>;
}

impl TransactionTypeExt for TransactionType {
    fn payload_from_request(
        &self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, TransactionDataError> {
        let payload = match self {
            Self::Payment => {
                serde_json::to_value(PaymentPayload::from(PaymentRequest::deserialize(request)?))
            }
            Self::LoginRiskTransaction => serde_json::to_value(LoginRiskTransactionPayload::from(
                LoginRiskTransactionRequest::deserialize(request)?,
            )),
            Self::AccountAccess => serde_json::to_value(AccountAccessPayload::from(
                AccountAccessRequest::deserialize(request)?,
            )),
            Self::Emandate => serde_json::to_value(EmandatePayload::from(
                EmandateRequest::deserialize(request)?,
            )),
        };

        Ok(payload?)
    }

    fn validate_payload(
        &self,
        wire: &serde_json::Value,
        leeway: Duration,
    ) -> Result<(), TransactionDataError> {
        match self {
            Self::Payment => validate_payment(&PaymentPayload::deserialize(wire)?, leeway),
            Self::LoginRiskTransaction => {
                LoginRiskTransactionPayload::deserialize(wire)?;
                Ok(())
            }
            Self::AccountAccess => {
                AccountAccessPayload::deserialize(wire)?;
                Ok(())
            }
            Self::Emandate => validate_emandate(&EmandatePayload::deserialize(wire)?, leeway),
        }
    }
}

fn validate_emandate(
    emandate: &EmandatePayload,
    leeway: Duration,
) -> Result<(), TransactionDataError> {
    // the User has to be told what they are mandating, either in words or as the payment
    if emandate.purpose.is_none() && emandate.payment_payload.is_none() {
        return Err(TransactionDataError::InvalidTransactionData(
            "purpose must be present unless payment_payload is".to_string(),
        ));
    }

    match &emandate.payment_payload {
        // can include nested payment request
        Some(payment) => validate_payment(payment, leeway),
        None => Ok(()),
    }
}

fn validate_payment(
    payment: &PaymentPayload,
    leeway: Duration,
) -> Result<(), TransactionDataError> {
    // a recurring payment executes on the schedule in `recurrence`, so it has no single
    // execution date
    if payment.execution_date.is_some() && payment.recurrence.is_some() {
        return Err(TransactionDataError::InvalidTransactionData(
            "execution_date must not be present together with recurrence".to_string(),
        ));
    }

    match &payment.execution_date {
        Some(execution_date) => validate_execution_date(execution_date, leeway),
        None => Ok(()),
    }
}

/// Section 4.3.1: the execution date must not lie in the past. A date is past once its
/// day is over.
fn validate_execution_date(
    execution_date: &str,
    leeway: Duration,
) -> Result<(), TransactionDataError> {
    let date = Date::parse(execution_date, DATE_FORMAT).map_err(|_| {
        TransactionDataError::InvalidTransactionData(format!(
            "execution_date {execution_date} is not a date"
        ))
    })?;

    if date < (clock::now_utc() - leeway).date() {
        return Err(TransactionDataError::InvalidTransactionData(format!(
            "execution_date {execution_date} must not lie in the past"
        )));
    }

    Ok(())
}

#[derive(Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(PaymentPayload)]
pub(crate) struct PaymentRequest {
    pub transaction_id: String,
    pub date_time: Option<String>,
    pub payee: PayeeRequest,
    #[into(with_fn = convert_inner)]
    pub pisp: Option<TppRequest>,
    pub execution_date: Option<String>,
    pub currency: String,
    pub amount: f64,
    pub amount_estimated: Option<bool>,
    pub amount_earmarked: Option<bool>,
    pub sct_inst: Option<bool>,
    #[into(with_fn = convert_inner)]
    pub recurrence: Option<RecurrenceRequest>,
}

#[derive(Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(Payee)]
pub(crate) struct PayeeRequest {
    pub name: String,
    pub id: String,
    pub logo: Option<String>,
    pub website: Option<String>,
}

#[derive(Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(Tpp)]
pub(crate) struct TppRequest {
    pub legal_name: String,
    pub brand_name: String,
    pub domain_name: String,
}

#[derive(Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(Recurrence)]
pub(crate) struct RecurrenceRequest {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub number: Option<u32>,
    // the ISO 20022 codes are spelled the same in both representations
    pub frequency: Frequency,
    #[into(with_fn = convert_inner)]
    pub mit_options: Option<MitOptionsRequest>,
}

#[derive(Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(MitOptions)]
pub(crate) struct MitOptionsRequest {
    pub amount_variable: Option<bool>,
    pub min_amount: Option<f64>,
    pub max_amount: Option<f64>,
    pub total_amount: Option<f64>,
    pub initial_amount: Option<f64>,
    pub initial_amount_number: Option<u32>,
    pub apr: Option<f64>,
}

#[derive(Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(LoginRiskTransactionPayload)]
pub(crate) struct LoginRiskTransactionRequest {
    pub transaction_id: String,
    pub date_time: Option<String>,
    pub service: Option<String>,
    pub action: String,
}

#[derive(Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(AccountAccessPayload)]
pub(crate) struct AccountAccessRequest {
    pub transaction_id: String,
    pub date_time: Option<String>,
    #[into(with_fn = convert_inner)]
    pub aisp: Option<TppRequest>,
    pub description: Option<String>,
}

#[derive(Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(EmandatePayload)]
pub(crate) struct EmandateRequest {
    pub transaction_id: String,
    pub date_time: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub reference_number: Option<String>,
    pub creditor_id: Option<String>,
    pub purpose: Option<String>,
    #[into(with_fn = convert_inner)]
    pub payment_payload: Option<PaymentRequest>,
}
