use serde::{Deserialize, Deserializer};
use time::{Duration, OffsetDateTime};
use utoipa::ToSchema;
use utoipa::openapi::Schema;
use utoipa::openapi::schema::{ArrayBuilder, OneOfBuilder};

pub fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(time::serde::rfc3339::deserialize(deserializer)?))
}

/// Query params are always transmitted as strings; parse the number of
/// seconds explicitly since `serde_qs` doesn't coerce numeric string values.
pub fn deserialize_duration_seconds<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let seconds = value.parse::<i64>().map_err(serde::de::Error::custom)?;
    Ok(Some(Duration::seconds(seconds)))
}

/// for use together with serde_as::OneOrMany
pub(crate) fn one_or_many<T: ToSchema>() -> Schema {
    OneOfBuilder::new()
        .item(T::schema())
        .item(ArrayBuilder::new().items(T::schema()).build())
        .build()
        .into()
}
