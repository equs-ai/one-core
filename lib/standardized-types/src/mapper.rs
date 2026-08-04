// Utility for `secrecy` string values serialization
pub mod secret_string {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(secret: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        secret.expose_secret().serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<SecretString, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = String::deserialize(d)?;
        Ok(SecretString::from(data))
    }
}

// Utility for optional `secrecy` string values serialization
pub mod opt_secret_string {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(
        secret: &Option<SecretString>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        secret
            .as_ref()
            .map(|secret| secret.expose_secret())
            .serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<SecretString>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data: Option<String> = Option::deserialize(d)?;
        Ok(data.map(SecretString::from))
    }
}

/// Deserializes a value that may be provided either inline (as JSON) or as a JSON string.
///
/// Several standards allow the same parameter to be passed both as a JSON object (e.g. inside a
/// request object) and as a JSON-encoded string (e.g. as a URL query parameter).
pub fn deserialize_json_or_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: for<'a> serde::Deserialize<'a>,
{
    use serde::Deserialize;

    let value = serde_json::Value::deserialize(deserializer)?;
    match value.as_str() {
        None => serde_json::from_value(value).map_err(serde::de::Error::custom),
        Some(buffer) => serde_json::from_str(buffer).map_err(serde::de::Error::custom),
    }
}

/// XML date-time (de)serialization for ETSI trusted-list formats.
///
/// ETSI TS 119 612 §5.1.3 / TS 119 602 require ISO 8601 UTC with the `Z`
/// designator, but real EUDI test data emits timezone-less timestamps
/// (`2026-04-30T14:28:34`). RFC 3339 is accepted as-is; a naive value is
/// parsed and treated as UTC (which the spec guarantees it to be).
pub mod xml_datetime {
    use serde::{Deserializer, Serializer};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    use time::macros::format_description;

    const NAIVE_FMT: &[time::format_description::BorrowedFormatItem<'static>] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

    fn parse(s: &str) -> Result<OffsetDateTime, time::error::Parse> {
        if let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) {
            return Ok(dt);
        }
        time::PrimitiveDateTime::parse(s, NAIVE_FMT).map(time::PrimitiveDateTime::assume_utc)
    }

    pub fn serialize<S: Serializer>(v: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
        let formatted = v.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
        s.serialize_str(&formatted)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OffsetDateTime, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        parse(&s).map_err(serde::de::Error::custom)
    }

    pub mod option {
        use serde::{Deserializer, Serializer};
        use time::OffsetDateTime;
        use time::format_description::well_known::Rfc3339;

        pub fn serialize<S: Serializer>(
            v: &Option<OffsetDateTime>,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            match v {
                Some(dt) => {
                    let formatted = dt.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
                    s.serialize_str(&formatted)
                }
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<OffsetDateTime>, D::Error> {
            let s = <Option<String> as serde::Deserialize>::deserialize(d)?;
            match s {
                None => Ok(None),
                Some(s) => super::parse(&s).map(Some).map_err(serde::de::Error::custom),
            }
        }
    }
}
