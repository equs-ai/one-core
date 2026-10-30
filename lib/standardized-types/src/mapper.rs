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

/// XML date-time (de)serialization for ETSI trusted-list formats.
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
