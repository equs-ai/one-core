use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use time::Duration;

use super::{Error, Headers, HttpClient, Method, Request, RequestBuilder, Response, StatusCode};
#[derive(Clone)]
pub struct ReqwestClient {
    pub client: reqwest::Client,
    options: ReqwestClientOptions,
}

/// What a [`ReqwestClient`] enforces on top of its `reqwest::Client`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReqwestClientOptions {
    /// The largest response body accepted; a larger one fails with [`Error::BodyTooLarge`].
    pub max_body_bytes: Option<usize>,
}

impl ReqwestClient {
    pub fn new(client: reqwest::Client) -> Self {
        Self::with_options(client, ReqwestClientOptions::default())
    }

    pub fn with_options(client: reqwest::Client, options: ReqwestClientOptions) -> Self {
        Self { client, options }
    }

    pub fn hardened(max_body_bytes: usize) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()?;
        Ok(Self::with_options(
            client,
            ReqwestClientOptions {
                max_body_bytes: Some(max_body_bytes),
            },
        ))
    }

    /// A client for revocation data, such as a CRL distribution point.
    pub fn for_revocation_data(
        max_body_bytes: usize,
        timeout: std::time::Duration,
    ) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .timeout(timeout)
            .build()?;
        Ok(Self::with_options(
            client,
            ReqwestClientOptions {
                max_body_bytes: Some(max_body_bytes),
            },
        ))
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[async_trait::async_trait]
impl HttpClient for ReqwestClient {
    fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Get, url)
    }

    fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Post, url)
    }

    fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Put, url)
    }

    fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Patch, url)
    }

    #[track_caller]
    async fn send(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        headers: Option<Headers>,
        method: Method,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let request = Request {
            body: body.clone(),
            headers: headers.clone().unwrap_or_default(),
            method,
            url: url.to_string(),
            timeout,
        };

        let mut builder = match method {
            Method::Get => self.client.get(url),
            Method::Post => self.client.post(url),
            Method::Put => self.client.put(url),
            Method::Patch => self.client.patch(url),
        };

        if let Some(headers) = headers {
            builder = builder.headers(to_header_map(headers)?);
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout.try_into()?);
        }

        let response = builder.send().await?;

        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                let value = v.to_str()?;
                Ok((k.to_string(), value.to_string()))
            })
            .collect::<Result<Headers, Error>>()?;
        let status_code = response.status().as_u16();
        let body = match self.options.max_body_bytes {
            Some(max_body_bytes) => read_within(response, max_body_bytes).await?,
            None => response.bytes().await?.to_vec(),
        };

        Ok(Response {
            body,
            headers,
            status: StatusCode(status_code),
            request,
        })
    }
}

/// The body of `response`, or [`Error::BodyTooLarge`] once it exceeds `max_body_bytes`.
async fn read_within(
    mut response: reqwest::Response,
    max_body_bytes: usize,
) -> Result<Vec<u8>, Error> {
    if response
        .content_length()
        .is_some_and(|length| length > max_body_bytes as u64)
    {
        return Err(Error::BodyTooLarge(max_body_bytes));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_within(&mut body, &chunk, max_body_bytes)?;
    }
    Ok(body)
}

fn append_within(body: &mut Vec<u8>, chunk: &[u8], max_body_bytes: usize) -> Result<(), Error> {
    if body.len().saturating_add(chunk.len()) > max_body_bytes {
        return Err(Error::BodyTooLarge(max_body_bytes));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn to_header_map(headers: HashMap<String, String>) -> Result<HeaderMap, Error> {
    headers
        .into_iter()
        .map(|(k, v)| {
            let name = HeaderName::from_str(k.as_str())?;
            let value = HeaderValue::from_str(v.as_str())?;

            Ok((name, value))
        })
        .collect::<Result<HeaderMap, Error>>()
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::append_within;
    use crate::proto::http_client::Error;

    #[test]
    fn body_up_to_the_limit_is_kept_whole() {
        let mut body = vec![];

        append_within(&mut body, b"01", 4).unwrap();
        append_within(&mut body, b"23", 4).unwrap();
        assert_eq!(body, b"0123");
    }

    #[test]
    fn body_over_the_limit_is_an_error() {
        let mut body = vec![];

        append_within(&mut body, b"012", 4).unwrap();
        assert!(matches!(
            append_within(&mut body, b"34", 4),
            Err(Error::BodyTooLarge(4))
        ));
    }

    #[tokio::test]
    async fn hardened_client_refuses_http() {
        let client = super::ReqwestClient::hardened(1024).unwrap();

        let error = client
            .client
            .get("http://127.0.0.1:9/never")
            .send()
            .await
            .unwrap_err();

        // refused before connecting: the scheme is not allowed
        assert!(error.is_builder(), "{error}");
    }

    #[tokio::test]
    async fn revocation_data_client_fetches_http_without_following_redirects() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::proto::http_client::HttpClient;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ca.crl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"0123456789".to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/moved.crl"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://127.0.0.1:9/elsewhere"),
            )
            .mount(&server)
            .await;
        let client =
            super::ReqwestClient::for_revocation_data(10, std::time::Duration::from_secs(5))
                .unwrap();
        let small_client =
            super::ReqwestClient::for_revocation_data(4, std::time::Duration::from_secs(5))
                .unwrap();

        let crl = client
            .get(&format!("{}/ca.crl", server.uri()))
            .send()
            .await
            .unwrap();
        let moved = client
            .get(&format!("{}/moved.crl", server.uri()))
            .send()
            .await
            .unwrap();
        let too_large = small_client
            .get(&format!("{}/ca.crl", server.uri()))
            .send()
            .await;

        assert_eq!(crl.body, b"0123456789");
        assert_eq!(moved.status.0, 302);
        assert!(
            matches!(
                too_large,
                Err(crate::proto::http_client::Error::BodyTooLarge(4))
            ),
            "{:?}",
            too_large.err()
        );
    }
}
