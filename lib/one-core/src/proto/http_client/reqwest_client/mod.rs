use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use time::Duration;

use super::{Error, Headers, HttpClient, Method, Request, RequestBuilder, Response, StatusCode};
#[derive(Clone)]
pub struct ReqwestClient {
    pub client: reqwest::Client,
    max_body_bytes: Option<usize>,
}

impl ReqwestClient {
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            max_body_bytes: None,
        }
    }

    pub fn hardened(max_body_bytes: usize) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()?;
        Ok(Self::new(client).with_max_body_bytes(max_body_bytes))
    }

    /// A client for revocation data, such as a CRL distribution point
    pub fn for_revocation_data(
        max_body_bytes: usize,
        timeout: std::time::Duration,
    ) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .timeout(timeout)
            .build()?;
        Ok(Self::new(client).with_max_body_bytes(max_body_bytes))
    }

    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = Some(max_body_bytes);
        self
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
        let body = match self.max_body_bytes {
            Some(max_body_bytes) => read_capped(response, max_body_bytes).await?,
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

/// The body of `response`, cut off once it exceeds `max_body_bytes`.
async fn read_capped(
    mut response: reqwest::Response,
    max_body_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if append_capped(&mut body, &chunk, max_body_bytes) {
            break;
        }
    }
    Ok(body)
}

/// Appends `chunk` up to one byte past `max_body_bytes`; returns whether that point is reached.
fn append_capped(body: &mut Vec<u8>, chunk: &[u8], max_body_bytes: usize) -> bool {
    let cap = max_body_bytes.saturating_add(1);
    let room = cap.saturating_sub(body.len());
    body.extend(chunk.iter().take(room));
    body.len() >= cap
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

    use super::append_capped;

    #[test]
    fn body_within_the_cap_is_kept_whole() {
        let mut body = vec![];

        assert!(!append_capped(&mut body, b"01", 4));
        assert!(!append_capped(&mut body, b"23", 4));
        assert_eq!(body, b"0123");
    }

    #[test]
    fn body_over_the_cap_is_cut_one_byte_past_it() {
        let mut body = vec![];

        assert!(!append_capped(&mut body, b"012", 4));
        assert!(append_capped(&mut body, b"3456789", 4));
        assert_eq!(body, b"01234");
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

        // the body is cut one byte past the cap
        assert_eq!(crl.body, b"01234");
        assert_eq!(moved.status.0, 302);
    }
}
