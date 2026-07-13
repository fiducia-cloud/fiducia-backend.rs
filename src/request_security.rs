//! Exact-origin request checks and credential-bound customer CSRF tokens.
//!
//! `*.fiducia.cloud` hosts are same-site, so `SameSite=Strict` alone does not
//! isolate the customer portal from sibling origins. Dynamic customer routes
//! validate the configured Host and browser Origin; ambient-cookie mutations
//! additionally require an HMAC token bound to the verified credential.

use std::{env, io};

use axum::http::{header::HOST, HeaderMap};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const ORIGIN: &str = "origin";
const SEC_FETCH_SITE: &str = "sec-fetch-site";
const MIN_CSRF_SECRET_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct RequestSecurity {
    expected_origin: String,
    expected_host: String,
    csrf_secret: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestSecurityError {
    AmbiguousHost,
    AmbiguousOrigin,
    CrossSiteFetch,
    InvalidCsrfToken,
    MissingHost,
    MissingOrigin,
    MismatchedHost,
    MismatchedOrigin,
}

impl RequestSecurityError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AmbiguousHost => "ambiguous_host",
            Self::AmbiguousOrigin => "ambiguous_origin",
            Self::CrossSiteFetch => "cross_site_fetch",
            Self::InvalidCsrfToken => "invalid_csrf_token",
            Self::MissingHost => "missing_host",
            Self::MissingOrigin => "missing_origin",
            Self::MismatchedHost => "mismatched_host",
            Self::MismatchedOrigin => "mismatched_origin",
        }
    }
}

impl RequestSecurity {
    /// Release deployments must configure one exact HTTPS customer origin and a
    /// nontrivial signing secret. Debug builds retain an explicit loopback-only
    /// default so local development can still boot without production secrets.
    pub fn from_env(port: u16) -> Result<Self, io::Error> {
        let origin = match env::var("CUSTOMER_APP_ORIGIN")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(origin) => origin,
            None if cfg!(debug_assertions) => {
                let origin = format!("http://127.0.0.1:{port}");
                tracing::warn!(%origin, "CUSTOMER_APP_ORIGIN unset; using debug-only loopback origin");
                origin
            }
            None => return Err(invalid_input("CUSTOMER_APP_ORIGIN must be set")),
        };
        let csrf_secret = match env::var("FIDUCIA_CUSTOMER_CSRF_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(secret) => secret.into_bytes(),
            None if cfg!(debug_assertions) => {
                tracing::warn!("FIDUCIA_CUSTOMER_CSRF_SECRET unset; using a debug-only CSRF key");
                b"fiducia-customer-debug-only-csrf-key-never-production".to_vec()
            }
            None => return Err(invalid_input("FIDUCIA_CUSTOMER_CSRF_SECRET must be set")),
        };
        let security = Self::new(&origin, csrf_secret)?;
        if !cfg!(debug_assertions) && !security.expected_origin.starts_with("https://") {
            return Err(invalid_input(
                "CUSTOMER_APP_ORIGIN must use https in release builds",
            ));
        }
        Ok(security)
    }

    pub fn new(origin: &str, csrf_secret: Vec<u8>) -> Result<Self, io::Error> {
        if csrf_secret.len() < MIN_CSRF_SECRET_BYTES {
            return Err(invalid_input(
                "FIDUCIA_CUSTOMER_CSRF_SECRET must contain at least 32 bytes",
            ));
        }

        let parsed = reqwest::Url::parse(origin.trim())
            .map_err(|_| invalid_input("CUSTOMER_APP_ORIGIN must be an absolute URL"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(invalid_input(
                "CUSTOMER_APP_ORIGIN must contain only http(s) scheme and authority",
            ));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| invalid_input("CUSTOMER_APP_ORIGIN must include a host"))?;
        let expected_host = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };

        Ok(Self {
            expected_origin: parsed.origin().ascii_serialization(),
            expected_host,
            csrf_secret,
        })
    }

    pub fn require_host(&self, headers: &HeaderMap) -> Result<(), RequestSecurityError> {
        let mut hosts = headers.get_all(HOST).iter();
        let host = hosts
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or(RequestSecurityError::MissingHost)?;
        if hosts.next().is_some() {
            return Err(RequestSecurityError::AmbiguousHost);
        }
        if !host.eq_ignore_ascii_case(&self.expected_host) {
            return Err(RequestSecurityError::MismatchedHost);
        }
        Ok(())
    }

    /// Require the exact customer origin. `same-site` is intentionally not
    /// accepted because a sibling subdomain is outside this credential boundary.
    pub fn require_same_origin(&self, headers: &HeaderMap) -> Result<(), RequestSecurityError> {
        self.require_host(headers)?;
        let mut origins = headers.get_all(ORIGIN).iter();
        let origin = origins
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or(RequestSecurityError::MissingOrigin)?;
        if origins.next().is_some() {
            return Err(RequestSecurityError::AmbiguousOrigin);
        }
        if origin != self.expected_origin {
            return Err(RequestSecurityError::MismatchedOrigin);
        }
        if let Some(fetch_site) = headers
            .get(SEC_FETCH_SITE)
            .and_then(|value| value.to_str().ok())
        {
            if fetch_site != "same-origin" && fetch_site != "none" {
                return Err(RequestSecurityError::CrossSiteFetch);
            }
        }
        Ok(())
    }

    /// Bearer clients may omit Origin, but all requests must target the exact
    /// Host and browser fetch metadata must never claim a foreign site.
    pub fn require_api_host(&self, headers: &HeaderMap) -> Result<(), RequestSecurityError> {
        self.require_host(headers)?;
        if headers.contains_key(ORIGIN) {
            self.require_same_origin(headers)?;
        } else if headers
            .get_all(SEC_FETCH_SITE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| value != "same-origin" && value != "none")
        {
            return Err(RequestSecurityError::CrossSiteFetch);
        }
        Ok(())
    }

    pub fn csrf_token(&self, credential_binding: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.csrf_secret)
            .expect("HMAC accepts keys of any non-empty size");
        mac.update(b"fiducia-customer-csrf-v1\0");
        mac.update(credential_binding.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    pub fn verify_csrf_token(
        &self,
        credential_binding: &str,
        provided: &str,
    ) -> Result<(), RequestSecurityError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(provided)
            .map_err(|_| RequestSecurityError::InvalidCsrfToken)?;
        let mut mac = HmacSha256::new_from_slice(&self.csrf_secret)
            .expect("HMAC accepts keys of any non-empty size");
        mac.update(b"fiducia-customer-csrf-v1\0");
        mac.update(credential_binding.as_bytes());
        mac.verify_slice(&decoded)
            .map_err(|_| RequestSecurityError::InvalidCsrfToken)
    }
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn security() -> RequestSecurity {
        RequestSecurity::new(
            "https://app.fiducia.cloud",
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap()
    }

    fn browser_headers(origin: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("app.fiducia.cloud"));
        headers.insert(ORIGIN, HeaderValue::from_static(origin));
        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        headers
    }

    #[test]
    fn exact_customer_origin_is_accepted() {
        assert_eq!(
            security().require_same_origin(&browser_headers("https://app.fiducia.cloud")),
            Ok(())
        );
    }

    #[test]
    fn sibling_origin_is_rejected_even_though_it_is_same_site() {
        assert_eq!(
            security().require_same_origin(&browser_headers("https://admin.fiducia.cloud")),
            Err(RequestSecurityError::MismatchedOrigin)
        );
    }

    #[test]
    fn duplicate_security_authorities_are_rejected() {
        let mut duplicate_origin = browser_headers("https://app.fiducia.cloud");
        duplicate_origin.append(
            ORIGIN,
            HeaderValue::from_static("https://app.fiducia.cloud"),
        );
        assert_eq!(
            security().require_same_origin(&duplicate_origin),
            Err(RequestSecurityError::AmbiguousOrigin)
        );

        let mut duplicate_host = browser_headers("https://app.fiducia.cloud");
        duplicate_host.append(HOST, HeaderValue::from_static("app.fiducia.cloud"));
        assert_eq!(
            security().require_same_origin(&duplicate_host),
            Err(RequestSecurityError::AmbiguousHost)
        );
    }

    #[test]
    fn same_site_fetch_metadata_is_rejected() {
        let mut headers = browser_headers("https://app.fiducia.cloud");
        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-site"));
        assert_eq!(
            security().require_same_origin(&headers),
            Err(RequestSecurityError::CrossSiteFetch)
        );
    }

    #[test]
    fn csrf_token_is_bound_to_the_verified_credential() {
        let token = security().csrf_token("cookie\0verified.jwt");
        assert_eq!(
            security().verify_csrf_token("cookie\0verified.jwt", &token),
            Ok(())
        );
        assert_eq!(
            security().verify_csrf_token("cookie\0other.jwt", &token),
            Err(RequestSecurityError::InvalidCsrfToken)
        );
    }

    #[test]
    fn origin_paths_and_short_secrets_are_rejected() {
        assert!(RequestSecurity::new(
            "https://app.fiducia.cloud/login",
            b"0123456789abcdef0123456789abcdef".to_vec()
        )
        .is_err());
        assert!(RequestSecurity::new("https://app.fiducia.cloud", b"short".to_vec()).is_err());
    }
}
