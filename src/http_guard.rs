//! Transport guard for the HTTP listeners (the REST API and the streamable MCP
//! endpoint).
//!
//! Three controls apply to every request that reaches a guarded router:
//!
//! - **Host.** On a loopback bind only loopback host names are accepted, which
//!   defeats DNS rebinding against a local server. A bind to one specific
//!   address also accepts that address. A wildcard bind skips this check,
//!   because the bearer token below is the control there.
//! - **Origin.** A request that carries an `Origin` header must name an allowed
//!   origin. The allowlist is the built-in Studio origin plus any origins listed
//!   in `RAMPARTS_CORS_ORIGINS`. Nothing else receives a CORS grant.
//! - **Bearer token.** A non-loopback bind requires
//!   `Authorization: Bearer <RAMPARTS_API_TOKEN>` and fails closed when no token
//!   is configured. A loopback bind requires the token only when one is set.
//!
//! Probe routes (`/health`, `/healthz`, `/livez`) sit outside the guard so that
//! orchestrators can see the listener is up without credentials.

use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{info, warn};

/// First-party origin allowed to call the API from a browser (Studio's MCP scan
/// runs client-side). Extra origins come from `RAMPARTS_CORS_ORIGINS`.
const DEFAULT_ALLOWED_ORIGINS: &[&str] = &["https://studio.highflame.ai"];

#[derive(Debug, Clone)]
pub struct GuardConfig {
    bind_host: String,
    token: Option<String>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
}

impl GuardConfig {
    /// Read the guard settings from the environment for a listener bound to
    /// `bind_host`. Variables are optional; an unset token on a non-loopback
    /// bind fails closed rather than falling back to open access.
    pub fn from_env(bind_host: &str) -> Self {
        let token = std::env::var("RAMPARTS_API_TOKEN")
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());
        let allowed_hosts = csv_env("RAMPARTS_ALLOWED_HOSTS")
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        let mut allowed_origins: Vec<String> = DEFAULT_ALLOWED_ORIGINS
            .iter()
            .map(|o| (*o).to_string())
            .collect();
        allowed_origins.extend(
            csv_env("RAMPARTS_CORS_ORIGINS")
                .iter()
                .map(|o| normalize_origin(o)),
        );
        Self::new(bind_host, token, allowed_hosts, allowed_origins)
    }

    pub fn new(
        bind_host: &str,
        token: Option<String>,
        allowed_hosts: Vec<String>,
        allowed_origins: Vec<String>,
    ) -> Self {
        Self {
            bind_host: bind_host.trim().to_string(),
            token: token.filter(|t| !t.is_empty()),
            allowed_hosts,
            allowed_origins: allowed_origins
                .iter()
                .map(|o| normalize_origin(o))
                .collect(),
        }
    }

    pub fn is_loopback_bind(&self) -> bool {
        is_loopback_host(&self.bind_host)
    }

    /// Log the effective posture once at startup. Never logs token values.
    pub fn log_posture(&self) {
        if self.is_loopback_bind() {
            info!(
                "Listener bound to loopback ({}); bearer token {}",
                self.bind_host,
                if self.token.is_some() {
                    "required"
                } else {
                    "not required"
                }
            );
        } else if self.token.is_some() {
            info!(
                "Listener bound to {}; bearer token required on /v1 routes",
                self.bind_host
            );
        } else {
            warn!(
                "Listener bound to non-loopback address {} without RAMPARTS_API_TOKEN: \
                 /v1 routes refuse every request (probes stay up)",
                self.bind_host
            );
        }
    }

    /// CORS grants for the explicit origin allowlist. Preflights from any other
    /// origin receive no `Access-Control-Allow-Origin` header.
    pub fn cors_layer(&self) -> CorsLayer {
        let origins: Vec<HeaderValue> = self
            .allowed_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    }

    /// Host names this listener accepts, or `None` when the Host check is off.
    fn host_allowlist(&self) -> Option<Vec<String>> {
        // A wildcard bind with no host allowlist is protected by the token alone.
        if is_unspecified_host(&self.bind_host) && self.allowed_hosts.is_empty() {
            return None;
        }
        let mut names: Vec<String> = Vec::new();
        if self.is_loopback_bind() {
            names.extend(["localhost", "127.0.0.1", "::1"].map(String::from));
        } else if !is_unspecified_host(&self.bind_host) {
            names.push(self.bind_host.to_ascii_lowercase());
        }
        names.extend(self.allowed_hosts.iter().cloned());
        Some(names)
    }
}

/// Decide whether a request may proceed. Returns the status and a reason on refusal.
pub fn check_request(cfg: &GuardConfig, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    if let Some(allowed) = cfg.host_allowlist() {
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(host_name_of);
        match host {
            Some(name) if allowed.contains(&name) => {}
            _ => {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Host header is not allowed on this listener".to_string(),
                ))
            }
        }
    }

    if let Some(origin) = headers.get(header::ORIGIN) {
        let allowed = origin
            .to_str()
            .ok()
            .map(normalize_origin)
            .is_some_and(|o| cfg.allowed_origins.contains(&o));
        if !allowed {
            return Err((
                StatusCode::FORBIDDEN,
                "Origin is not allowed on this listener".to_string(),
            ));
        }
    }

    match (&cfg.token, cfg.is_loopback_bind()) {
        (None, true) => Ok(()),
        (None, false) => Err((
            StatusCode::UNAUTHORIZED,
            "This listener is exposed beyond loopback and RAMPARTS_API_TOKEN is not set; \
             refusing all requests"
                .to_string(),
        )),
        (Some(expected), _) => {
            let presented = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(str::trim);
            match presented {
                Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => Ok(()),
                _ => Err((
                    StatusCode::UNAUTHORIZED,
                    "A valid bearer token is required".to_string(),
                )),
            }
        }
    }
}

/// Axum middleware that applies [`check_request`] before the handler runs.
pub async fn guard(State(cfg): State<Arc<GuardConfig>>, request: Request, next: Next) -> Response {
    match check_request(&cfg, request.headers()) {
        Ok(()) => next.run(request).await,
        Err((status, reason)) => {
            warn!("Refused request on {}: {}", request.uri().path(), reason);
            (
                status,
                Json(json!({
                    "success": false,
                    "error": reason,
                })),
            )
                .into_response()
        }
    }
}

/// Whether a bind address is loopback (`localhost`, `127.0.0.0/8`, `::1`).
pub fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether a bind address is a wildcard (`0.0.0.0` or `::`).
fn is_unspecified_host(host: &str) -> bool {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_unspecified())
}

/// Extract the host name from a `Host` header value, without port or brackets,
/// lowercased. `localhost:3000` gives `localhost`; `[::1]:8080` gives `::1`.
fn host_name_of(value: &str) -> String {
    let v = value.trim().to_ascii_lowercase();
    if let Some(rest) = v.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default().to_string();
    }
    if v.matches(':').count() == 1 {
        return v.split(':').next().unwrap_or_default().to_string();
    }
    v
}

/// Canonical form of an origin for comparison: trimmed, lowercased, no trailing slash.
fn normalize_origin(origin: &str) -> String {
    origin.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn csv_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Compare two secrets without an early exit on the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn loopback(token: Option<&str>) -> GuardConfig {
        GuardConfig::new(
            "127.0.0.1",
            token.map(str::to_string),
            Vec::new(),
            vec!["https://studio.highflame.ai".to_string()],
        )
    }

    fn exposed(token: Option<&str>) -> GuardConfig {
        GuardConfig::new(
            "0.0.0.0",
            token.map(str::to_string),
            Vec::new(),
            vec!["https://studio.highflame.ai".to_string()],
        )
    }

    #[test]
    fn foreign_origin_is_refused_and_studio_origin_is_allowed() {
        let cfg = loopback(None);
        let evil = headers(&[
            ("host", "127.0.0.1:3000"),
            ("origin", "https://evil.example"),
        ]);
        assert_eq!(
            check_request(&cfg, &evil).unwrap_err().0,
            StatusCode::FORBIDDEN
        );

        let studio = headers(&[
            ("host", "127.0.0.1:3000"),
            ("origin", "https://studio.highflame.ai"),
        ]);
        assert!(check_request(&cfg, &studio).is_ok());

        let null_origin = headers(&[("host", "127.0.0.1:3000"), ("origin", "null")]);
        assert!(check_request(&cfg, &null_origin).is_err());
    }

    #[test]
    fn foreign_host_is_refused_on_a_loopback_bind() {
        // DNS rebinding: a hostile name that resolves to 127.0.0.1.
        let cfg = loopback(None);
        let rebound = headers(&[("host", "attacker.example:3000")]);
        assert_eq!(
            check_request(&cfg, &rebound).unwrap_err().0,
            StatusCode::FORBIDDEN
        );

        let local = headers(&[("host", "localhost:3000")]);
        assert!(check_request(&cfg, &local).is_ok());
        let v6 = headers(&[("host", "[::1]:3000")]);
        assert!(check_request(&cfg, &v6).is_ok());
    }

    #[test]
    fn wildcard_bind_skips_the_host_check_and_relies_on_the_token() {
        // A wildcard bind with no host allowlist skips the Host check.
        let cfg = exposed(Some("s3cret"));
        let any_host = headers(&[
            ("host", "api.example.com"),
            ("authorization", "Bearer s3cret"),
        ]);
        assert!(check_request(&cfg, &any_host).is_ok());
    }

    #[test]
    fn non_loopback_bind_without_a_token_fails_closed() {
        let cfg = exposed(None);
        let req = headers(&[("host", "127.0.0.1:8080")]);
        assert_eq!(
            check_request(&cfg, &req).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        let with_bearer = headers(&[("host", "127.0.0.1:8080"), ("authorization", "Bearer x")]);
        assert_eq!(
            check_request(&cfg, &with_bearer).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn non_loopback_bind_requires_the_matching_bearer_token() {
        let cfg = exposed(Some("s3cret"));
        let none = headers(&[("host", "127.0.0.1:8080")]);
        assert_eq!(
            check_request(&cfg, &none).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );

        let wrong = headers(&[("host", "127.0.0.1:8080"), ("authorization", "Bearer nope")]);
        assert_eq!(
            check_request(&cfg, &wrong).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );

        let basic = headers(&[
            ("host", "127.0.0.1:8080"),
            ("authorization", "Basic s3cret"),
        ]);
        assert!(check_request(&cfg, &basic).is_err());

        let right = headers(&[
            ("host", "127.0.0.1:8080"),
            ("authorization", "Bearer s3cret"),
        ]);
        assert!(check_request(&cfg, &right).is_ok());
    }

    #[test]
    fn loopback_bind_enforces_the_token_only_when_one_is_configured() {
        let open = loopback(None);
        let plain = headers(&[("host", "127.0.0.1:3000")]);
        assert!(check_request(&open, &plain).is_ok());

        let locked = loopback(Some("s3cret"));
        assert!(check_request(&locked, &plain).is_err());
        let right = headers(&[
            ("host", "127.0.0.1:3000"),
            ("authorization", "Bearer s3cret"),
        ]);
        assert!(check_request(&locked, &right).is_ok());
    }

    #[test]
    fn loopback_detection_covers_names_and_addresses() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(!is_loopback_host("10.0.0.5"));
        assert!(!is_loopback_host("::"));
    }

    #[test]
    fn constant_time_eq_matches_only_identical_inputs() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
