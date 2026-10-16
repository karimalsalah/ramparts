//! Scan-target policy shared by every entry point.
//!
//! A scan target is either a remote `http`/`https` endpoint or a `stdio:`
//! command that the scanner launches as a child process. Launching a command is
//! only acceptable for a trusted caller: the CLI, or the stdio MCP server whose
//! parent process already controls the host. A network-facing caller may name
//! remote endpoints only, and those must not resolve to the host or to private
//! networks.

use std::net::IpAddr;

/// What a caller is allowed to make the scanner do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerTrust {
    /// The CLI and the stdio MCP server. Their parent process already controls
    /// the host, so launching a local command is allowed.
    Local,
    /// Any caller reached over a network listener. It may name remote endpoints
    /// only, and loopback, private and link-local addresses are refused.
    Network,
}

impl CallerTrust {
    pub fn allows_stdio(self) -> bool {
        matches!(self, Self::Local)
    }
}

/// The kind of scan target a caller named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTargetKind {
    /// A remote endpoint over HTTP or HTTPS. Scheme-less input is normalized to
    /// `http://` by the scanner.
    Http,
    /// A local command launched as a subprocess (`stdio:...`).
    Stdio,
}

pub const STDIO_REFUSED: &str = "stdio targets launch a local process and are only accepted from \
     trusted callers (the CLI or the stdio MCP server)";

/// Classify a raw target by its explicit scheme.
///
/// `stdio:` is matched case-insensitively and with or without `//`, so the
/// scheme-less `stdio:/bin/sh` form cannot slip past a check that only looks for
/// `stdio://`. Any other `scheme://` prefix must be `http` or `https`. Input
/// with no scheme is an HTTP host, as before.
pub fn classify_scan_target(raw: &str) -> Result<ScanTargetKind, String> {
    let trimmed = raw.trim();
    if trimmed
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("stdio:"))
    {
        return Ok(ScanTargetKind::Stdio);
    }
    if let Some((scheme, _)) = trimmed.split_once("://") {
        if is_scheme_token(scheme) {
            return match scheme.to_ascii_lowercase().as_str() {
                "http" | "https" => Ok(ScanTargetKind::Http),
                _ => Err("Only HTTP and HTTPS URLs are supported".to_string()),
            };
        }
    }
    Ok(ScanTargetKind::Http)
}

/// A URI scheme is a letter followed by letters, digits, `+`, `-` or `.`.
/// Anything else before `://` (a path or query that happens to contain it) is
/// not a scheme.
fn is_scheme_token(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Admit or refuse a target for the given caller.
pub fn admit_target(raw: &str, trust: CallerTrust) -> Result<(), String> {
    match classify_scan_target(raw)? {
        ScanTargetKind::Stdio if trust.allows_stdio() => Ok(()),
        ScanTargetKind::Stdio => Err(STDIO_REFUSED.to_string()),
        ScanTargetKind::Http if trust.allows_stdio() => Ok(()),
        ScanTargetKind::Http => reject_forbidden_target(raw),
    }
}

/// Reject scan targets that resolve to the host itself or to private networks.
///
/// The scan endpoints make the server fetch a caller-supplied URL, which is a
/// textbook request-forgery primitive: without this, a caller reaches
/// `169.254.169.254` for cloud credentials, or any service bound to the host's
/// private interfaces. Set `RAMPARTS_ALLOW_PRIVATE_TARGETS=1` to scan internal
/// servers deliberately.
pub fn reject_forbidden_target(raw_url: &str) -> Result<(), String> {
    let allow_private = std::env::var("RAMPARTS_ALLOW_PRIVATE_TARGETS").is_ok_and(|v| v == "1");
    reject_forbidden_target_with(raw_url, allow_private)
}

/// The policy itself, with the environment read out of it, so tests exercise
/// the rules without mutating process-global state.
pub fn reject_forbidden_target_with(raw_url: &str, allow_private: bool) -> Result<(), String> {
    if allow_private {
        return Ok(());
    }

    // Normalize the same way the scanner does before inspecting the host.
    let candidate = if raw_url.contains("://") {
        raw_url.to_string()
    } else {
        format!("http://{raw_url}")
    };

    let parsed = url::Url::parse(&candidate).map_err(|e| format!("Invalid URL: {e}"))?;

    // Match on the typed host. `host_str` returns an IPv6 literal wrapped in
    // brackets ("[::1]"), which does not parse as an IpAddr, so a string-based
    // check silently lets IPv6 loopback through.
    let ip = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
        Some(url::Host::Domain(domain)) => {
            let lowered = domain.to_ascii_lowercase();
            if lowered == "localhost" || lowered.ends_with(".localhost") {
                return Err(
                    "Refusing to scan a loopback address. Set RAMPARTS_ALLOW_PRIVATE_TARGETS=1 \
                     to allow it."
                        .to_string(),
                );
            }
            // A bare domain may still resolve into private space. Resolution
            // happens later in the HTTP stack, so this check is best-effort by
            // design; the literal forms below are what an attacker reaches for.
            None
        }
        None => return Err("URL has no host".to_string()),
    };

    if let Some(ip) = ip {
        let forbidden = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
        if forbidden {
            return Err(format!(
                "Refusing to scan {ip}: loopback, private, or link-local address. \
                 Set RAMPARTS_ALLOW_PRIVATE_TARGETS=1 to allow it."
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdio_forms_are_classified_as_stdio_including_scheme_less() {
        // The scheme-less form was the one that slipped past the REST check.
        assert_eq!(
            classify_scan_target("stdio:/bin/sh"),
            Ok(ScanTargetKind::Stdio)
        );
        assert_eq!(
            classify_scan_target("stdio:///bin/sh"),
            Ok(ScanTargetKind::Stdio)
        );
        assert_eq!(
            classify_scan_target("  STDIO:/bin/sh  "),
            Ok(ScanTargetKind::Stdio)
        );
    }

    #[test]
    fn http_forms_and_scheme_less_hosts_are_http() {
        assert_eq!(
            classify_scan_target("https://mcp.example.com/v1"),
            Ok(ScanTargetKind::Http)
        );
        assert_eq!(
            classify_scan_target("mcp.example.com"),
            Ok(ScanTargetKind::Http)
        );
        assert_eq!(
            classify_scan_target("localhost:3000"),
            Ok(ScanTargetKind::Http)
        );
    }

    #[test]
    fn other_schemes_are_refused() {
        assert!(classify_scan_target("file:///etc/passwd").is_err());
        assert!(classify_scan_target("ssh://host/x").is_err());
    }

    #[test]
    fn network_callers_cannot_name_stdio_targets() {
        assert_eq!(
            admit_target("stdio:/bin/sh:-c:true", CallerTrust::Network),
            Err(STDIO_REFUSED.to_string())
        );
        assert_eq!(
            admit_target("stdio:///bin/sh", CallerTrust::Network),
            Err(STDIO_REFUSED.to_string())
        );
    }

    #[test]
    fn trusted_callers_may_name_stdio_targets_and_private_hosts() {
        assert!(admit_target("stdio:/bin/sh", CallerTrust::Local).is_ok());
        assert!(admit_target("http://127.0.0.1:3000", CallerTrust::Local).is_ok());
    }

    #[test]
    fn network_callers_are_guarded_against_forged_http_targets() {
        assert!(admit_target("http://169.254.169.254/", CallerTrust::Network).is_err());
        assert!(admit_target("https://mcp.example.com/v1", CallerTrust::Network).is_ok());
    }
}
