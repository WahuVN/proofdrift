use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::{LeakMatch, SecretFingerprintIndex, StreamingScanner};

pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyAction {
    Allow,
    RequireApproval,
    Block,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRule {
    pub host: String,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub allow_subdomains: bool,
    pub action: PolicyAction,
}

impl HostRule {
    /// Exact host rule restricted to HTTPS. This is the safe default for
    /// secret-bearing traffic; callers must opt into another scheme explicitly.
    pub fn exact_https(host: impl Into<String>, action: PolicyAction) -> Self {
        Self {
            host: normalize_rule_host(&host.into()),
            scheme: Some("https".to_owned()),
            port: Some(443),
            allow_subdomains: false,
            action,
        }
    }

    /// Explicit host rule for callers that need non-default scheme/port policy.
    pub fn explicit(
        host: impl Into<String>,
        scheme: Option<&str>,
        port: Option<u16>,
        allow_subdomains: bool,
        action: PolicyAction,
    ) -> Self {
        Self {
            host: normalize_rule_host(&host.into()),
            scheme: scheme.map(|value| value.to_ascii_lowercase()),
            port,
            allow_subdomains,
            action,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DestinationPolicy {
    rules: BTreeMap<String, Vec<HostRule>>,
}

impl DestinationPolicy {
    pub fn add_rule(&mut self, secret_id: impl Into<String>, mut rule: HostRule) {
        rule.host = normalize_rule_host(&rule.host);
        self.rules.entry(secret_id.into()).or_default().push(rule);
    }

    fn action_for(&self, secret_id: &str, destination: &NormalizedDestination) -> PolicyAction {
        let Some(rules) = self.rules.get(secret_id) else {
            return PolicyAction::Block;
        };
        let mut best = None;
        for rule in rules {
            if !host_matches(&destination.host, &rule.host, rule.allow_subdomains) {
                continue;
            }
            if rule
                .scheme
                .as_deref()
                .is_some_and(|scheme| scheme != destination.scheme)
            {
                continue;
            }
            if rule.port.is_some() && rule.port != Some(destination.port) {
                continue;
            }
            best = Some(match (best, rule.action) {
                (None, action) => action,
                (Some(PolicyAction::Block), _) | (_, PolicyAction::Block) => PolicyAction::Block,
                (Some(PolicyAction::RequireApproval), _) | (_, PolicyAction::RequireApproval) => {
                    PolicyAction::RequireApproval
                }
                _ => PolicyAction::Allow,
            });
        }
        best.unwrap_or(PolicyAction::Block)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressVerdict {
    Allow,
    RequireApproval,
    Block,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressReport {
    pub verdict: EgressVerdict,
    pub normalized_destination: Option<String>,
    pub matches: Vec<LeakMatch>,
    pub reason_codes: Vec<&'static str>,
}

pub struct EgressGuard {
    fingerprints: SecretFingerprintIndex,
    policy: DestinationPolicy,
    max_payload_bytes: usize,
}

impl fmt::Debug for EgressGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressGuard")
            .field("fingerprints", &self.fingerprints)
            .field("policy", &self.policy)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .finish()
    }
}

impl EgressGuard {
    pub fn new(fingerprints: SecretFingerprintIndex, policy: DestinationPolicy) -> Self {
        Self {
            fingerprints,
            policy,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }

    pub fn with_max_payload_bytes(mut self, max_payload_bytes: usize) -> Self {
        self.max_payload_bytes = max_payload_bytes.max(1);
        self
    }

    pub fn inspect(&self, destination_url: &str, payload: &[u8]) -> EgressReport {
        if payload.len() > self.max_payload_bytes {
            return payload_limit_report(destination_url);
        }
        let matches = self.fingerprints.scan(payload);
        self.decide(destination_url, matches)
    }

    pub fn streaming(&self, destination_url: &str) -> StreamingEgressGuard<'_> {
        StreamingEgressGuard {
            guard: self,
            destination_url: destination_url.to_owned(),
            scanner: self.fingerprints.streaming_scanner(),
            total_payload_bytes: 0,
            terminal_limit_block: false,
        }
    }

    fn decide(&self, destination_url: &str, matches: Vec<LeakMatch>) -> EgressReport {
        let destination = match NormalizedDestination::parse(destination_url) {
            Ok(destination) => destination,
            Err(()) => {
                return EgressReport {
                    verdict: EgressVerdict::Block,
                    normalized_destination: None,
                    matches,
                    reason_codes: vec!["EGRESS_DESTINATION_INVALID"],
                };
            }
        };

        if matches.is_empty() {
            return EgressReport {
                verdict: EgressVerdict::Allow,
                normalized_destination: Some(destination.display()),
                matches,
                reason_codes: vec!["NO_REGISTERED_SECRET_DETECTED"],
            };
        }

        let mut action = PolicyAction::Allow;
        for leak in &matches {
            action = most_restrictive(
                action,
                self.policy.action_for(&leak.secret_id, &destination),
            );
        }
        let (verdict, reason) = match action {
            PolicyAction::Allow => (EgressVerdict::Allow, "SECRET_DESTINATION_ALLOWED"),
            PolicyAction::RequireApproval => (
                EgressVerdict::RequireApproval,
                "SECRET_DESTINATION_REQUIRES_APPROVAL",
            ),
            PolicyAction::Block => (EgressVerdict::Block, "SECRET_EGRESS_BLOCKED"),
        };

        EgressReport {
            verdict,
            normalized_destination: Some(destination.display()),
            matches,
            reason_codes: vec![reason],
        }
    }
}

pub struct StreamingEgressGuard<'a> {
    guard: &'a EgressGuard,
    destination_url: String,
    scanner: StreamingScanner<'a>,
    total_payload_bytes: usize,
    terminal_limit_block: bool,
}

impl fmt::Debug for StreamingEgressGuard<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingEgressGuard")
            .field("destination_url", &self.destination_url)
            .field("scanner", &self.scanner)
            .field("total_payload_bytes", &self.total_payload_bytes)
            .field("terminal_limit_block", &self.terminal_limit_block)
            .finish()
    }
}

impl StreamingEgressGuard<'_> {
    pub fn inspect_chunk(&mut self, chunk: &[u8]) -> EgressReport {
        if self.terminal_limit_block
            || self.total_payload_bytes.saturating_add(chunk.len()) > self.guard.max_payload_bytes
        {
            self.terminal_limit_block = true;
            return payload_limit_report(&self.destination_url);
        }
        self.total_payload_bytes += chunk.len();
        let matches = self.scanner.scan_chunk(chunk);
        self.guard.decide(&self.destination_url, matches)
    }
}

#[derive(Debug)]
struct NormalizedDestination {
    scheme: String,
    host: String,
    port: u16,
}

impl NormalizedDestination {
    /// Small fail-closed HTTP(S) authority parser. It intentionally rejects
    /// user-info, non-ASCII hostnames and malformed/unbracketed IPv6 rather
    /// than guessing or applying a browser-style URL normalization.
    fn parse(raw: &str) -> Result<Self, ()> {
        if raw.is_empty()
            || raw
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(());
        }
        let (raw_scheme, remainder) = raw.split_once("://").ok_or(())?;
        let scheme = raw_scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https") {
            return Err(());
        }
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        if authority.is_empty() || authority.contains('@') {
            return Err(());
        }

        let (host, explicit_port) = parse_authority(authority)?;
        let port = explicit_port.unwrap_or(if scheme == "https" { 443 } else { 80 });
        Ok(Self { scheme, host, port })
    }

    fn display(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{}://{}:{}", self.scheme, host, self.port)
    }
}

fn parse_authority(authority: &str) -> Result<(String, Option<u16>), ()> {
    if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest.find(']').ok_or(())?;
        let raw_host = &rest[..closing];
        let ip = IpAddr::from_str(raw_host).map_err(|_| ())?;
        if !ip.is_ipv6() {
            return Err(());
        }
        let suffix = &rest[closing + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(parse_port(suffix.strip_prefix(':').ok_or(())?)?)
        };
        return Ok((ip.to_string().to_ascii_lowercase(), port));
    }

    if authority.matches(':').count() > 1 {
        return Err(());
    }
    let (raw_host, port) = match authority.rsplit_once(':') {
        Some((host, raw_port)) => (host, Some(parse_port(raw_port)?)),
        None => (authority, None),
    };
    let host = normalize_and_validate_host(raw_host)?;
    Ok((host, port))
}

fn parse_port(raw: &str) -> Result<u16, ()> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let port = raw.parse::<u16>().map_err(|_| ())?;
    if port == 0 {
        return Err(());
    }
    Ok(port)
}

fn normalize_and_validate_host(raw_host: &str) -> Result<String, ()> {
    if !raw_host.is_ascii() || raw_host.contains('%') {
        return Err(());
    }
    let host = normalize_rule_host(raw_host);
    if host.is_empty() || host.len() > 253 {
        return Err(());
    }
    if let Ok(ip) = IpAddr::from_str(&host) {
        return Ok(ip.to_string().to_ascii_lowercase());
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(());
        }
    }
    Ok(host)
}

fn payload_limit_report(destination_url: &str) -> EgressReport {
    EgressReport {
        verdict: EgressVerdict::Block,
        normalized_destination: NormalizedDestination::parse(destination_url)
            .ok()
            .map(|destination| destination.display()),
        matches: Vec::new(),
        reason_codes: vec!["EGRESS_PAYLOAD_LIMIT_EXCEEDED"],
    }
}

fn most_restrictive(left: PolicyAction, right: PolicyAction) -> PolicyAction {
    use PolicyAction::{Allow, Block, RequireApproval};
    match (left, right) {
        (Block, _) | (_, Block) => Block,
        (RequireApproval, _) | (_, RequireApproval) => RequireApproval,
        _ => Allow,
    }
}

fn normalize_rule_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn host_matches(actual: &str, configured: &str, allow_subdomains: bool) -> bool {
    actual == configured
        || (allow_subdomains
            && actual.len() > configured.len()
            && actual.ends_with(configured)
            && actual.as_bytes()[actual.len() - configured.len() - 1] == b'.')
}

#[cfg(test)]
mod tests {
    use crate::{FingerprintKey, SecretFingerprintIndex};

    use super::*;

    fn guard(action: Option<PolicyAction>) -> EgressGuard {
        let mut index = SecretFingerprintIndex::new(FingerprintKey::from_bytes([9; 32]));
        index
            .register_secret("synthetic.api", b"synthetic-api-secret-123")
            .unwrap();
        let mut policy = DestinationPolicy::default();
        if let Some(action) = action {
            policy.add_rule(
                "synthetic.api",
                HostRule::exact_https("api.example.test", action),
            );
        }
        EgressGuard::new(index, policy)
    }

    #[test]
    fn defaults_to_block_when_secret_has_no_destination_rule() {
        let report = guard(None).inspect(
            "https://evil.example/upload",
            b"token=synthetic-api-secret-123",
        );
        assert_eq!(report.verdict, EgressVerdict::Block);
        assert_eq!(report.reason_codes, vec!["SECRET_EGRESS_BLOCKED"]);
        assert!(!format!("{report:?}").contains("synthetic-api-secret-123"));
    }

    #[test]
    fn allows_secret_only_for_exact_approved_https_host() {
        let guard = guard(Some(PolicyAction::Allow));
        assert_eq!(
            guard
                .inspect("https://API.EXAMPLE.TEST./v1", b"synthetic-api-secret-123")
                .verdict,
            EgressVerdict::Allow
        );
        assert_eq!(
            guard
                .inspect(
                    "https://sub.api.example.test/v1",
                    b"synthetic-api-secret-123"
                )
                .verdict,
            EgressVerdict::Block
        );
        assert_eq!(
            guard
                .inspect("http://api.example.test/v1", b"synthetic-api-secret-123")
                .verdict,
            EgressVerdict::Block
        );
        assert_eq!(
            guard
                .inspect(
                    "https://api.example.test:444/v1",
                    b"synthetic-api-secret-123"
                )
                .verdict,
            EgressVerdict::Block
        );
    }

    #[test]
    fn invalid_or_non_http_destination_fails_closed() {
        let guard = guard(Some(PolicyAction::Allow));
        for destination in [
            "file:///tmp/x",
            "https://user@api.example.test/x",
            "https://api.example.test:0/x",
            "https://bad host/x",
            "https://[127.0.0.1]/x",
        ] {
            let report = guard.inspect(destination, b"nothing secret");
            assert_eq!(report.verdict, EgressVerdict::Block, "{destination}");
            assert_eq!(report.reason_codes, vec!["EGRESS_DESTINATION_INVALID"]);
        }
    }

    #[test]
    fn require_approval_is_preserved() {
        let report = guard(Some(PolicyAction::RequireApproval))
            .inspect("https://api.example.test/v1", b"synthetic-api-secret-123");
        assert_eq!(report.verdict, EgressVerdict::RequireApproval);
    }

    #[test]
    fn stream_detects_secret_split_across_outbound_chunks() {
        let guard = guard(None);
        let mut stream = guard.streaming("https://evil.example/upload");
        assert_eq!(
            stream.inspect_chunk(b"synthetic-api-").verdict,
            EgressVerdict::Allow
        );
        assert_eq!(
            stream.inspect_chunk(b"secret-123").verdict,
            EgressVerdict::Block
        );
    }

    #[test]
    fn oversized_payload_fails_closed_before_expensive_scan() {
        let guard = guard(None).with_max_payload_bytes(16);
        let report = guard.inspect("https://evil.example/upload", &[b'x'; 17]);
        assert_eq!(report.verdict, EgressVerdict::Block);
        assert_eq!(report.reason_codes, vec!["EGRESS_PAYLOAD_LIMIT_EXCEEDED"]);

        let mut stream = guard.streaming("https://evil.example/upload");
        assert_eq!(
            stream.inspect_chunk(b"12345678").verdict,
            EgressVerdict::Allow
        );
        assert_eq!(
            stream.inspect_chunk(b"123456789").verdict,
            EgressVerdict::Block
        );
        assert_eq!(stream.inspect_chunk(b"x").verdict, EgressVerdict::Block);
    }

    #[test]
    fn parses_ipv4_and_bracketed_ipv6_deterministically() {
        assert_eq!(
            NormalizedDestination::parse("HTTPS://127.0.0.1/path")
                .unwrap()
                .display(),
            "https://127.0.0.1:443"
        );
        assert_eq!(
            NormalizedDestination::parse("http://[2001:db8::1]:8080/x")
                .unwrap()
                .display(),
            "http://[2001:db8::1]:8080"
        );
    }
}
