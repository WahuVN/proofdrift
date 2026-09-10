use crate::{BrokerError, DownstreamMcp, DownstreamResponse, ToolDefinition};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// Transport-neutral configuration surface.
///
/// Concrete stdio/HTTP clients are intentionally injected through `DownstreamMcp` so the
/// broker security path does not depend on one MCP SDK version. This lets integration code
/// negotiate legacy and modern MCP revisions without weakening deny-before-dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpTransportConfig {
    Stdio {
        program: String,
        args: Vec<String>,
    },
    StreamableHttp {
        endpoint: String,
        protocol_version: String,
        headers: Vec<(String, String)>,
    },
}

impl McpTransportConfig {
    pub fn validate(&self) -> Result<(), BrokerError> {
        match self {
            Self::Stdio { program, .. } if program.trim().is_empty() => Err(
                BrokerError::Downstream("stdio program must not be empty".into()),
            ),
            Self::StreamableHttp { endpoint, .. }
                if !(endpoint.starts_with("https://")
                    || endpoint.starts_with("http://127.0.0.1")
                    || endpoint.starts_with("http://localhost")) =>
            {
                Err(BrokerError::Downstream(
                    "remote Streamable HTTP requires https; plain http is limited to loopback"
                        .into(),
                ))
            }
            Self::StreamableHttp { endpoint, .. } if endpoint.trim().is_empty() => Err(
                BrokerError::Downstream("HTTP endpoint must not be empty".into()),
            ),
            _ => Ok(()),
        }
    }

    pub fn redacted_summary(&self) -> Value {
        match self {
            Self::Stdio { program, args } => serde_json::json!({
                "transport": "stdio",
                "program": program,
                "arg_count": args.len(),
            }),
            Self::StreamableHttp {
                endpoint,
                protocol_version,
                headers,
            } => serde_json::json!({
                "transport": "streamable_http",
                "endpoint": endpoint,
                "protocol_version": protocol_version,
                "header_names": headers.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            }),
        }
    }
}

/// Simple delegation adapter used by CLI/integration code after it constructs a concrete
/// stdio or HTTP MCP client. It keeps the broker's test seam small and makes fake servers easy.
pub struct DelegatingDownstream {
    inner: Arc<dyn DownstreamMcp>,
}

impl DelegatingDownstream {
    pub fn new(inner: Arc<dyn DownstreamMcp>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl DownstreamMcp for DelegatingDownstream {
    async fn list_tools(&self) -> Result<Vec<ToolDefinition>, BrokerError> {
        self.inner.list_tools().await
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<DownstreamResponse, BrokerError> {
        self.inner.call_tool(name, arguments).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_plain_http_is_rejected_but_loopback_is_allowed() {
        let remote = McpTransportConfig::StreamableHttp {
            endpoint: "http://example.com/mcp".into(),
            protocol_version: crate::MODERN_PROTOCOL_VERSION.into(),
            headers: vec![],
        };
        assert!(remote.validate().is_err());

        let local = McpTransportConfig::StreamableHttp {
            endpoint: "http://127.0.0.1:3000/mcp".into(),
            protocol_version: crate::MODERN_PROTOCOL_VERSION.into(),
            headers: vec![],
        };
        assert!(local.validate().is_ok());
    }

    #[test]
    fn redacted_summary_never_serializes_header_values() {
        let config = McpTransportConfig::StreamableHttp {
            endpoint: "https://example.com/mcp".into(),
            protocol_version: crate::MODERN_PROTOCOL_VERSION.into(),
            headers: vec![("Authorization".into(), "Bearer SYNTHETIC_SECRET".into())],
        };
        let encoded = config.redacted_summary().to_string();
        assert!(encoded.contains("Authorization"));
        assert!(!encoded.contains("SYNTHETIC_SECRET"));
    }
}
