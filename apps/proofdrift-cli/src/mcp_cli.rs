use crate::runtime_cli::{evidence_db_path, CedarRuntimePolicy, PersistentRuntimeSink};
use proofdrift_mcp_proxy::{
    transport::{connect_transport, McpTransportConfig},
    BrokerError, BrokerLimits, McpBroker, MODERN_PROTOCOL_VERSION,
};
use proofdrift_runtime::ApprovalManager;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_MAX_UPSTREAM_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyConfig {
    server_id: String,
    #[serde(default = "default_policy")]
    policy: String,
    #[serde(default = "default_principal")]
    principal: String,
    #[serde(default)]
    approval_mode: ApprovalMode,
    #[serde(default)]
    evidence_root: Option<PathBuf>,
    #[serde(default)]
    limits: LimitConfig,
    transport: TransportConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ApprovalMode {
    #[default]
    Deny,
    Tty,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TransportConfig {
    Stdio {
        program: String,
        #[serde(default)]
        args: Vec<String>,
    },
    StreamableHttp {
        endpoint: String,
        #[serde(default)]
        header_env: BTreeMap<String, String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LimitConfig {
    timeout_ms: u64,
    max_request_bytes: usize,
    max_response_bytes: usize,
    max_concurrent_calls: usize,
    max_upstream_line_bytes: usize,
}

impl Default for LimitConfig {
    fn default() -> Self {
        let broker = BrokerLimits::default();
        Self {
            timeout_ms: broker.timeout_ms,
            max_request_bytes: broker.max_request_bytes,
            max_response_bytes: broker.max_response_bytes,
            max_concurrent_calls: broker.max_concurrent_calls,
            max_upstream_line_bytes: DEFAULT_MAX_UPSTREAM_LINE_BYTES,
        }
    }
}

impl LimitConfig {
    fn broker_limits(&self) -> BrokerLimits {
        BrokerLimits {
            timeout_ms: self.timeout_ms.max(1),
            max_request_bytes: self.max_request_bytes.max(1),
            max_response_bytes: self.max_response_bytes.max(1),
            max_concurrent_calls: self.max_concurrent_calls.max(1),
        }
    }
}

fn default_policy() -> String {
    "constrained-mcp".into()
}

fn default_principal() -> String {
    "mcp-client".into()
}

pub(crate) fn run_proxy(config_path: &Path) -> Result<u8, String> {
    let bytes = std::fs::read(config_path)
        .map_err(|error| format!("read MCP proxy config {}: {error}", config_path.display()))?;
    if bytes.len() > 1024 * 1024 {
        return Err("MCP proxy config exceeds 1 MiB".into());
    }
    let config: ProxyConfig = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse MCP proxy config {}: {error}", config_path.display()))?;
    validate_config(&config)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("build MCP runtime: {error}"))?;
    runtime.block_on(run_proxy_async(config))
}

async fn run_proxy_async(config: ProxyConfig) -> Result<u8, String> {
    let transport = resolve_transport(&config.transport)?;
    let downstream = connect_transport(&transport)
        .await
        .map_err(|error| format!("connect downstream MCP transport: {error}"))?;
    let policy = Arc::new(
        CedarRuntimePolicy::from_builtin(&config.policy)
            .map_err(|error| format!("load MCP policy {}: {error}", config.policy))?,
    );
    let evidence_root = config
        .evidence_root
        .clone()
        .unwrap_or(std::env::current_dir().map_err(|error| format!("resolve cwd: {error}"))?);
    std::fs::create_dir_all(&evidence_root)
        .map_err(|error| format!("create evidence root {}: {error}", evidence_root.display()))?;
    let db_path = evidence_db_path(&evidence_root);
    let sink = Arc::new(
        PersistentRuntimeSink::open(&db_path)
            .map_err(|error| format!("open MCP evidence store {}: {error}", db_path.display()))?,
    );
    let approvals = Arc::new(ApprovalManager::new(60_000));
    let session_id = new_session_id("mcp");
    let broker = McpBroker::new(
        config.server_id.clone(),
        MODERN_PROTOCOL_VERSION,
        policy,
        sink,
        approvals,
        downstream,
        config.limits.broker_limits(),
        session_id,
        config.principal.clone(),
    );

    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        let line = match read_bounded_line(&mut input, config.limits.max_upstream_line_bytes.max(1))
        {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                write_error(&mut output, Value::Null, -32700, &error, None)?;
                continue;
            }
        };
        let request: Value = match serde_json::from_slice(&line) {
            Ok(value) => value,
            Err(error) => {
                write_error(
                    &mut output,
                    Value::Null,
                    -32700,
                    "invalid JSON-RPC payload",
                    Some(json!({"detail": error.to_string()})),
                )?;
                continue;
            }
        };
        let Some(object) = request.as_object() else {
            write_error(
                &mut output,
                Value::Null,
                -32600,
                "MCP request must be a JSON object",
                None,
            )?;
            continue;
        };
        let id = object.get("id").cloned();
        if id.is_none() {
            // MCP 2026 defines no client-to-server notifications in the modern core. Ignore a
            // notification-shaped message rather than emitting a response with a made-up id.
            continue;
        }
        let id = id.unwrap_or(Value::Null);
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            write_error(&mut output, id, -32600, "jsonrpc must be 2.0", None)?;
            continue;
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            write_error(&mut output, id, -32600, "request method is missing", None)?;
            continue;
        };
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        if let Err(detail) = validate_modern_envelope(&params) {
            write_error(
                &mut output,
                id,
                -32022,
                "unsupported or missing MCP protocol version",
                Some(json!({"supported": [MODERN_PROTOCOL_VERSION], "detail": detail})),
            )?;
            continue;
        }

        match method {
            "server/discover" => write_result(
                &mut output,
                id,
                json!({
                    "resultType": "complete",
                    "supportedVersions": [MODERN_PROTOCOL_VERSION],
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "proofdrift-mcp-proxy",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "instructions": "Tool calls are policy-gated and recorded by ProofDrift before downstream dispatch."
                }),
            )?,
            "tools/list" => match broker.list_tools().await {
                Ok(tools) => write_result(
                    &mut output,
                    id,
                    json!({
                        "resultType": "complete",
                        "tools": tools,
                        "ttlMs": 0,
                        "cacheScope": "private"
                    }),
                )?,
                Err(error) => write_broker_error(&mut output, id, &error)?,
            },
            "tools/call" => {
                let Some(params) = params.as_object() else {
                    write_error(&mut output, id, -32602, "params must be an object", None)?;
                    continue;
                };
                let Some(name) = params.get("name").and_then(Value::as_str) else {
                    write_error(&mut output, id, -32602, "tools/call requires name", None)?;
                    continue;
                };
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if !arguments.is_object() {
                    write_error(
                        &mut output,
                        id,
                        -32602,
                        "tools/call arguments must be an object",
                        None,
                    )?;
                    continue;
                }
                let request_state = match params.get("requestState") {
                    None => None,
                    Some(Value::String(value)) => Some(value.as_str()),
                    Some(_) => {
                        write_error(
                            &mut output,
                            id,
                            -32602,
                            "requestState must be a string",
                            None,
                        )?;
                        continue;
                    }
                };
                let input_responses = match params.get("inputResponses") {
                    None => None,
                    Some(value) if value.is_object() => Some(value),
                    Some(_) => {
                        write_error(
                            &mut output,
                            id,
                            -32602,
                            "inputResponses must be an object",
                            None,
                        )?;
                        continue;
                    }
                };
                let first = broker
                    .call_tool_with_context(
                        name,
                        arguments.clone(),
                        request_state,
                        input_responses,
                        None,
                    )
                    .await;
                let result = match first {
                    Err(BrokerError::ApprovalRequired { approval_id })
                        if config.approval_mode == ApprovalMode::Tty =>
                    {
                        if prompt_tty_approval(&config.server_id, name, &approval_id)? {
                            let grant = broker
                                .approve_challenge(&approval_id)
                                .map_err(|error| format!("approve MCP challenge: {error}"))?;
                            broker
                                .call_tool_with_context(
                                    name,
                                    arguments,
                                    request_state,
                                    input_responses,
                                    Some(&grant.token),
                                )
                                .await
                        } else {
                            Err(BrokerError::ApprovalRequired { approval_id })
                        }
                    }
                    other => other,
                };
                match result {
                    Ok(response) => write_result(&mut output, id, response.result)?,
                    Err(error) => write_broker_error(&mut output, id, &error)?,
                }
            }
            _ => write_error(&mut output, id, -32601, "method not found", None)?,
        }
    }
    Ok(0)
}

fn validate_config(config: &ProxyConfig) -> Result<(), String> {
    if config.server_id.trim().is_empty() {
        return Err("MCP proxy server_id must not be empty".into());
    }
    if config.principal.trim().is_empty() {
        return Err("MCP proxy principal must not be empty".into());
    }
    if config.limits.max_request_bytes == 0
        || config.limits.max_response_bytes == 0
        || config.limits.max_concurrent_calls == 0
        || config.limits.max_upstream_line_bytes == 0
    {
        return Err("MCP proxy limits must be greater than zero".into());
    }
    Ok(())
}

fn resolve_transport(config: &TransportConfig) -> Result<McpTransportConfig, String> {
    match config {
        TransportConfig::Stdio { program, args } => Ok(McpTransportConfig::Stdio {
            program: program.clone(),
            args: args.clone(),
        }),
        TransportConfig::StreamableHttp {
            endpoint,
            header_env,
        } => {
            let mut headers = Vec::with_capacity(header_env.len());
            for (header, env_name) in header_env {
                if env_name.trim().is_empty() {
                    return Err(format!(
                        "environment variable name for header {header} is empty"
                    ));
                }
                let value = std::env::var(env_name).map_err(|_| {
                    format!(
                        "required environment variable {env_name} for header {header} is not set"
                    )
                })?;
                headers.push((header.clone(), value));
            }
            Ok(McpTransportConfig::StreamableHttp {
                endpoint: endpoint.clone(),
                protocol_version: MODERN_PROTOCOL_VERSION.into(),
                headers,
            })
        }
    }
}

fn validate_modern_envelope(params: &Value) -> Result<(), String> {
    let meta = params
        .as_object()
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
        .ok_or_else(|| "params._meta is required for MCP 2026".to_string())?;
    let version = meta
        .get("io.modelcontextprotocol/protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| "_meta protocolVersion is missing".to_string())?;
    if version != MODERN_PROTOCOL_VERSION {
        return Err(format!("received {version}"));
    }
    Ok(())
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut out = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| format!("read MCP upstream stdin: {error}"))?;
        if available.is_empty() {
            return if out.is_empty() {
                Ok(None)
            } else {
                Ok(Some(out))
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if out.len().saturating_add(take) > max_bytes.saturating_add(1) {
            reader.consume(take);
            return Err(format!("MCP upstream message exceeds {max_bytes} bytes"));
        }
        out.extend_from_slice(&available[..take]);
        reader.consume(take);
        if out.last() == Some(&b'\n') {
            out.pop();
            if out.last() == Some(&b'\r') {
                out.pop();
            }
            if out.is_empty() {
                continue;
            }
            return Ok(Some(out));
        }
    }
}

fn write_result<W: Write>(writer: &mut W, id: Value, result: Value) -> Result<(), String> {
    write_json_line(writer, &json!({"jsonrpc":"2.0","id":id,"result":result}))
}

fn write_error<W: Write>(
    writer: &mut W,
    id: Value,
    code: i64,
    message: &str,
    data: Option<Value>,
) -> Result<(), String> {
    let mut error = serde_json::Map::new();
    error.insert("code".into(), Value::from(code));
    error.insert("message".into(), Value::String(message.into()));
    if let Some(data) = data {
        error.insert("data".into(), data);
    }
    write_json_line(
        writer,
        &json!({"jsonrpc":"2.0","id":id,"error":Value::Object(error)}),
    )
}

fn write_json_line<W: Write>(writer: &mut W, value: &Value) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|error| format!("write JSON-RPC: {error}"))?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .map_err(|error| format!("flush JSON-RPC stdout: {error}"))
}

fn write_broker_error<W: Write>(
    writer: &mut W,
    id: Value,
    error: &BrokerError,
) -> Result<(), String> {
    let (code, message, data) = match error {
        BrokerError::Denied => (-32040, "tool call denied by ProofDrift policy", None),
        BrokerError::ApprovalRequired { approval_id } => (
            -32041,
            "human approval required before tool dispatch",
            Some(json!({"approvalId": approval_id})),
        ),
        BrokerError::SchemaDrift { drift } => (
            -32042,
            "downstream tool definition changed since the broker baseline",
            Some(json!({"drift": drift})),
        ),
        BrokerError::UnknownTool(name) => (
            -32602,
            "requested tool is not present in the current broker snapshot",
            Some(json!({"tool": name})),
        ),
        BrokerError::RequestTooLarge => (-32043, "request exceeded configured bound", None),
        BrokerError::ResponseTooLarge => (-32044, "response exceeded configured bound", None),
        BrokerError::Timeout => (-32045, "downstream operation timed out", None),
        BrokerError::ConcurrencyLimit => (-32046, "broker concurrency limit reached", None),
        other => (
            -32050,
            "MCP broker/downstream operation failed",
            Some(json!({"detail": other.to_string()})),
        ),
    };
    write_error(writer, id, code, message, data)
}

fn prompt_tty_approval(
    server_id: &str,
    tool_name: &str,
    approval_id: &str,
) -> Result<bool, String> {
    #[cfg(windows)]
    let (input_path, output_path) = ("CONIN$", "CONOUT$");
    #[cfg(not(windows))]
    let (input_path, output_path) = ("/dev/tty", "/dev/tty");

    let mut terminal_out = OpenOptions::new()
        .write(true)
        .open(output_path)
        .map_err(|error| {
            format!(
                "trusted TTY approval requested but no controlling terminal is available: {error}"
            )
        })?;
    writeln!(
        terminal_out,
        "ProofDrift approval required: server={server_id} tool={tool_name} challenge={approval_id}"
    )
    .and_then(|_| write!(terminal_out, "Approve one scoped dispatch? [y/N] "))
    .and_then(|_| terminal_out.flush())
    .map_err(|error| format!("write approval prompt: {error}"))?;

    let terminal_in = OpenOptions::new()
        .read(true)
        .open(input_path)
        .map_err(|error| format!("open trusted TTY for approval input: {error}"))?;
    let mut reader = BufReader::new(terminal_in);
    let mut answer = String::new();
    reader
        .read_line(&mut answer)
        .map_err(|error| format!("read approval response: {error}"))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn new_session_id(prefix: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{prefix}-{}-{millis}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_fail_closed_for_approval() {
        let config: ProxyConfig = serde_json::from_value(json!({
            "server_id":"srv",
            "transport":{"type":"stdio","program":"server","args":[]}
        }))
        .unwrap();
        assert_eq!(config.approval_mode, ApprovalMode::Deny);
        assert_eq!(config.policy, "constrained-mcp");
    }

    #[test]
    fn header_credentials_are_resolved_from_environment_name_not_config_value() {
        let name = format!("PROOFDRIFT_TEST_HEADER_{}", std::process::id());
        std::env::set_var(&name, "Bearer synthetic-test-value");
        let transport = resolve_transport(&TransportConfig::StreamableHttp {
            endpoint: "https://example.com/mcp".into(),
            header_env: BTreeMap::from([("Authorization".into(), name.clone())]),
        })
        .unwrap();
        std::env::remove_var(name);
        let encoded = transport.redacted_summary().to_string();
        assert!(encoded.contains("Authorization"));
        assert!(!encoded.contains("synthetic-test-value"));
    }

    #[test]
    fn modern_envelope_is_required() {
        assert!(validate_modern_envelope(&json!({})).is_err());
        assert!(validate_modern_envelope(&json!({"_meta":{
            "io.modelcontextprotocol/protocolVersion":MODERN_PROTOCOL_VERSION
        }}))
        .is_ok());
    }

    #[test]
    fn bounded_upstream_reader_rejects_large_message() {
        let bytes = vec![b'x'; 100];
        let mut reader = BufReader::new(bytes.as_slice());
        assert!(read_bounded_line(&mut reader, 16).is_err());
    }
}
