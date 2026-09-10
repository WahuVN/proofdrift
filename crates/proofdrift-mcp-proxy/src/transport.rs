use crate::{
    BrokerError, DownstreamMcp, DownstreamResponse, ToolDefinition, MODERN_PROTOCOL_VERSION,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::StreamExt;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE},
    redirect::Policy as RedirectPolicy,
    Client, Url,
};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Stdio,
    sync::Arc,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
};

const DEFAULT_MAX_WIRE_BYTES: usize = 8 * 1024 * 1024;
const CONNECT_TIMEOUT_MS: u64 = 5_000;
const MAX_LIST_PAGES: usize = 64;
const MAX_LIST_TOOLS: usize = 10_000;

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
            Self::Stdio { program, .. } => {
                if program.trim().is_empty() {
                    return Err(BrokerError::Downstream(
                        "stdio program must not be empty".into(),
                    ));
                }
                Ok(())
            }
            Self::StreamableHttp {
                endpoint,
                protocol_version,
                headers,
            } => {
                if protocol_version != MODERN_PROTOCOL_VERSION {
                    return Err(BrokerError::Downstream(format!(
                        "Streamable HTTP transport currently pins MCP {MODERN_PROTOCOL_VERSION}; legacy protocol {protocol_version} requires the retired session/initialize flow and is refused"
                    )));
                }
                validate_endpoint(endpoint)?;
                for (name, value) in headers {
                    validate_configured_header(name, value)?;
                }
                Ok(())
            }
        }
    }

    pub fn redacted_summary(&self) -> Value {
        match self {
            Self::Stdio { program, args } => json!({
                "transport": "stdio",
                "program": program,
                "arg_count": args.len(),
            }),
            Self::StreamableHttp {
                endpoint,
                protocol_version,
                headers,
            } => json!({
                "transport": "streamable_http",
                "endpoint": endpoint,
                "protocol_version": protocol_version,
                "header_names": headers.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            }),
        }
    }
}

pub async fn connect_transport(
    config: &McpTransportConfig,
) -> Result<Arc<dyn DownstreamMcp>, BrokerError> {
    config.validate()?;
    let connect = async {
        match config {
            McpTransportConfig::Stdio { program, args } => {
                let client =
                    StdioMcpClient::connect(program.clone(), args.clone(), DEFAULT_MAX_WIRE_BYTES)
                        .await?;
                client.probe_modern().await?;
                Ok::<Arc<dyn DownstreamMcp>, BrokerError>(Arc::new(client))
            }
            McpTransportConfig::StreamableHttp {
                endpoint,
                protocol_version,
                headers,
            } => {
                let client = StreamableHttpMcpClient::new(
                    endpoint,
                    protocol_version,
                    headers,
                    DEFAULT_MAX_WIRE_BYTES,
                )?;
                client.probe_modern().await?;
                Ok::<Arc<dyn DownstreamMcp>, BrokerError>(Arc::new(client))
            }
        }
    };
    tokio::time::timeout(
        std::time::Duration::from_millis(CONNECT_TIMEOUT_MS),
        connect,
    )
    .await
    .map_err(|_| BrokerError::Downstream("MCP server/discover probe timed out".into()))?
}

/// Simple delegation adapter retained as a narrow test/integration seam.
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

struct StdioState {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

pub struct StdioMcpClient {
    state: Mutex<StdioState>,
    max_wire_bytes: usize,
}

impl StdioMcpClient {
    pub async fn connect(
        program: String,
        args: Vec<String>,
        max_wire_bytes: usize,
    ) -> Result<Self, BrokerError> {
        if program.trim().is_empty() {
            return Err(BrokerError::Downstream(
                "stdio program must not be empty".into(),
            ));
        }
        let mut command = Command::new(&program);
        command
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // MCP stdio reserves stdout for protocol messages; server diagnostics belong on
            // stderr. Inheriting stderr prevents an unread pipe from deadlocking the server.
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|error| BrokerError::Downstream(format!("spawn MCP stdio server: {error}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| BrokerError::Downstream("MCP stdio child has no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BrokerError::Downstream("MCP stdio child has no stdout".into()))?;
        Ok(Self {
            state: Mutex::new(StdioState {
                _child: child,
                stdin,
                stdout: BufReader::new(stdout),
                next_id: 1,
            }),
            max_wire_bytes: max_wire_bytes.max(1024),
        })
    }

    async fn probe_modern(&self) -> Result<(), BrokerError> {
        let result = self.rpc("server/discover", json!({})).await?;
        validate_discover_result(&result)
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, BrokerError> {
        let mut state = self.state.lock().await;
        let id = state.next_id;
        state.next_id = state.next_id.saturating_add(1);
        let request = modern_request(id, method, params)?;
        let mut bytes = serde_json::to_vec(&request)?;
        if bytes.len() > self.max_wire_bytes {
            return Err(BrokerError::RequestTooLarge);
        }
        bytes.push(b'\n');
        state.stdin.write_all(&bytes).await.map_err(|error| {
            BrokerError::Downstream(format!("write MCP stdio request: {error}"))
        })?;
        state.stdin.flush().await.map_err(|error| {
            BrokerError::Downstream(format!("flush MCP stdio request: {error}"))
        })?;

        loop {
            let line = read_bounded_line(&mut state.stdout, self.max_wire_bytes).await?;
            let value: Value = serde_json::from_slice(&line).map_err(|error| {
                BrokerError::Downstream(format!("invalid JSON on MCP server stdout: {error}"))
            })?;
            if value.get("method").is_some() && value.get("id").is_some() {
                return Err(BrokerError::Downstream(
                    "MCP 2026 server-to-client JSON-RPC requests are not permitted; use input_required/MRTR"
                        .into(),
                ));
            }
            if value.get("id") == Some(&Value::from(id)) {
                return parse_jsonrpc_response(value, id);
            }
            // Notifications and responses for another request id are ignored. Access to a
            // single stdio connection is serialized, so a foreign response id is suspicious
            // but can arise from a late response after cancellation; keep waiting bounded by
            // the broker's outer timeout.
        }
    }
}

#[async_trait]
impl DownstreamMcp for StdioMcpClient {
    async fn list_tools(&self) -> Result<Vec<ToolDefinition>, BrokerError> {
        list_tools_paginated(|params| self.rpc("tools/list", params)).await
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<DownstreamResponse, BrokerError> {
        self.call_tool_with_context(name, arguments, None, None)
            .await
    }

    async fn call_tool_with_context(
        &self,
        name: &str,
        arguments: Value,
        request_state: Option<String>,
        input_responses: Option<Value>,
    ) -> Result<DownstreamResponse, BrokerError> {
        let params = tool_call_params(name, arguments, request_state, input_responses)?;
        let result = self.rpc("tools/call", params).await?;
        validate_call_result(&result)?;
        Ok(DownstreamResponse { result })
    }
}

pub struct StreamableHttpMcpClient {
    client: Client,
    endpoint: Url,
    protocol_version: String,
    configured_headers: HeaderMap,
    max_wire_bytes: usize,
    tool_headers: Mutex<BTreeMap<String, Vec<HeaderBinding>>>,
    next_id: Mutex<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeaderBinding {
    argument: String,
    header_suffix: String,
}

impl StreamableHttpMcpClient {
    pub fn new(
        endpoint: &str,
        protocol_version: &str,
        headers: &[(String, String)],
        max_wire_bytes: usize,
    ) -> Result<Self, BrokerError> {
        if protocol_version != MODERN_PROTOCOL_VERSION {
            return Err(BrokerError::Downstream(format!(
                "Streamable HTTP client requires MCP {MODERN_PROTOCOL_VERSION}"
            )));
        }
        let endpoint = validate_endpoint(endpoint)?;
        let mut configured_headers = HeaderMap::new();
        for (name, value) in headers {
            validate_configured_header(name, value)?;
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                BrokerError::Downstream(format!("invalid configured HTTP header name: {error}"))
            })?;
            let header_value = HeaderValue::from_str(value).map_err(|error| {
                BrokerError::Downstream(format!("invalid configured HTTP header value: {error}"))
            })?;
            configured_headers.insert(header_name, header_value);
        }
        let client = Client::builder()
            .redirect(RedirectPolicy::none())
            .build()
            .map_err(|error| BrokerError::Downstream(format!("build HTTP client: {error}")))?;
        Ok(Self {
            client,
            endpoint,
            protocol_version: protocol_version.into(),
            configured_headers,
            max_wire_bytes: max_wire_bytes.max(1024),
            tool_headers: Mutex::new(BTreeMap::new()),
            next_id: Mutex::new(1),
        })
    }

    async fn probe_modern(&self) -> Result<(), BrokerError> {
        let result = self.rpc("server/discover", json!({}), None, &[]).await?;
        validate_discover_result(&result)
    }

    async fn rpc(
        &self,
        method: &str,
        params: Value,
        routed_name: Option<&str>,
        dynamic_headers: &[(HeaderName, HeaderValue)],
    ) -> Result<Value, BrokerError> {
        let id = {
            let mut next = self.next_id.lock().await;
            let id = *next;
            *next = next.saturating_add(1);
            id
        };
        let request = modern_request(id, method, params)?;
        let request_bytes = serde_json::to_vec(&request)?;
        if request_bytes.len() > self.max_wire_bytes {
            return Err(BrokerError::RequestTooLarge);
        }

        let mut builder = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", &self.protocol_version)
            .header("Mcp-Method", method)
            .headers(self.configured_headers.clone())
            .body(request_bytes);
        if let Some(name) = routed_name {
            builder = builder.header("Mcp-Name", name);
        }
        for (name, value) in dynamic_headers {
            builder = builder.header(name, value);
        }
        let response = builder.send().await.map_err(|error| {
            BrokerError::Downstream(format!("MCP HTTP request failed: {error}"))
        })?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let body = read_bounded_http_body(response, self.max_wire_bytes).await?;
        let wire = if content_type.starts_with("text/event-stream") {
            parse_sse_response(&body, id)?
        } else {
            serde_json::from_slice(&body).map_err(|error| {
                BrokerError::Downstream(format!(
                    "MCP HTTP response is not valid JSON (status {status}): {error}"
                ))
            })?
        };
        // Modern MCP permits protocol JSON-RPC errors to arrive with HTTP 400, notably
        // header-mismatch errors. Parse the JSON-RPC envelope before treating status as fatal.
        if wire.get("id") == Some(&Value::from(id)) && wire.get("error").is_some() {
            return parse_jsonrpc_response(wire, id);
        }
        if !status.is_success() {
            return Err(BrokerError::Downstream(format!(
                "MCP HTTP status {status} without an addressed JSON-RPC error"
            )));
        }
        parse_jsonrpc_response(wire, id)
    }
}

#[async_trait]
impl DownstreamMcp for StreamableHttpMcpClient {
    async fn list_tools(&self) -> Result<Vec<ToolDefinition>, BrokerError> {
        let tools =
            list_tools_paginated(|params| self.rpc("tools/list", params, None, &[])).await?;
        let mut bindings = BTreeMap::new();
        let mut accepted = Vec::with_capacity(tools.len());
        for tool in tools {
            match tool_header_bindings(&tool) {
                Ok(tool_bindings) => {
                    bindings.insert(tool.name.clone(), tool_bindings);
                    accepted.push(tool);
                }
                Err(_) => {
                    // Current MCP requires clients to exclude a tool with an invalid
                    // x-mcp-header declaration. Do not let one malformed tool poison the
                    // rest of the catalog.
                }
            }
        }
        *self.tool_headers.lock().await = bindings;
        Ok(accepted)
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<DownstreamResponse, BrokerError> {
        self.call_tool_with_context(name, arguments, None, None)
            .await
    }

    async fn call_tool_with_context(
        &self,
        name: &str,
        arguments: Value,
        request_state: Option<String>,
        input_responses: Option<Value>,
    ) -> Result<DownstreamResponse, BrokerError> {
        let bindings = self
            .tool_headers
            .lock()
            .await
            .get(name)
            .cloned()
            .ok_or_else(|| {
                BrokerError::Downstream(format!(
                    "HTTP tool definition for {name} is not cached; list tools before call so x-mcp-header mirroring can be enforced"
                ))
            })?;
        let dynamic_headers = materialize_tool_headers(&bindings, &arguments)?;
        let params = tool_call_params(name, arguments, request_state, input_responses)?;
        let result = self
            .rpc("tools/call", params, Some(name), &dynamic_headers)
            .await?;
        validate_call_result(&result)?;
        Ok(DownstreamResponse { result })
    }
}

fn tool_call_params(
    name: &str,
    arguments: Value,
    request_state: Option<String>,
    input_responses: Option<Value>,
) -> Result<Value, BrokerError> {
    if !arguments.is_object() {
        return Err(BrokerError::Downstream(
            "tools/call arguments must be a JSON object".into(),
        ));
    }
    if input_responses
        .as_ref()
        .is_some_and(|value| !value.is_object())
    {
        return Err(BrokerError::Downstream(
            "MCP inputResponses must be a JSON object".into(),
        ));
    }
    let mut params = Map::new();
    params.insert("name".into(), Value::String(name.into()));
    params.insert("arguments".into(), arguments);
    if let Some(request_state) = request_state {
        params.insert("requestState".into(), Value::String(request_state));
    }
    if let Some(input_responses) = input_responses {
        params.insert("inputResponses".into(), input_responses);
    }
    Ok(Value::Object(params))
}

fn modern_request(id: u64, method: &str, params: Value) -> Result<Value, BrokerError> {
    let mut params = match params {
        Value::Object(map) => map,
        Value::Null => Map::new(),
        _ => {
            return Err(BrokerError::Downstream(
                "MCP request params must be an object".into(),
            ))
        }
    };
    if params.contains_key("_meta") {
        return Err(BrokerError::Downstream(
            "transport-owned MCP _meta must not be supplied by callers".into(),
        ));
    }
    params.insert(
        "_meta".into(),
        json!({
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": "proofdrift",
                "version": env!("CARGO_PKG_VERSION")
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        }),
    );
    Ok(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    }))
}

async fn list_tools_paginated<F, Fut>(mut rpc: F) -> Result<Vec<ToolDefinition>, BrokerError>
where
    F: FnMut(Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, BrokerError>>,
{
    let mut cursor: Option<String> = None;
    let mut tools = Vec::new();
    let mut seen_cursors = BTreeSet::new();
    for _ in 0..MAX_LIST_PAGES {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |cursor| json!({"cursor": cursor}));
        let result = rpc(params).await?;
        require_complete_result(&result, "tools/list")?;
        let page: Vec<ToolDefinition> =
            serde_json::from_value(result.get("tools").cloned().ok_or_else(|| {
                BrokerError::Downstream("tools/list result missing tools".into())
            })?)?;
        if tools.len().saturating_add(page.len()) > MAX_LIST_TOOLS {
            return Err(BrokerError::Downstream(format!(
                "tools/list exceeded {MAX_LIST_TOOLS} tools"
            )));
        }
        tools.extend(page);
        let next = result
            .get("nextCursor")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        match next {
            None => return Ok(tools),
            Some(next) => {
                if !seen_cursors.insert(next.clone()) {
                    return Err(BrokerError::Downstream(
                        "tools/list repeated a pagination cursor".into(),
                    ));
                }
                cursor = Some(next);
            }
        }
    }
    Err(BrokerError::Downstream(format!(
        "tools/list exceeded {MAX_LIST_PAGES} pages"
    )))
}

fn validate_discover_result(result: &Value) -> Result<(), BrokerError> {
    require_complete_result(result, "server/discover")?;
    let versions = result
        .get("supportedVersions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            BrokerError::Downstream("server/discover missing supportedVersions".into())
        })?;
    if !versions
        .iter()
        .any(|value| value.as_str() == Some(MODERN_PROTOCOL_VERSION))
    {
        return Err(BrokerError::Downstream(format!(
            "downstream MCP server does not advertise required protocol {MODERN_PROTOCOL_VERSION}"
        )));
    }
    if !result.get("capabilities").is_some_and(Value::is_object) {
        return Err(BrokerError::Downstream(
            "server/discover missing capabilities object".into(),
        ));
    }
    Ok(())
}

fn require_complete_result(result: &Value, method: &str) -> Result<(), BrokerError> {
    match result.get("resultType").and_then(Value::as_str) {
        Some("complete") => Ok(()),
        Some(other) => Err(BrokerError::Downstream(format!(
            "{method} returned unsupported resultType {other}"
        ))),
        None => Err(BrokerError::Downstream(format!(
            "{method} response is missing required MCP 2026 resultType"
        ))),
    }
}

fn validate_call_result(result: &Value) -> Result<(), BrokerError> {
    match result.get("resultType").and_then(Value::as_str) {
        Some("complete" | "input_required") => Ok(()),
        Some(other) => Err(BrokerError::Downstream(format!(
            "tools/call returned unsupported resultType {other}"
        ))),
        None => Err(BrokerError::Downstream(
            "tools/call response is missing required MCP 2026 resultType".into(),
        )),
    }
}

fn parse_jsonrpc_response(value: Value, id: u64) -> Result<Value, BrokerError> {
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(BrokerError::Downstream(
            "MCP response has invalid jsonrpc version".into(),
        ));
    }
    if value.get("id") != Some(&Value::from(id)) {
        return Err(BrokerError::Downstream(format!(
            "MCP response id does not match request id {id}"
        )));
    }
    if let Some(error) = value.get("error") {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("MCP server error");
        return Err(BrokerError::Downstream(format!(
            "MCP JSON-RPC error {code}: {message}"
        )));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| BrokerError::Downstream("MCP response missing result/error".into()))
}

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, BrokerError> {
    let mut out = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| BrokerError::Downstream(format!("read MCP stdio: {error}")))?;
        if available.is_empty() {
            return Err(BrokerError::Downstream(
                "MCP stdio server closed stdout before response".into(),
            ));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if out.len().saturating_add(take) > max_bytes.saturating_add(1) {
            return Err(BrokerError::ResponseTooLarge);
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
            return Ok(out);
        }
    }
}

async fn read_bounded_http_body(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BrokerError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(BrokerError::ResponseTooLarge);
    }
    let mut stream = response.bytes_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            BrokerError::Downstream(format!("read MCP HTTP response body: {error}"))
        })?;
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(BrokerError::ResponseTooLarge);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn parse_sse_response(body: &[u8], id: u64) -> Result<Value, BrokerError> {
    let text = std::str::from_utf8(body)
        .map_err(|error| BrokerError::Downstream(format!("MCP SSE is not UTF-8: {error}")))?;
    let mut data_lines = Vec::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if !data_lines.is_empty() {
                let data = data_lines.join("\n");
                data_lines.clear();
                let value: Value = serde_json::from_str(&data).map_err(|error| {
                    BrokerError::Downstream(format!("invalid JSON in MCP SSE data: {error}"))
                })?;
                if value.get("id") == Some(&Value::from(id)) {
                    return Ok(value);
                }
            }
        } else if let Some(data) = line.strip_prefix("data:") {
            data_lines.push(data.strip_prefix(' ').unwrap_or(data));
        }
    }
    Err(BrokerError::Downstream(format!(
        "MCP SSE response did not contain JSON-RPC id {id}"
    )))
}

fn validate_endpoint(endpoint: &str) -> Result<Url, BrokerError> {
    let url = Url::parse(endpoint)
        .map_err(|error| BrokerError::Downstream(format!("invalid MCP endpoint URL: {error}")))?;
    if url.username() != "" || url.password().is_some() {
        return Err(BrokerError::Downstream(
            "credentials in MCP endpoint URLs are forbidden; use an explicit authorization header"
                .into(),
        ));
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback_host(&url) => Ok(url),
        "http" => Err(BrokerError::Downstream(
            "remote Streamable HTTP requires https; plain http is limited to exact loopback hosts"
                .into(),
        )),
        other => Err(BrokerError::Downstream(format!(
            "unsupported MCP endpoint scheme: {other}"
        ))),
    }
}

fn is_loopback_host(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    )
}

fn validate_configured_header(name: &str, value: &str) -> Result<(), BrokerError> {
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "content-type" | "accept" | "mcp-protocol-version" | "mcp-method" | "mcp-name"
    ) || lower.starts_with("mcp-param-")
    {
        return Err(BrokerError::Downstream(format!(
            "configured header {name} would override a transport-owned MCP header"
        )));
    }
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|error| BrokerError::Downstream(format!("invalid HTTP header name: {error}")))?;
    HeaderValue::from_str(value)
        .map_err(|error| BrokerError::Downstream(format!("invalid HTTP header value: {error}")))?;
    Ok(())
}

fn tool_header_bindings(tool: &ToolDefinition) -> Result<Vec<HeaderBinding>, BrokerError> {
    let properties = match tool.input_schema.get("properties") {
        Some(Value::Object(properties)) => properties,
        Some(_) => {
            return Err(BrokerError::Downstream(format!(
                "tool {} has non-object inputSchema.properties",
                tool.name
            )))
        }
        None => return Ok(Vec::new()),
    };
    let mut seen = BTreeSet::new();
    let mut bindings = Vec::new();
    for (argument, schema) in properties {
        let Some(header_suffix) = schema.get("x-mcp-header").and_then(Value::as_str) else {
            continue;
        };
        if header_suffix.is_empty()
            || !header_suffix
                .bytes()
                .all(|byte| byte.is_ascii() && byte > 0x20 && byte != b':')
        {
            return Err(BrokerError::Downstream(format!(
                "tool {} has invalid x-mcp-header on {argument}",
                tool.name
            )));
        }
        let schema_type = schema.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(schema_type, "string" | "integer" | "number" | "boolean") {
            return Err(BrokerError::Downstream(format!(
                "tool {} applies x-mcp-header to non-primitive property {argument}",
                tool.name
            )));
        }
        let lower = header_suffix.to_ascii_lowercase();
        if !seen.insert(lower) {
            return Err(BrokerError::Downstream(format!(
                "tool {} has duplicate x-mcp-header names",
                tool.name
            )));
        }
        HeaderName::from_bytes(format!("Mcp-Param-{header_suffix}").as_bytes()).map_err(|_| {
            BrokerError::Downstream(format!(
                "tool {} has x-mcp-header that is not a valid HTTP field name",
                tool.name
            ))
        })?;
        bindings.push(HeaderBinding {
            argument: argument.clone(),
            header_suffix: header_suffix.into(),
        });
    }
    Ok(bindings)
}

fn materialize_tool_headers(
    bindings: &[HeaderBinding],
    arguments: &Value,
) -> Result<Vec<(HeaderName, HeaderValue)>, BrokerError> {
    let object = arguments.as_object().ok_or_else(|| {
        BrokerError::Downstream("tools/call arguments must be a JSON object".into())
    })?;
    let mut result = Vec::new();
    for binding in bindings {
        let Some(value) = object.get(&binding.argument) else {
            continue;
        };
        let lexical = match value {
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            _ => {
                return Err(BrokerError::Downstream(format!(
                    "x-mcp-header argument {} is not a primitive value",
                    binding.argument
                )))
            }
        };
        let encoded = encode_mcp_header_value(&lexical);
        let name =
            HeaderName::from_bytes(format!("Mcp-Param-{}", binding.header_suffix).as_bytes())
                .map_err(|error| {
                    BrokerError::Downstream(format!("invalid Mcp-Param header: {error}"))
                })?;
        let value = HeaderValue::from_str(&encoded).map_err(|error| {
            BrokerError::Downstream(format!("invalid Mcp-Param header value: {error}"))
        })?;
        result.push((name, value));
    }
    Ok(result)
}

fn encode_mcp_header_value(value: &str) -> String {
    let bytes = value.as_bytes();
    let safe = !value.is_empty()
        && value.trim() == value
        && bytes.iter().all(|byte| (0x20..=0x7e).contains(byte));
    if safe {
        value.to_owned()
    } else {
        format!("=?base64?{}?=", BASE64.encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn tool_with_header(name: &str, schema: Value) -> ToolDefinition {
        ToolDefinition {
            name: name.into(),
            description: None,
            input_schema: schema,
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn endpoint_validation_rejects_lookalike_loopback_and_credentials() {
        assert!(validate_endpoint("http://127.0.0.1:3000/mcp").is_ok());
        assert!(validate_endpoint("http://localhost:3000/mcp").is_ok());
        assert!(validate_endpoint("http://[::1]:3000/mcp").is_ok());
        assert!(validate_endpoint("https://example.com/mcp").is_ok());
        assert!(validate_endpoint("http://localhost.evil.example/mcp").is_err());
        assert!(validate_endpoint("https://user:pass@example.com/mcp").is_err());
    }

    #[test]
    fn redacted_summary_never_serializes_header_values() {
        let config = McpTransportConfig::StreamableHttp {
            endpoint: "https://example.com/mcp".into(),
            protocol_version: MODERN_PROTOCOL_VERSION.into(),
            headers: vec![("Authorization".into(), "Bearer SYNTHETIC_SECRET".into())],
        };
        let encoded = config.redacted_summary().to_string();
        assert!(encoded.contains("Authorization"));
        assert!(!encoded.contains("SYNTHETIC_SECRET"));
    }

    #[test]
    fn configured_headers_cannot_override_protocol_routing() {
        assert!(validate_configured_header("Authorization", "Bearer safe-placeholder").is_ok());
        assert!(validate_configured_header("Mcp-Method", "tools/call").is_err());
        assert!(validate_configured_header("mcp-param-region", "x").is_err());
    }

    #[test]
    fn modern_envelope_owns_meta() {
        let request = modern_request(7, "tools/list", json!({})).unwrap();
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["id"], 7);
        assert_eq!(
            request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            MODERN_PROTOCOL_VERSION
        );
        assert!(modern_request(1, "tools/list", json!({"_meta": {}})).is_err());
    }

    #[tokio::test]
    async fn bounded_line_rejects_oversize_without_unbounded_growth() {
        let bytes = vec![b'x'; 2048];
        let mut reader = BufReader::new(bytes.as_slice());
        let result = read_bounded_line(&mut reader, 128).await;
        assert!(matches!(result, Err(BrokerError::ResponseTooLarge)));
    }

    #[test]
    fn sse_parser_selects_addressed_response() {
        let body = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"resultType\":\"complete\"}}\n\n";
        let parsed = parse_sse_response(body, 9).unwrap();
        assert_eq!(parsed["id"], 9);
    }

    #[test]
    fn x_mcp_header_validation_and_mirroring_are_fail_closed() {
        let tool = tool_with_header(
            "query",
            json!({
                "type":"object",
                "properties":{
                    "region":{"type":"string","x-mcp-header":"Region"},
                    "count":{"type":"integer","x-mcp-header":"Count"}
                }
            }),
        );
        let bindings = tool_header_bindings(&tool).unwrap();
        let headers =
            materialize_tool_headers(&bindings, &json!({"region":"us-west1","count":3})).unwrap();
        assert!(headers.iter().any(|(name, value)| {
            name.as_str().eq_ignore_ascii_case("mcp-param-region")
                && value.to_str().ok() == Some("us-west1")
        }));

        let duplicate = tool_with_header(
            "bad",
            json!({"properties":{
                "a":{"type":"string","x-mcp-header":"Region"},
                "b":{"type":"string","x-mcp-header":"region"}
            }}),
        );
        assert!(tool_header_bindings(&duplicate).is_err());
    }

    #[test]
    fn non_ascii_or_trim_sensitive_header_values_use_base64_sentinel() {
        assert_eq!(encode_mcp_header_value("plain"), "plain");
        assert!(encode_mcp_header_value(" leading").starts_with("=?base64?"));
        assert!(encode_mcp_header_value("Việt Nam").starts_with("=?base64?"));
    }

    #[test]
    fn modern_result_type_is_required() {
        assert!(require_complete_result(&json!({"tools":[]}), "tools/list").is_err());
        assert!(require_complete_result(
            &json!({"resultType":"complete","tools":[]}),
            "tools/list"
        )
        .is_ok());
        assert!(validate_call_result(&json!({"resultType":"input_required"})).is_ok());
    }
}
