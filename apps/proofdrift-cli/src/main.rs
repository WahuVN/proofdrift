use clap::{Args, Parser, Subcommand, ValueEnum};
use proofdrift_discover::discover_project;
use proofdrift_evidence::{verify_proofdrift_bundle, BundleLimits};
use proofdrift_patch::{analyze_git_range, TestPriority};
use proofdrift_policy::{
    built_in_policy_pack, lint_pack, PolicyDecisionKind, PolicyEngine, PolicyPack,
    PolicyRequest as CedarPolicyRequest,
};
use proofdrift_provenance::adapters::git::inspect_repository;
use proofdrift_scan::{scan_project, Severity as ScanSeverity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use thiserror::Error;
use walkdir::WalkDir;

mod config;
mod mcp_cli;
mod runtime_cli;

use config::LoadedConfig;

const SCHEMA_VERSION: &str = "0.1.0";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const EXIT_PASS: u8 = 0;
const EXIT_TOOL_ERROR: u8 = 1;
const EXIT_WARN: u8 = 2;
const EXIT_BLOCK: u8 = 3;
const EXIT_VERIFY_FAILED: u8 = 4;
const EXIT_UNSUPPORTED: u8 = 5;
const EXIT_CONFIG_ERROR: u8 = 64;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Parser)]
#[command(
    name = "proofdrift",
    version,
    about = "Local-first coding-agent change-control and evidence CLI",
    after_help = "Config precedence: CLI flags > PROOFDRIFT_* environment variables > config file > built-in defaults.\nDefault config: .proofdrift/config.toml (override with --config or PROOFDRIFT_CONFIG).\nExit classes: 0 pass, 1 tool error, 2 warn/findings, 3 block/deny, 4 verification failure, 5 unsupported, 64 config/input error."
)]
struct Cli {
    #[arg(
        long,
        global = true,
        conflicts_with = "output",
        help = "Emit stable machine-readable JSON (shorthand for --output json)"
    )]
    json: bool,
    #[arg(
        long,
        global = true,
        value_enum,
        conflicts_with = "json",
        help = "Output format; overrides environment and config"
    )]
    output: Option<OutputFormat>,
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Config file path (default: .proofdrift/config.toml when present)"
    )]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Discover(PathArg),
    Scan(PathArg),
    Config(ConfigArgs),
    Baseline(BaselineArgs),
    Diff(DiffArgs),
    Policy(PolicyArgs),
    Report(SessionArg),
    Verify(BundleArg),
    Patch(PatchArgs),
    Run(RunArgs),
    Mcp(McpArgs),
    Provenance(ProvenanceArgs),
}

#[derive(Args)]
struct PathArg {
    #[arg(default_value = ".")]
    path: PathBuf,
}

#[derive(Args)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand)]
enum ConfigCommand {
    Validate,
    Show,
}

#[derive(Args)]
struct BaselineArgs {
    #[command(subcommand)]
    command: BaselineCommand,
}

#[derive(Subcommand)]
enum BaselineCommand {
    Create {
        #[arg(long)]
        name: String,
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    List,
    Show {
        name: String,
    },
    Delete {
        name: String,
    },
}

#[derive(Args)]
struct DiffArgs {
    #[arg(long)]
    baseline: String,
    #[arg(default_value = ".")]
    path: PathBuf,
}

#[derive(Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Subcommand)]
enum PolicyCommand {
    Check { input: PathBuf },
    Lint { input: PathBuf },
    Explain { input: PathBuf },
}

#[derive(Args)]
struct SessionArg {
    session: Option<String>,
}
#[derive(Args)]
struct BundleArg {
    bundle: PathBuf,
}
#[derive(Args)]
struct PatchArgs {
    #[arg(long)]
    base: String,
    #[arg(long)]
    head: String,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum IsolationArg {
    None,
    Docker,
}

#[derive(Args)]
struct RunArgs {
    #[arg(
        long,
        value_name = "NAME",
        help = "Policy pack (CLI > PROOFDRIFT_POLICY > config > safe-local-dev)"
    )]
    policy: Option<String>,
    #[arg(
        long,
        value_name = "MILLISECONDS",
        help = "Timeout in ms (CLI > PROOFDRIFT_TIMEOUT_MS > config > 300000)"
    )]
    timeout_ms: Option<u64>,
    #[arg(
        long,
        value_name = "BYTES",
        help = "Captured output limit (CLI > PROOFDRIFT_MAX_OUTPUT_BYTES > config > 4194304)"
    )]
    max_output_bytes: Option<usize>,
    #[arg(long, value_enum, default_value_t = IsolationArg::None)]
    isolate: IsolationArg,
    /// Immutable container image reference required for --isolate docker.
    #[arg(long)]
    docker_image: Option<String>,
    /// Permit the isolated command to modify the mounted workspace.
    #[arg(long, default_value_t = false)]
    workspace_write: bool,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}
#[derive(Args)]
struct McpArgs {
    #[command(subcommand)]
    command: McpCommand,
}
#[derive(Subcommand)]
enum McpCommand {
    Proxy {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}
#[derive(Args)]
struct ProvenanceArgs {
    #[command(subcommand)]
    command: ProvenanceCommand,
}
#[derive(Subcommand)]
enum ProvenanceCommand {
    Explain { artifact: String },
}

#[derive(Debug, Error)]
enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON processing error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("tool error: {0}")]
    Tool(String),
    #[error("feature unavailable: {0}")]
    Unsupported(String),
}

impl From<config::ConfigError> for AppError {
    fn from(value: config::ConfigError) -> Self {
        Self::Config(value.to_string())
    }
}

impl AppError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::Invalid(_) => EXIT_CONFIG_ERROR,
            Self::Unsupported(_) => EXIT_UNSUPPORTED,
            Self::Io(_) | Self::Json(_) | Self::Tool(_) => EXIT_TOOL_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "PD_CLI_IO",
            Self::Json(_) => "PD_CLI_JSON",
            Self::Config(_) => "PD_CLI_CONFIG",
            Self::Invalid(_) => "PD_CLI_INPUT",
            Self::Tool(_) => "PD_CLI_TOOL",
            Self::Unsupported(_) => "PD_CLI_UNSUPPORTED",
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Config(_) | Self::Invalid(_) => "config_error",
            Self::Unsupported(_) => "unsupported",
            Self::Io(_) | Self::Json(_) | Self::Tool(_) => "tool_error",
        }
    }

    fn hint(&self) -> &'static str {
        match self {
            Self::Config(_) | Self::Invalid(_) => {
                "Check --help, proofdrift config validate, and the reported input/config path."
            }
            Self::Unsupported(_) => "Use a supported enforcement surface or integration.",
            Self::Io(_) | Self::Json(_) | Self::Tool(_) => {
                "Retry after fixing the reported local/tooling failure; this is not a policy verdict."
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Artifact {
    artifact_id: String,
    artifact_type: String,
    name: String,
    local_path: String,
    sha256: String,
    provenance_status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Snapshot {
    schema_version: String,
    name: String,
    root: String,
    digest: String,
    artifacts: Vec<Artifact>,
}

#[derive(Debug, Serialize)]
struct Envelope<T: Serialize> {
    schema_version: &'static str,
    generated_at: String,
    tool_version: &'static str,
    scope: String,
    data: T,
    diagnostics: Vec<Diagnostic>,
    evidence_refs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Diagnostic {
    code: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct DiffData {
    baseline: String,
    baseline_digest: String,
    current_digest: String,
    changes: Vec<Change>,
}

#[derive(Debug, Serialize)]
struct Change {
    severity: String,
    change: String,
    artifact: String,
    before: Option<String>,
    after: Option<String>,
    evidence: String,
}

fn main() -> ExitCode {
    let raw_args = std::env::args_os().collect::<Vec<_>>();
    let raw_json = raw_requests_json(&raw_args);
    let cli = match Cli::try_parse_from(raw_args) {
        Ok(cli) => cli,
        Err(error) if error.exit_code() == 0 => {
            let _ = error.print();
            return ExitCode::from(EXIT_PASS);
        }
        Err(error) => {
            if raw_json {
                let app_error = AppError::Config(format!("CLI parse error: {error}"));
                return finish_error(&app_error, true);
            }
            let _ = error.print();
            return ExitCode::from(EXIT_CONFIG_ERROR);
        }
    };

    let explicit_output = if cli.json {
        Some(true)
    } else {
        cli.output.map(|value| matches!(value, OutputFormat::Json))
    };
    let error_json = explicit_output.unwrap_or(false);
    let loaded = match LoadedConfig::load(cli.config.as_deref()) {
        Ok(config) => config,
        Err(error) => return finish_error(&AppError::from(error), error_json),
    };
    let json = match loaded.resolve_json(explicit_output) {
        Ok(json) => json,
        Err(error) => return finish_error(&AppError::from(error), error_json),
    };

    match run(cli, &loaded, json) {
        Ok(code) => ExitCode::from(code),
        Err(error) => finish_error(&error, json),
    }
}

fn raw_requests_json(args: &[OsString]) -> bool {
    let args = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    args.iter()
        .any(|arg| arg == "--json" || arg.eq_ignore_ascii_case("--output=json"))
        || args
            .windows(2)
            .any(|pair| pair[0] == "--output" && pair[1].eq_ignore_ascii_case("json"))
}

fn finish_error(error: &AppError, json: bool) -> ExitCode {
    let exit_code = error.exit_code();
    if json {
        let payload = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "generated_at": "deterministic-local",
            "tool_version": TOOL_VERSION,
            "status": "error",
            "exit_code": exit_code,
            "error": {
                "kind": error.kind(),
                "code": error.code(),
                "message": error.to_string(),
                "hint": error.hint()
            },
            "diagnostics": [{
                "code": error.code(),
                "message": error.to_string()
            }],
            "evidence_refs": []
        });
        println!("{payload}");
    } else {
        eprintln!("error [{}]: {error}", error.code());
        eprintln!("hint: {}", error.hint());
    }
    ExitCode::from(exit_code)
}

fn run(cli: Cli, loaded: &LoadedConfig, json: bool) -> Result<u8, AppError> {
    match cli.command {
        Command::Discover(args) => {
            let data =
                discover_project(&args.path).map_err(|e| AppError::Invalid(e.to_string()))?;
            emit(json, &args.path, data, |d| {
                println!("Discovered {} artifacts", d.artifacts.len());
                for a in &d.artifacts {
                    println!("  {}  {}", a.artifact_type, a.local_path);
                }
                for diagnostic in &d.diagnostics {
                    println!("  diagnostic: {diagnostic}");
                }
            })?;
            Ok(EXIT_PASS)
        }
        Command::Scan(args) => {
            let data = scan_project(&args.path).map_err(|e| AppError::Invalid(e.to_string()))?;
            let code = if data
                .findings
                .iter()
                .any(|f| matches!(f.severity, ScanSeverity::High | ScanSeverity::Critical))
            {
                EXIT_WARN
            } else {
                EXIT_PASS
            };
            emit(json, &args.path, data, |d| {
                println!("Findings: {}", d.findings.len());
                for f in &d.findings {
                    println!(
                        "{} | {} | {} | {}",
                        format!("{:?}", f.severity).to_uppercase(),
                        f.category,
                        f.location.path,
                        f.title
                    );
                }
            })?;
            Ok(code)
        }
        Command::Config(args) => config_command(json, args.command, loaded),
        Command::Baseline(args) => baseline(json, args.command),
        Command::Diff(args) => diff(json, args),
        Command::Policy(args) => policy(json, args.command),
        Command::Report(args) => report(json, args),
        Command::Verify(args) => verify_bundle_shape(json, &args.bundle),
        Command::Patch(args) => patch(json, args),
        Command::Run(args) => run_guarded(json, args, loaded),
        Command::Mcp(args) => match args.command {
            McpCommand::Proxy { config } => {
                let config =
                    config.unwrap_or_else(|| PathBuf::from(".proofdrift").join("mcp-proxy.json"));
                mcp_cli::run_proxy(&config).map_err(AppError::Invalid)
            }
        },
        Command::Provenance(args) => provenance(json, args.command),
    }
}

fn config_command(
    json: bool,
    command: ConfigCommand,
    loaded: &LoadedConfig,
) -> Result<u8, AppError> {
    let view = loaded.effective_view(json)?;
    match command {
        ConfigCommand::Validate => {
            if json {
                emit(
                    true,
                    loaded.source().unwrap_or_else(|| Path::new(".")),
                    serde_json::json!({
                        "valid": true,
                        "config": view
                    }),
                    |_| {},
                )?;
            } else if let Some(path) = loaded.source() {
                println!("VALID: {}", path.display());
            } else {
                println!("VALID: no config file selected; built-in defaults are valid");
            }
        }
        ConfigCommand::Show => {
            let scope = loaded.source().unwrap_or_else(|| Path::new("."));
            emit(json, scope, view, |value| {
                println!(
                    "Config source: {}",
                    value.source.as_deref().unwrap_or("built-in defaults")
                );
                println!("Output: {}", value.output);
                println!("Run policy: {}", value.run.policy);
                println!("Run timeout: {} ms", value.run.timeout_ms);
                println!("Run max output: {} bytes", value.run.max_output_bytes);
            })?;
        }
    }
    Ok(EXIT_PASS)
}

fn emit<T: Serialize>(
    json: bool,
    scope: &Path,
    data: T,
    human: impl FnOnce(&T),
) -> Result<(), AppError> {
    if json {
        let envelope = Envelope {
            schema_version: SCHEMA_VERSION,
            generated_at: "deterministic-local".into(),
            tool_version: TOOL_VERSION,
            scope: scope.display().to_string(),
            data,
            diagnostics: vec![],
            evidence_refs: vec![],
        };
        serde_json::to_writer_pretty(io::stdout().lock(), &envelope)?;
        println!();
    } else {
        human(&data);
    }
    Ok(())
}

fn inventory(root: &Path) -> Result<Vec<Artifact>, AppError> {
    let canonical = fs::canonicalize(root)?;
    let mut out = Vec::new();
    for entry in WalkDir::new(&canonical)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = match path.strip_prefix(&canonical) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if should_skip(rel) {
            continue;
        }
        let bytes = fs::read(path)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        let rel_norm = rel.to_string_lossy().replace('\\', "/");
        let kind = classify(&rel_norm);
        let artifact_id = format!("file:sha256:{digest}");
        out.push(Artifact {
            artifact_id,
            artifact_type: kind.into(),
            name: entry.file_name().to_string_lossy().into_owned(),
            local_path: rel_norm,
            sha256: digest,
            provenance_status: "observed".into(),
        });
    }
    out.sort_by(|a, b| {
        a.local_path
            .cmp(&b.local_path)
            .then(a.sha256.cmp(&b.sha256))
    });
    Ok(out)
}

fn should_skip(path: &Path) -> bool {
    path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some(".git" | ".proofdrift" | "target" | "node_modules")
        )
    })
}

fn classify(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".json") && lower.contains("mcp") {
        "mcp_server"
    } else if lower.contains("skill") {
        "skill"
    } else if lower.contains("hook") {
        "hook"
    } else if lower.contains("agent") {
        "agent"
    } else if lower.ends_with("cargo.lock")
        || lower.ends_with("package-lock.json")
        || lower.ends_with("apm.lock.yaml")
    {
        "package"
    } else {
        "file"
    }
}

fn inventory_digest(artifacts: &[Artifact]) -> String {
    let mut h = Sha256::new();
    for a in artifacts {
        h.update(a.local_path.as_bytes());
        h.update([0]);
        h.update(a.sha256.as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

fn state_dir() -> Result<PathBuf, AppError> {
    let cwd = std::env::current_dir()?;
    Ok(cwd.join(".proofdrift").join("baselines"))
}

fn baseline(json: bool, cmd: BaselineCommand) -> Result<u8, AppError> {
    let dir = state_dir()?;
    fs::create_dir_all(&dir)?;
    match cmd {
        BaselineCommand::Create { name, path } => {
            validate_name(&name)?;
            let artifacts = inventory(&path)?;
            let snap = Snapshot {
                schema_version: SCHEMA_VERSION.into(),
                name: name.clone(),
                root: path.display().to_string(),
                digest: inventory_digest(&artifacts),
                artifacts,
            };
            let bytes = serde_json::to_vec_pretty(&snap)?;
            fs::write(dir.join(format!("{name}.json")), bytes)?;
            if json {
                emit(true, &path, snap, |_| {})?;
            } else {
                println!("Baseline '{name}' created: {}", snap.digest);
            }
            Ok(0)
        }
        BaselineCommand::List => {
            let mut names = Vec::new();
            for e in fs::read_dir(&dir)? {
                let e = e?;
                if e.path().extension().and_then(|x| x.to_str()) == Some("json") {
                    if let Some(s) = e.path().file_stem().and_then(|x| x.to_str()) {
                        names.push(s.to_owned());
                    }
                }
            }
            names.sort();
            if json {
                emit(true, Path::new("."), names, |_| {})?;
            } else {
                for n in names {
                    println!("{n}");
                }
            }
            Ok(0)
        }
        BaselineCommand::Show { name } => {
            validate_name(&name)?;
            let snap = read_baseline(&name)?;
            if json {
                emit(true, Path::new("."), snap, |_| {})?;
            } else {
                println!(
                    "{}  {}  {} artifacts",
                    snap.name,
                    snap.digest,
                    snap.artifacts.len()
                );
            }
            Ok(0)
        }
        BaselineCommand::Delete { name } => {
            validate_name(&name)?;
            let path = dir.join(format!("{name}.json"));
            if path.exists() {
                fs::remove_file(path)?;
            }
            if json {
                emit(
                    true,
                    Path::new("."),
                    serde_json::json!({"deleted": name}),
                    |_| {},
                )?;
            } else {
                println!("Deleted baseline '{name}'");
            }
            Ok(0)
        }
    }
}

fn validate_name(name: &str) -> Result<(), AppError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::Invalid(
            "baseline name must match [A-Za-z0-9_-]{1,64}".into(),
        ));
    }
    Ok(())
}

fn read_baseline(name: &str) -> Result<Snapshot, AppError> {
    let bytes = fs::read(state_dir()?.join(format!("{name}.json")))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn diff(json: bool, args: DiffArgs) -> Result<u8, AppError> {
    validate_name(&args.baseline)?;
    let before = read_baseline(&args.baseline)?;
    let current = inventory(&args.path)?;
    let current_digest = inventory_digest(&current);
    let old: BTreeMap<_, _> = before
        .artifacts
        .iter()
        .map(|a| (a.local_path.clone(), a))
        .collect();
    let new: BTreeMap<_, _> = current.iter().map(|a| (a.local_path.clone(), a)).collect();
    let paths: BTreeSet<_> = old.keys().chain(new.keys()).cloned().collect();
    let mut changes = Vec::new();
    for path in paths {
        match (old.get(&path), new.get(&path)) {
            (None, Some(a)) => changes.push(change(
                "medium",
                "COMPONENT_ADDED",
                &path,
                None,
                Some(&a.sha256),
            )),
            (Some(a), None) => changes.push(change(
                "medium",
                "COMPONENT_REMOVED",
                &path,
                Some(&a.sha256),
                None,
            )),
            (Some(a), Some(b)) if a.sha256 != b.sha256 => changes.push(change(
                "high",
                "HASH_DRIFT",
                &path,
                Some(&a.sha256),
                Some(&b.sha256),
            )),
            _ => {}
        }
    }
    changes.sort_by(|a, b| a.artifact.cmp(&b.artifact).then(a.change.cmp(&b.change)));
    let code = if changes
        .iter()
        .any(|c| c.severity == "high" || c.severity == "critical")
    {
        2
    } else {
        0
    };
    let data = DiffData {
        baseline: before.name,
        baseline_digest: before.digest,
        current_digest,
        changes,
    };
    if json {
        emit(true, &args.path, data, |_| {})?;
    } else {
        println!("{} -> {}", data.baseline_digest, data.current_digest);
        println!("SEVERITY | CHANGE | ARTIFACT | BEFORE -> AFTER | EVIDENCE");
        for c in &data.changes {
            println!(
                "{} | {} | {} | {} -> {} | {}",
                c.severity.to_uppercase(),
                c.change,
                c.artifact,
                c.before.as_deref().unwrap_or("-"),
                c.after.as_deref().unwrap_or("-"),
                c.evidence
            );
        }
        if data.changes.is_empty() {
            println!("No changes.");
        }
    }
    Ok(code)
}

fn change(
    severity: &str,
    kind: &str,
    artifact: &str,
    before: Option<&String>,
    after: Option<&String>,
) -> Change {
    Change {
        severity: severity.into(),
        change: kind.into(),
        artifact: artifact.into(),
        before: before.cloned(),
        after: after.cloned(),
        evidence: "local-content-digest".into(),
    }
}

fn policy(json: bool, cmd: PolicyCommand) -> Result<u8, AppError> {
    match cmd {
        PolicyCommand::Lint { input } => {
            let bytes = fs::read(&input)?;
            let pack: PolicyPack = serde_json::from_slice(&bytes)?;
            let diagnostics = lint_pack(&pack);
            let invalid = !diagnostics.is_empty();
            let data = serde_json::json!({
                "policy_pack": pack.name,
                "version": pack.version,
                "valid": !invalid,
                "diagnostics": diagnostics,
            });
            emit(json, &input, data, |d| {
                println!(
                    "{}",
                    if d["valid"].as_bool() == Some(true) {
                        "VALID"
                    } else {
                        "INVALID"
                    }
                );
                if let Some(items) = d["diagnostics"].as_array() {
                    for item in items {
                        println!("  {}", item.as_str().unwrap_or("unknown diagnostic"));
                    }
                }
            })?;
            Ok(if invalid { 2 } else { 0 })
        }
        PolicyCommand::Check { input } | PolicyCommand::Explain { input } => {
            let bytes = fs::read(&input)?;
            let request: CedarPolicyRequest = serde_json::from_slice(&bytes)?;
            let pack_name = request
                .context
                .get("policy_pack")
                .and_then(|v| v.as_str())
                .unwrap_or("safe-local-dev");
            let source = built_in_policy_pack(pack_name).ok_or_else(|| {
                AppError::Invalid(format!("unknown built-in policy pack: {pack_name}"))
            })?;
            let engine = PolicyEngine::default();
            let pack = engine
                .compile_cached(source)
                .map_err(|e| AppError::Invalid(e.to_string()))?;
            let decision = engine
                .evaluate(&pack, &request, None)
                .map_err(|e| AppError::Invalid(e.to_string()))?;
            let exit = match decision.decision {
                PolicyDecisionKind::Deny | PolicyDecisionKind::RequireApproval => 3,
                PolicyDecisionKind::Allow | PolicyDecisionKind::Observe => 0,
            };
            emit(json, &input, decision, |d| {
                println!("{:?}", d.decision);
                println!("Policy digest: {}", d.policy_bundle_digest);
                if !d.reason_codes.is_empty() {
                    println!("Reasons: {}", d.reason_codes.join(", "));
                }
            })?;
            Ok(exit)
        }
    }
}

fn run_guarded(json: bool, args: RunArgs, loaded: &LoadedConfig) -> Result<u8, AppError> {
    let cwd = std::env::current_dir()?;
    let resolved = loaded.resolve_run(args.policy, args.timeout_ms, args.max_output_bytes)?;
    let isolation = match args.isolate {
        IsolationArg::None => {
            if args.docker_image.is_some() || args.workspace_write {
                return Err(AppError::Invalid(
                    "--docker-image/--workspace-write require --isolate docker".into(),
                ));
            }
            runtime_cli::RunIsolation::None
        }
        IsolationArg::Docker => {
            let image = args.docker_image.clone().ok_or_else(|| {
                AppError::Invalid(
                    "--isolate docker requires --docker-image <name>@sha256:<64-hex>".into(),
                )
            })?;
            runtime_cli::RunIsolation::Docker {
                image,
                workspace_writable: args.workspace_write,
            }
        }
    };
    match runtime_cli::execute_guarded_command(
        &args.command,
        &cwd,
        &resolved.policy,
        resolved.timeout_ms,
        resolved.max_output_bytes,
        isolation,
    ) {
        Ok(data) => {
            let code = if data.status_code == Some(0) {
                EXIT_PASS
            } else {
                EXIT_TOOL_ERROR
            };
            emit(json, &cwd, data, |d| {
                if !d.stdout.is_empty() {
                    print!("{}", d.stdout);
                    if !d.stdout.ends_with('\n') {
                        println!();
                    }
                }
                if !d.stderr.is_empty() {
                    eprint!("{}", d.stderr);
                    if !d.stderr.ends_with('\n') {
                        eprintln!();
                    }
                }
                println!("Session: {}", d.session_id);
                println!("Policy: {}", d.policy_pack);
                println!(
                    "Enforcement: {} ({})",
                    d.enforcement_level, d.enforcement_scope
                );
                println!("Evidence events: {}", d.events_recorded);
                println!("Evidence DB: {}", d.evidence_db);
                println!(
                    "Process exit: {}",
                    d.status_code
                        .map_or_else(|| "signal/unknown".into(), |value| value.to_string())
                );
            })?;
            Ok(code)
        }
        Err(runtime_cli::GuardedRunError::Denied {
            session_id,
            evidence_db,
            events_recorded,
        }) => {
            let data = serde_json::json!({
                "verdict": "block",
                "reason": "policy_denied",
                "dispatched": false,
                "session_id": session_id,
                "events_recorded": events_recorded,
                "evidence_db": evidence_db,
                "policy_pack": resolved.policy
            });
            emit(json, &cwd, data, |d| {
                eprintln!("DENIED: policy blocked command before process dispatch");
                eprintln!("Session: {}", d["session_id"].as_str().unwrap_or("unknown"));
                eprintln!("Evidence events: {}", d["events_recorded"]);
                eprintln!(
                    "Evidence DB: {}",
                    d["evidence_db"].as_str().unwrap_or("unknown")
                );
            })?;
            Ok(EXIT_BLOCK)
        }
        Err(runtime_cli::GuardedRunError::ApprovalRequired {
            approval_id,
            session_id,
            evidence_db,
            events_recorded,
        }) => {
            let data = serde_json::json!({
                "verdict": "block",
                "reason": "approval_required",
                "approval_id": approval_id,
                "dispatched": false,
                "session_id": session_id,
                "events_recorded": events_recorded,
                "evidence_db": evidence_db,
                "policy_pack": resolved.policy
            });
            emit(json, &cwd, data, |d| {
                eprintln!(
                    "APPROVAL_REQUIRED: {}; command was not dispatched",
                    d["approval_id"].as_str().unwrap_or("unknown")
                );
                eprintln!("Session: {}", d["session_id"].as_str().unwrap_or("unknown"));
                eprintln!("Evidence events: {}", d["events_recorded"]);
                eprintln!(
                    "Evidence DB: {}",
                    d["evidence_db"].as_str().unwrap_or("unknown")
                );
            })?;
            Ok(EXIT_BLOCK)
        }
        Err(runtime_cli::GuardedRunError::Setup(error)) => Err(AppError::Config(error)),
        Err(runtime_cli::GuardedRunError::Runtime(error)) => Err(AppError::Tool(error)),
    }
}

fn report(json: bool, args: SessionArg) -> Result<u8, AppError> {
    let cwd = std::env::current_dir()?;
    let data = runtime_cli::load_report(&cwd, args.session.as_deref())
        .map_err(|error| AppError::Invalid(error.to_string()))?;
    emit(json, &cwd, data, |d| match d {
        runtime_cli::ReportResult::SessionList { sessions } => {
            if sessions.is_empty() {
                println!("No recorded runtime sessions.");
            } else {
                println!("Recorded sessions: {}", sessions.len());
                for session in sessions {
                    println!("  {session}");
                }
            }
        }
        runtime_cli::ReportResult::Session {
            session_id,
            valid,
            event_count,
            final_hash,
            events,
        } => {
            println!("Session: {session_id}");
            println!("Chain valid: {valid}");
            println!("Events: {event_count}");
            println!("Final hash: {final_hash}");
            println!("SEQ | EVENT | ACTION | OUTCOME | LEVEL | RESOURCE");
            for event in events {
                println!(
                    "{} | {} | {} | {} | {} | {}",
                    event.sequence,
                    event.event.event_type,
                    event.event.proposed_action,
                    event.event.outcome,
                    event.event.enforcement_level,
                    event.event.resource
                );
            }
        }
    })?;
    Ok(0)
}

fn patch(json: bool, args: PatchArgs) -> Result<u8, AppError> {
    let repo = std::env::current_dir()?;
    let impact =
        analyze_git_range(&repo, &args.base, &args.head, &[]).map_err(AppError::Invalid)?;
    let files = impact
        .changed_files
        .iter()
        .map(|f| {
            serde_json::json!({
                "path": f.path,
                "additions": f.additions,
                "deletions": f.deletions,
                "test_only": f.test_only,
                "generated": f.generated,
                "language": f.language,
                "sensitive_surfaces": f.sensitive_surfaces.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                "symbols": f.symbols.iter().map(|s| serde_json::json!({
                    "name": s.name,
                    "kind": s.kind,
                    "evidence_kind": s.evidence_kind,
                    "confidence_millis": s.confidence_millis
                })).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let tests = impact
        .tests
        .iter()
        .map(|t| {
            let priority = match t.priority {
                TestPriority::MustRun => "MUST_RUN",
                TestPriority::Recommended => "RECOMMENDED",
                TestPriority::LowRelevance => "LOW_RELEVANCE",
            };
            serde_json::json!({"selector": t.selector, "priority": priority, "reason": t.reason})
        })
        .collect::<Vec<_>>();
    let data = serde_json::json!({
        "schema_version": impact.schema_version,
        "base": impact.base,
        "head": impact.head,
        "changed_files": files,
        "affected_modules": impact.affected_modules,
        "sensitive_surfaces": impact.sensitive_surfaces.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "blast_radius": {
            "direct_dependents": impact.blast_radius.direct_dependents,
            "transitive_reachability": impact.blast_radius.transitive_reachability,
            "public_api": impact.blast_radius.public_api,
            "state_or_schema": impact.blast_radius.state_or_schema,
            "concurrency": impact.blast_radius.concurrency,
            "privilege": impact.blast_radius.privilege,
            "persistence": impact.blast_radius.persistence,
            "score": impact.blast_radius.score
        },
        "tests": tests,
        "evidence_gaps": impact.evidence_gaps.iter().map(|g| serde_json::json!({
            "code": g.code,
            "surface": g.surface.as_str(),
            "explanation": g.explanation
        })).collect::<Vec<_>>(),
        "diagnostics": impact.diagnostics
    });
    if json {
        let envelope = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "generated_at": "deterministic-local",
            "tool_version": TOOL_VERSION,
            "scope": repo.display().to_string(),
            "data": data,
            "diagnostics": [],
            "evidence_refs": []
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    } else {
        println!("Patch {}..{}", args.base, args.head);
        println!("Changed files: {}", impact.changed_files.len());
        println!("Blast radius score: {}", impact.blast_radius.score);
        if !impact.sensitive_surfaces.is_empty() {
            println!(
                "Sensitive: {}",
                impact
                    .sensitive_surfaces
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        for test in &impact.tests {
            let priority = match test.priority {
                TestPriority::MustRun => "MUST_RUN",
                TestPriority::Recommended => "RECOMMENDED",
                TestPriority::LowRelevance => "LOW_RELEVANCE",
            };
            println!("{priority} | {} | {}", test.selector, test.reason);
        }
        for gap in &impact.evidence_gaps {
            println!(
                "GAP | {} | {} | {}",
                gap.code,
                gap.surface.as_str(),
                gap.explanation
            );
        }
    }
    Ok(if impact.evidence_gaps.is_empty() {
        0
    } else {
        2
    })
}

fn provenance(json: bool, cmd: ProvenanceCommand) -> Result<u8, AppError> {
    let ProvenanceCommand::Explain { artifact } = cmd;
    let repo = std::env::current_dir()?;
    let graph = inspect_repository(&repo).map_err(|e| AppError::Invalid(e.to_string()))?;
    let selected = graph
        .artifacts
        .values()
        .find(|a| a.artifact_id == artifact || a.name == artifact)
        .or_else(|| {
            graph
                .artifacts
                .values()
                .find(|a| a.artifact_id.contains(&artifact))
        })
        .ok_or_else(|| {
            AppError::Invalid(format!(
                "artifact not found in local provenance graph: {artifact}"
            ))
        })?;
    let incoming = graph.incoming(&selected.artifact_id);
    let outgoing = graph.outgoing(&selected.artifact_id);
    let paths = graph.why_is_this_here(&selected.artifact_id, 8);
    if json {
        let data = serde_json::json!({
            "artifact": selected,
            "incoming": incoming,
            "outgoing": outgoing,
            "explanation_paths": paths,
            "graph_schema_version": graph.schema_version,
            "source": "git-local"
        });
        let envelope = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "generated_at": "deterministic-local",
            "tool_version": TOOL_VERSION,
            "scope": repo.display().to_string(),
            "data": data,
            "diagnostics": [],
            "evidence_refs": []
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    } else {
        println!("Artifact: {}", selected.artifact_id);
        println!("Type: {:?}", selected.artifact_type);
        println!("Status: {:?}", selected.provenance_status);
        println!(
            "Revision: {}",
            selected.resolved_revision.as_deref().unwrap_or("unknown")
        );
        println!("Incoming edges: {}", incoming.len());
        println!("Outgoing edges: {}", outgoing.len());
        if paths.is_empty() {
            println!("No upstream explanation path in the local Git graph.");
        } else {
            for path in paths {
                println!("Path: {}", path.artifact_ids.join(" -> "));
            }
        }
    }
    Ok(0)
}

fn verify_bundle_shape(json: bool, path: &Path) -> Result<u8, AppError> {
    if !path.exists() {
        return Err(AppError::Invalid(format!(
            "bundle not found: {}",
            path.display()
        )));
    }
    match verify_proofdrift_bundle(path, &BundleLimits::default()) {
        Ok(result) => {
            if json {
                let envelope = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": "deterministic-local",
                    "tool_version": TOOL_VERSION,
                    "scope": path.display().to_string(),
                    "data": result,
                    "diagnostics": [],
                    "evidence_refs": []
                });
                println!("{}", serde_json::to_string_pretty(&envelope)?);
            } else {
                println!(
                    "VERIFIED: session={} files={} events={} final_hash={}",
                    result.session_id,
                    result.verified_files,
                    result.event_count,
                    result.final_event_hash
                );
            }
            Ok(if result.valid {
                EXIT_PASS
            } else {
                EXIT_VERIFY_FAILED
            })
        }
        Err(err) => {
            if json {
                let envelope = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": "deterministic-local",
                    "tool_version": TOOL_VERSION,
                    "scope": path.display().to_string(),
                    "data": {"verified": false, "integrity": "FAILED", "error": err.to_string()},
                    "diagnostics": [{"code": "EVIDENCE_VERIFICATION_FAILED", "message": err.to_string()}],
                    "evidence_refs": []
                });
                println!("{}", serde_json::to_string_pretty(&envelope)?);
            } else {
                eprintln!("verification failed: {err}");
            }
            Ok(EXIT_VERIFY_FAILED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("proofdrift-cli-{label}-{n}"))
    }

    #[test]
    fn inventory_and_digest_are_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("digest");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("b.txt"), b"b")?;
        fs::write(dir.join("a.txt"), b"a")?;
        let a = inventory(&dir)?;
        let b = inventory(&dir)?;
        assert_eq!(a, b);
        assert_eq!(inventory_digest(&a), inventory_digest(&b));
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn scan_never_executes_mcp_config() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("mcp");
        fs::create_dir_all(&dir)?;
        let marker = dir.join("must-not-exist");
        fs::write(
            dir.join("mcp.json"),
            format!("{{\"command\":\"touch {}\"}}", marker.display()),
        )?;
        let _result = scan_project(&dir)?;
        assert!(!marker.exists());
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn baseline_name_rejects_path_traversal() {
        assert!(validate_name("../../escape").is_err());
        assert!(validate_name("safe-main_1").is_ok());
    }

    #[test]
    fn internal_proofdrift_state_is_excluded_from_inventory() {
        assert!(should_skip(Path::new(".proofdrift/baselines/trusted.json")));
        assert!(should_skip(Path::new("nested/.proofdrift/events.db")));
        assert!(!should_skip(Path::new("src/config.json")));
    }

    #[test]
    fn template_mcp_is_not_flagged_active() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("template-mcp");
        let examples = dir.join("examples");
        fs::create_dir_all(&examples)?;
        fs::write(
            examples.join("mcp.example.json"),
            br#"{"mcpServers":{"example":{"command":"echo","args":["safe"]}}}"#,
        )?;
        let result = scan_project(&dir)?;
        assert!(result.findings.is_empty());
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn cli_verify_accepts_valid_bundle_and_rejects_tamper() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = temp_dir("verify");
        fs::create_dir_all(&dir)?;
        let bundle = dir.join("session.proofdrift");
        let input = proofdrift_evidence::BundleInput {
            session_id: "cli-verify".into(),
            events: Vec::new(),
            assets: BTreeMap::new(),
        };
        proofdrift_evidence::create_proofdrift_bundle(&bundle, &input, &BundleLimits::default())?;
        assert_eq!(verify_bundle_shape(false, &bundle)?, 0);
        let mut bytes = fs::read(&bundle)?;
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        fs::write(&bundle, bytes)?;
        assert_eq!(verify_bundle_shape(false, &bundle)?, 4);
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
