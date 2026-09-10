use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

pub const SCHEMA_VERSION: &str = "0.1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitiveSurface {
    Auth,
    Crypto,
    Secret,
    Db,
    Migration,
    Concurrency,
    Network,
    PublicApi,
    Serialization,
    Config,
    Build,
    Deployment,
    TestWeakening,
}

impl SensitiveSurface {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Crypto => "crypto",
            Self::Secret => "secret",
            Self::Db => "db",
            Self::Migration => "migration",
            Self::Concurrency => "concurrency",
            Self::Network => "network",
            Self::PublicApi => "public_api",
            Self::Serialization => "serialization",
            Self::Config => "config",
            Self::Build => "build",
            Self::Deployment => "deployment",
            Self::TestWeakening => "test_weakening",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    pub path: String,
    pub additions: usize,
    pub deletions: usize,
    pub test_only: bool,
    pub generated: bool,
    pub language: Option<&'static str>,
    pub symbols: Vec<ChangedSymbol>,
    pub sensitive_surfaces: BTreeSet<SensitiveSurface>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedSymbol {
    pub name: String,
    pub kind: &'static str,
    pub evidence_kind: &'static str,
    pub confidence_millis: u16,
}

/// Language-neutral extension boundary. AST/compiler-backed analyzers can implement this
/// without changing the PatchImpact contract. Implementations must label their evidence.
pub trait LanguageAnalysisPlugin {
    fn analyze_symbols(
        &self,
        language: Option<&'static str>,
        changed_lines: &[String],
    ) -> Vec<ChangedSymbol>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HeuristicLanguagePlugin;

impl LanguageAnalysisPlugin for HeuristicLanguagePlugin {
    fn analyze_symbols(
        &self,
        language: Option<&'static str>,
        changed_lines: &[String],
    ) -> Vec<ChangedSymbol> {
        extract_symbols(language, changed_lines)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlastRadius {
    pub direct_dependents: u32,
    pub transitive_reachability: u32,
    pub public_api: u32,
    pub state_or_schema: u32,
    pub concurrency: u32,
    pub privilege: u32,
    pub persistence: u32,
    pub score: u32,
}

impl BlastRadius {
    fn recompute_score(&mut self) {
        self.score = self.direct_dependents
            + self.transitive_reachability
            + self.public_api
            + self.state_or_schema
            + self.concurrency
            + self.privilege
            + self.persistence;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestPriority {
    MustRun,
    Recommended,
    LowRelevance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestRecommendation {
    pub selector: String,
    pub priority: TestPriority,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedTestEvidence {
    pub command: String,
    pub exit_code: i32,
    pub observed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceGap {
    pub code: &'static str,
    pub surface: SensitiveSurface,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchImpact {
    pub schema_version: &'static str,
    pub base: String,
    pub head: String,
    pub changed_files: Vec<ChangedFile>,
    pub affected_modules: BTreeSet<String>,
    pub sensitive_surfaces: BTreeSet<SensitiveSurface>,
    pub blast_radius: BlastRadius,
    pub tests: Vec<TestRecommendation>,
    pub evidence_gaps: Vec<EvidenceGap>,
    pub diagnostics: Vec<String>,
}

pub fn analyze_git_range(
    repo: &Path,
    base: &str,
    head: &str,
    observed: &[ObservedTestEvidence],
) -> Result<PatchImpact, String> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(["diff", "--no-ext-diff", "--unified=3", base, head])
        .output()
        .map_err(|e| format!("failed to execute git diff: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let diff = String::from_utf8(output.stdout)
        .map_err(|_| "git diff output was not UTF-8".to_string())?;
    Ok(analyze_unified_diff(&diff, base, head, observed))
}

pub fn analyze_unified_diff(
    diff: &str,
    base: &str,
    head: &str,
    observed: &[ObservedTestEvidence],
) -> PatchImpact {
    let mut files = parse_diff(diff);
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let mut sensitive_surfaces = BTreeSet::new();
    let mut affected_modules = BTreeSet::new();
    for file in &files {
        sensitive_surfaces.extend(file.sensitive_surfaces.iter().cloned());
        if let Some(module) = top_level_module(&file.path) {
            affected_modules.insert(module);
        }
    }

    let mut blast = score_blast_radius(&files, &sensitive_surfaces);
    blast.recompute_score();
    let tests = recommend_tests(&files, &sensitive_surfaces);
    let evidence_gaps = find_evidence_gaps(&sensitive_surfaces, observed);

    let mut diagnostics = Vec::new();
    if files
        .iter()
        .any(|f| f.symbols.iter().any(|s| s.evidence_kind == "heuristic"))
    {
        diagnostics.push(
            "symbol extraction used deterministic heuristic fallback; AST evidence unavailable"
                .to_string(),
        );
    }
    if files.iter().any(|f| f.generated) {
        diagnostics.push("generated files are separated from primary impact scoring".to_string());
    }
    if files.iter().any(|f| f.test_only) {
        diagnostics
            .push("test-only changes are separated from production surface scoring".to_string());
    }

    PatchImpact {
        schema_version: SCHEMA_VERSION,
        base: base.to_string(),
        head: head.to_string(),
        changed_files: files,
        affected_modules,
        sensitive_surfaces,
        blast_radius: blast,
        tests,
        evidence_gaps,
        diagnostics,
    }
}

fn parse_diff(diff: &str) -> Vec<ChangedFile> {
    let mut files = Vec::new();
    let mut current: Option<ChangedFile> = None;
    let mut changed_lines: Vec<String> = Vec::new();

    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("diff --git a/") {
            if let Some(mut file) = current.take() {
                enrich_file(&mut file, &changed_lines);
                files.push(file);
                changed_lines.clear();
            }
            let path = rest.split(" b/").next().unwrap_or(rest).to_string();
            current = Some(new_changed_file(path));
            continue;
        }
        if let Some(file) = current.as_mut() {
            if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
                continue;
            }
            if let Some(payload) = line.strip_prefix('+') {
                file.additions += 1;
                changed_lines.push(payload.to_string());
            } else if let Some(payload) = line.strip_prefix('-') {
                file.deletions += 1;
                changed_lines.push(payload.to_string());
            }
        }
    }
    if let Some(mut file) = current.take() {
        enrich_file(&mut file, &changed_lines);
        files.push(file);
    }
    files
}

fn new_changed_file(path: String) -> ChangedFile {
    let lower = path.to_ascii_lowercase();
    ChangedFile {
        test_only: is_test_path(&lower),
        generated: is_generated_path(&lower),
        language: detect_language(&lower),
        path,
        additions: 0,
        deletions: 0,
        symbols: Vec::new(),
        sensitive_surfaces: BTreeSet::new(),
    }
}

fn detect_language(path: &str) -> Option<&'static str> {
    if path.ends_with(".rs") {
        Some("rust")
    } else if path.ends_with(".cs") {
        Some("csharp")
    } else if path.ends_with(".py") {
        Some("python")
    } else if path.ends_with(".ts")
        || path.ends_with(".tsx")
        || path.ends_with(".js")
        || path.ends_with(".jsx")
    {
        Some("typescript_js")
    } else {
        None
    }
}

fn is_test_path(path: &str) -> bool {
    path.contains("/test/")
        || path.contains("/tests/")
        || path.contains("\\tests\\")
        || path.ends_with("_test.rs")
        || path.ends_with("_test.py")
        || path.ends_with(".test.ts")
        || path.ends_with(".spec.ts")
        || path.contains("test")
            && (path.ends_with(".cs") || path.ends_with(".rs") || path.ends_with(".py"))
}

fn is_generated_path(path: &str) -> bool {
    path.contains("/generated/")
        || path.ends_with(".g.cs")
        || path.ends_with(".designer.cs")
        || path.ends_with(".min.js")
        || path.contains("/dist/")
        || path.contains("/target/")
}

fn enrich_file(file: &mut ChangedFile, lines: &[String]) {
    let lower_path = file.path.to_ascii_lowercase();
    let joined = lines.join("\n").to_ascii_lowercase();
    classify_sensitive(
        &lower_path,
        &joined,
        file.test_only,
        &mut file.sensitive_surfaces,
    );
    file.symbols = extract_symbols(file.language, lines);
}

fn classify_sensitive(
    path: &str,
    content: &str,
    test_only: bool,
    out: &mut BTreeSet<SensitiveSurface>,
) {
    let has = |needles: &[&str]| {
        needles
            .iter()
            .any(|n| path.contains(n) || content.contains(n))
    };
    if has(&[
        "auth",
        "authorize",
        "permission",
        "role",
        "jwt",
        "oauth",
        "login",
    ]) {
        out.insert(SensitiveSurface::Auth);
    }
    if has(&[
        "crypto",
        "cipher",
        "encrypt",
        "decrypt",
        "signature",
        "hash",
        "tls",
    ]) {
        out.insert(SensitiveSurface::Crypto);
    }
    if has(&[
        "secret",
        "token",
        "credential",
        "password",
        "api_key",
        "apikey",
    ]) {
        out.insert(SensitiveSurface::Secret);
    }
    if has(&[
        "database",
        "db/",
        "repository",
        "transaction",
        "sql",
        "entityframework",
        "diesel",
        "sqlx",
    ]) {
        out.insert(SensitiveSurface::Db);
    }
    if has(&[
        "migration",
        "migrations",
        "schema.sql",
        "alter table",
        "create table",
    ]) {
        out.insert(SensitiveSurface::Migration);
    }
    if has(&[
        "mutex",
        "rwlock",
        "semaphore",
        "atomic",
        "thread",
        "spawn",
        "async",
        "await",
        "concurrent",
        "race",
    ]) {
        out.insert(SensitiveSurface::Concurrency);
    }
    if has(&[
        "http", "https", "socket", "network", "client", "server", "request", "response",
    ]) {
        out.insert(SensitiveSurface::Network);
    }
    if has(&[
        "pub fn ",
        "pub struct ",
        "pub enum ",
        "public ",
        "export ",
        "module.exports",
        "__all__",
    ]) {
        out.insert(SensitiveSurface::PublicApi);
    }
    if has(&[
        "serde",
        "serialize",
        "deserialize",
        "json",
        "protobuf",
        "yaml",
        "toml",
    ]) {
        out.insert(SensitiveSurface::Serialization);
    }
    if has(&["config", ".toml", ".yaml", ".yml", ".json", ".env"]) {
        out.insert(SensitiveSurface::Config);
    }
    if has(&[
        "cargo.toml",
        ".csproj",
        "package.json",
        "pyproject.toml",
        "build.rs",
        "dockerfile",
    ]) {
        out.insert(SensitiveSurface::Build);
    }
    if has(&[
        "deploy",
        "docker",
        "kubernetes",
        "helm",
        "terraform",
        "github/workflows",
        "ci/",
    ]) {
        out.insert(SensitiveSurface::Deployment);
    }
    if test_only
        && has(&[
            "assert", "expect", "skip", "ignore", "disabled", "xfail", "todo!",
        ])
    {
        out.insert(SensitiveSurface::TestWeakening);
    }
}

fn extract_symbols(language: Option<&'static str>, lines: &[String]) -> Vec<ChangedSymbol> {
    let mut found = BTreeMap::<String, (&'static str, u16)>::new();
    for raw in lines {
        let line = raw.trim();
        let candidate = match language {
            Some("rust") => rust_symbol(line),
            Some("csharp") => csharp_symbol(line),
            Some("python") => python_symbol(line),
            Some("typescript_js") => js_symbol(line),
            _ => None,
        };
        if let Some((name, kind, confidence)) = candidate {
            if !name.is_empty() {
                found.entry(name).or_insert((kind, confidence));
            }
        }
    }
    found
        .into_iter()
        .map(|(name, (kind, confidence_millis))| ChangedSymbol {
            name,
            kind,
            evidence_kind: "heuristic",
            confidence_millis,
        })
        .collect()
}

fn word_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let idx = line.find(marker)? + marker.len();
    line[idx..]
        .trim_start()
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .next()
        .filter(|s| !s.is_empty())
}

fn rust_symbol(line: &str) -> Option<(String, &'static str, u16)> {
    for (m, k) in [
        ("fn ", "function"),
        ("struct ", "struct"),
        ("enum ", "enum"),
        ("trait ", "trait"),
        ("mod ", "module"),
        ("type ", "type"),
    ] {
        if let Some(name) = word_after(line, m) {
            return Some((name.to_string(), k, 780));
        }
    }
    None
}

fn python_symbol(line: &str) -> Option<(String, &'static str, u16)> {
    if let Some(name) = word_after(line, "def ") {
        return Some((name.to_string(), "function", 800));
    }
    if let Some(name) = word_after(line, "class ") {
        return Some((name.to_string(), "class", 800));
    }
    None
}

fn csharp_symbol(line: &str) -> Option<(String, &'static str, u16)> {
    for (m, k) in [
        (" class ", "class"),
        (" interface ", "interface"),
        (" enum ", "enum"),
        (" struct ", "struct"),
        (" record ", "record"),
    ] {
        if let Some(name) = word_after(&format!(" {line}"), m) {
            return Some((name.to_string(), k, 760));
        }
    }
    if line.contains('(')
        && (line.contains("public ")
            || line.contains("private ")
            || line.contains("protected ")
            || line.contains("internal "))
    {
        let before = line.split('(').next()?.trim();
        let name = before.split_whitespace().last()?;
        if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Some((name.to_string(), "method", 650));
        }
    }
    None
}

fn js_symbol(line: &str) -> Option<(String, &'static str, u16)> {
    if let Some(name) = word_after(line, "function ") {
        return Some((name.to_string(), "function", 780));
    }
    if let Some(name) = word_after(line, "class ") {
        return Some((name.to_string(), "class", 780));
    }
    if let Some(name) = word_after(line, "export const ") {
        return Some((name.to_string(), "export", 690));
    }
    if let Some(name) = word_after(line, "export function ") {
        return Some((name.to_string(), "function", 800));
    }
    None
}

fn top_level_module(path: &str) -> Option<String> {
    let mut parts = path.split('/').filter(|p| !p.is_empty());
    let first = parts.next()?;
    let second = parts.next();
    Some(match second {
        Some(s) if matches!(first, "crates" | "src" | "packages" | "apps" | "services") => {
            format!("{first}/{s}")
        }
        _ => first.to_string(),
    })
}

fn score_blast_radius(files: &[ChangedFile], surfaces: &BTreeSet<SensitiveSurface>) -> BlastRadius {
    let production: Vec<&ChangedFile> = files
        .iter()
        .filter(|f| !f.test_only && !f.generated)
        .collect();
    let modules = production
        .iter()
        .filter_map(|f| top_level_module(&f.path))
        .collect::<BTreeSet<_>>();
    let public_symbols = production
        .iter()
        .flat_map(|f| &f.symbols)
        .filter(|s| s.kind == "trait" || s.kind == "interface" || s.kind == "export")
        .count() as u32;
    BlastRadius {
        direct_dependents: (production.len() as u32).min(10),
        transitive_reachability: (modules.len() as u32).saturating_sub(1) * 2,
        public_api: if surfaces.contains(&SensitiveSurface::PublicApi) {
            5 + public_symbols.min(5)
        } else {
            0
        },
        state_or_schema: if surfaces.contains(&SensitiveSurface::Db)
            || surfaces.contains(&SensitiveSurface::Migration)
            || surfaces.contains(&SensitiveSurface::Serialization)
        {
            7
        } else {
            0
        },
        concurrency: if surfaces.contains(&SensitiveSurface::Concurrency) {
            7
        } else {
            0
        },
        privilege: if surfaces.contains(&SensitiveSurface::Auth)
            || surfaces.contains(&SensitiveSurface::Secret)
            || surfaces.contains(&SensitiveSurface::Crypto)
        {
            8
        } else {
            0
        },
        persistence: if surfaces.contains(&SensitiveSurface::Db)
            || surfaces.contains(&SensitiveSurface::Config)
            || surfaces.contains(&SensitiveSurface::Deployment)
        {
            6
        } else {
            0
        },
        score: 0,
    }
}

fn recommend_tests(
    files: &[ChangedFile],
    surfaces: &BTreeSet<SensitiveSurface>,
) -> Vec<TestRecommendation> {
    let mut out = Vec::new();
    if surfaces.contains(&SensitiveSurface::Auth) {
        push_test(
            &mut out,
            "auth",
            TestPriority::MustRun,
            "patch touches authentication/authorization surface",
        );
    }
    if surfaces.contains(&SensitiveSurface::Db) {
        push_test(
            &mut out,
            "db",
            TestPriority::MustRun,
            "patch touches persistence/transaction surface",
        );
    }
    if surfaces.contains(&SensitiveSurface::Migration) {
        push_test(
            &mut out,
            "migration",
            TestPriority::MustRun,
            "schema migration can affect stored state and rollback behavior",
        );
    }
    if surfaces.contains(&SensitiveSurface::Concurrency) {
        push_test(
            &mut out,
            "concurrency",
            TestPriority::MustRun,
            "patch contains synchronization/async/concurrency signals",
        );
    }
    if surfaces.contains(&SensitiveSurface::Network) {
        push_test(
            &mut out,
            "network",
            TestPriority::Recommended,
            "network boundary changed",
        );
    }
    if surfaces.contains(&SensitiveSurface::PublicApi) {
        push_test(
            &mut out,
            "api",
            TestPriority::Recommended,
            "public API compatibility may have changed",
        );
    }
    if surfaces.contains(&SensitiveSurface::Serialization) {
        push_test(
            &mut out,
            "serialization",
            TestPriority::Recommended,
            "wire/storage representation may have changed",
        );
    }
    if surfaces.contains(&SensitiveSurface::Config) {
        push_test(
            &mut out,
            "config",
            TestPriority::Recommended,
            "configuration semantics changed",
        );
    }
    if surfaces.contains(&SensitiveSurface::TestWeakening) {
        push_test(
            &mut out,
            "regression",
            TestPriority::MustRun,
            "tests themselves changed in a way that can weaken evidence",
        );
    }
    if out.is_empty() && files.iter().any(|f| !f.test_only) {
        push_test(
            &mut out,
            "affected-module",
            TestPriority::Recommended,
            "run tests closest to changed production modules",
        );
    }
    if files.iter().all(|f| f.test_only) && !files.is_empty() {
        push_test(&mut out, "changed-tests", TestPriority::LowRelevance, "patch is test-only; run the directly changed tests but do not infer production correctness");
    }
    out
}

fn push_test(
    out: &mut Vec<TestRecommendation>,
    selector: &str,
    priority: TestPriority,
    reason: &str,
) {
    if !out.iter().any(|x| x.selector == selector) {
        out.push(TestRecommendation {
            selector: selector.to_string(),
            priority,
            reason: reason.to_string(),
        });
    }
}

fn observed_matches(command: &str, selector: &str) -> bool {
    let c = command.to_ascii_lowercase();
    let s = selector.to_ascii_lowercase();
    c.contains(&s)
}

fn find_evidence_gaps(
    surfaces: &BTreeSet<SensitiveSurface>,
    observed: &[ObservedTestEvidence],
) -> Vec<EvidenceGap> {
    let required = [
        (SensitiveSurface::Auth, "auth"),
        (SensitiveSurface::Db, "db"),
        (SensitiveSurface::Migration, "migration"),
        (SensitiveSurface::Concurrency, "concurrency"),
        (SensitiveSurface::TestWeakening, "regression"),
    ];
    let passing: Vec<&ObservedTestEvidence> = observed
        .iter()
        .filter(|e| e.observed && e.exit_code == 0)
        .collect();
    let mut gaps = Vec::new();
    for (surface, selector) in required {
        if surfaces.contains(&surface)
            && !passing
                .iter()
                .any(|e| observed_matches(&e.command, selector))
        {
            gaps.push(EvidenceGap {
                code: "INSUFFICIENT_TEST_EVIDENCE",
                surface: surface.clone(),
                explanation: format!("patch touches {} but no observed passing test command was mapped to '{selector}'", surface.as_str()),
            });
        }
    }
    gaps
}

impl PatchImpact {
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("PATCH {} -> {}\n", self.base, self.head));
        out.push_str(&format!(
            "FILES {} | BLAST {}\n",
            self.changed_files.len(),
            self.blast_radius.score
        ));
        for file in &self.changed_files {
            let surfaces = file
                .sensitive_surfaces
                .iter()
                .map(SensitiveSurface::as_str)
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!(
                "{} +{} -{} [{}]\n",
                file.path, file.additions, file.deletions, surfaces
            ));
        }
        for test in &self.tests {
            out.push_str(&format!(
                "TEST {:?} {} — {}\n",
                test.priority, test.selector, test.reason
            ));
        }
        for gap in &self.evidence_gaps {
            out.push_str(&format!(
                "GAP {} {} — {}\n",
                gap.code,
                gap.surface.as_str(),
                gap.explanation
            ));
        }
        out
    }

    pub fn to_stable_json(&self) -> String {
        fn esc(s: &str) -> String {
            let mut out = String::with_capacity(s.len() + 8);
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out
        }
        let files = self.changed_files.iter().map(|f| {
            let surfaces = f.sensitive_surfaces.iter().map(|s| format!("\"{}\"", s.as_str())).collect::<Vec<_>>().join(",");
            let symbols = f.symbols.iter().map(|s| format!("{{\"name\":\"{}\",\"kind\":\"{}\",\"evidence_kind\":\"{}\",\"confidence_millis\":{}}}", esc(&s.name), s.kind, s.evidence_kind, s.confidence_millis)).collect::<Vec<_>>().join(",");
            format!("{{\"path\":\"{}\",\"additions\":{},\"deletions\":{},\"test_only\":{},\"generated\":{},\"language\":{},\"symbols\":[{}],\"sensitive_surfaces\":[{}]}}", esc(&f.path), f.additions, f.deletions, f.test_only, f.generated, f.language.map(|l| format!("\"{}\"", l)).unwrap_or_else(|| "null".to_string()), symbols, surfaces)
        }).collect::<Vec<_>>().join(",");
        let surfaces = self
            .sensitive_surfaces
            .iter()
            .map(|s| format!("\"{}\"", s.as_str()))
            .collect::<Vec<_>>()
            .join(",");
        let modules = self
            .affected_modules
            .iter()
            .map(|m| format!("\"{}\"", esc(m)))
            .collect::<Vec<_>>()
            .join(",");
        let gaps = self
            .evidence_gaps
            .iter()
            .map(|g| {
                format!(
                    "{{\"code\":\"{}\",\"surface\":\"{}\",\"explanation\":\"{}\"}}",
                    g.code,
                    g.surface.as_str(),
                    esc(&g.explanation)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"schema_version\":\"{}\",\"base\":\"{}\",\"head\":\"{}\",\"changed_files\":[{}],\"affected_modules\":[{}],\"sensitive_surfaces\":[{}],\"blast_radius\":{{\"direct_dependents\":{},\"transitive_reachability\":{},\"public_api\":{},\"state_or_schema\":{},\"concurrency\":{},\"privilege\":{},\"persistence\":{},\"score\":{}}},\"evidence_gaps\":[{}]}}", SCHEMA_VERSION, esc(&self.base), esc(&self.head), files, modules, surfaces, self.blast_radius.direct_dependents, self.blast_radius.transitive_reachability, self.blast_radius.public_api, self.blast_radius.state_or_schema, self.blast_radius.concurrency, self.blast_radius.privilege, self.blast_radius.persistence, self.blast_radius.score, gaps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RISKY_DIFF: &str = r#"diff --git a/src/auth/service.rs b/src/auth/service.rs
index 1111111..2222222 100644
--- a/src/auth/service.rs
+++ b/src/auth/service.rs
@@ -1,4 +1,7 @@
-pub fn authorize(user: &User) -> bool { old(user) }
+pub fn authorize(user: &User) -> bool { verify_token(user) }
+pub async fn refresh_session() { client.request().await; }
diff --git a/src/db/transaction.rs b/src/db/transaction.rs
index 3333333..4444444 100644
--- a/src/db/transaction.rs
+++ b/src/db/transaction.rs
@@ -1,2 +1,4 @@
+use std::sync::Mutex;
+pub fn commit_transaction() { /* sql transaction */ }
"#;

    #[test]
    fn detects_sensitive_surfaces_and_symbols() {
        let report = analyze_unified_diff(RISKY_DIFF, "main", "HEAD", &[]);
        assert!(report.sensitive_surfaces.contains(&SensitiveSurface::Auth));
        assert!(report.sensitive_surfaces.contains(&SensitiveSurface::Db));
        assert!(report
            .sensitive_surfaces
            .contains(&SensitiveSurface::Concurrency));
        assert!(report
            .sensitive_surfaces
            .contains(&SensitiveSurface::Network));
        assert!(report
            .changed_files
            .iter()
            .flat_map(|f| &f.symbols)
            .any(|s| s.name == "authorize"));
        assert!(report.blast_radius.score > 0);
    }

    #[test]
    fn reports_missing_db_and_concurrency_evidence_when_only_auth_ran() {
        let observed = [ObservedTestEvidence {
            command: "cargo test auth".into(),
            exit_code: 0,
            observed: true,
        }];
        let report = analyze_unified_diff(RISKY_DIFF, "main", "HEAD", &observed);
        assert!(!report
            .evidence_gaps
            .iter()
            .any(|g| g.surface == SensitiveSurface::Auth));
        assert!(report
            .evidence_gaps
            .iter()
            .any(|g| g.surface == SensitiveSurface::Db));
        assert!(report
            .evidence_gaps
            .iter()
            .any(|g| g.surface == SensitiveSurface::Concurrency));
    }

    #[test]
    fn failed_test_does_not_satisfy_evidence() {
        let observed = [ObservedTestEvidence {
            command: "cargo test db".into(),
            exit_code: 1,
            observed: true,
        }];
        let report = analyze_unified_diff(RISKY_DIFF, "main", "HEAD", &observed);
        assert!(report
            .evidence_gaps
            .iter()
            .any(|g| g.surface == SensitiveSurface::Db));
    }

    #[test]
    fn deterministic_file_order() {
        let diff = "diff --git a/z.rs b/z.rs\n--- a/z.rs\n+++ b/z.rs\n+pub fn z() {}\ndiff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n+pub fn a() {}\n";
        let a = analyze_unified_diff(diff, "a", "b", &[]);
        let b = analyze_unified_diff(diff, "a", "b", &[]);
        assert_eq!(a, b);
        assert_eq!(a.changed_files[0].path, "a.rs");
        assert_eq!(a.changed_files[1].path, "z.rs");
    }

    #[test]
    fn separates_test_only_changes() {
        let diff = "diff --git a/tests/auth_test.rs b/tests/auth_test.rs\n--- a/tests/auth_test.rs\n+++ b/tests/auth_test.rs\n-assert!(denied);\n+// ignore assertion\n";
        let report = analyze_unified_diff(diff, "a", "b", &[]);
        assert!(report.changed_files[0].test_only);
        assert!(report
            .sensitive_surfaces
            .contains(&SensitiveSurface::TestWeakening));
        assert_eq!(report.blast_radius.direct_dependents, 0);
    }

    #[test]
    fn does_not_use_loc_as_primary_risk_signal() {
        let mut diff = String::from("diff --git a/docs/notes.txt b/docs/notes.txt\n--- a/docs/notes.txt\n+++ b/docs/notes.txt\n");
        for i in 0..500 {
            diff.push_str(&format!("+documentation line {i}\n"));
        }
        let report = analyze_unified_diff(&diff, "a", "b", &[]);
        assert!(report.blast_radius.score <= 10);
    }

    #[test]
    fn detects_multiple_language_symbols() {
        let diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n+def check_access():\n+    pass\ndiff --git a/B.cs b/B.cs\n--- a/B.cs\n+++ b/B.cs\n+public class Guard {}\ndiff --git a/c.ts b/c.ts\n--- a/c.ts\n+++ b/c.ts\n+export function validate() {}\n";
        let report = analyze_unified_diff(diff, "a", "b", &[]);
        let names = report
            .changed_files
            .iter()
            .flat_map(|f| &f.symbols)
            .map(|s| s.name.as_str())
            .collect::<BTreeSet<_>>();
        assert!(names.contains("check_access"));
        assert!(names.contains("Guard"));
        assert!(names.contains("validate"));
    }
}
