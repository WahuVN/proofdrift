use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = std::env::temp_dir().join(format!(
        "proofdrift-cli-e2e-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run(args: &[&str], cwd: &PathBuf) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_proofdrift"))
        .args(args)
        .current_dir(cwd)
        .output()?)
}

fn stdout_json(output: &Output) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn json_cli_parse_error_is_machine_readable_and_uses_config_exit_class(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir("parse-error")?;
    let output = run(&["--json", "scan", "--definitely-invalid"], &dir)?;
    assert_eq!(output.status.code(), Some(64));
    let body = stdout_json(&output)?;
    assert_eq!(body["status"], "error");
    assert_eq!(body["exit_code"], 64);
    assert_eq!(body["error"]["kind"], "config_error");
    assert_eq!(body["error"]["code"], "PD_CLI_CONFIG");
    assert!(output.stderr.is_empty());
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn missing_explicit_config_fails_early_with_actionable_json(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir("missing-config")?;
    let missing = dir.join("missing.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_proofdrift"))
        .arg("--json")
        .arg("--config")
        .arg(&missing)
        .args(["config", "validate"])
        .current_dir(&dir)
        .output()?;
    assert_eq!(output.status.code(), Some(64));
    let body = stdout_json(&output)?;
    assert_eq!(body["error"]["code"], "PD_CLI_CONFIG");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("failed to read config"));
    assert!(message.contains("missing.toml"));
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn config_file_accepts_crlf_and_environment_overrides_file_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir("precedence")?;
    let config = dir.join("proofdrift.toml");
    fs::write(
        &config,
        "[output]\r\nformat = \"json\"\r\n\r\n[run]\r\npolicy = \"safe-local-dev\"\r\ntimeout_ms = 111\r\nmax_output_bytes = 2222\r\n",
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_proofdrift"))
        .arg("--config")
        .arg(&config)
        .args(["config", "show"])
        .env("PROOFDRIFT_TIMEOUT_MS", "333")
        .env("PROOFDRIFT_MAX_OUTPUT_BYTES", "4444")
        .current_dir(&dir)
        .output()?;
    assert!(output.status.success());
    let body = stdout_json(&output)?;
    assert_eq!(body["data"]["output"], "json");
    assert_eq!(body["data"]["run"]["timeout_ms"], 333);
    assert_eq!(body["data"]["run"]["max_output_bytes"], 4444);
    assert_eq!(body["data"]["run"]["policy"], "safe-local-dev");
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn unknown_config_keys_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir("unknown-key")?;
    let config = dir.join("proofdrift.toml");
    fs::write(&config, "[run]\ntimeout_ms = 1000\nunknown = true\n")?;
    let output = Command::new(env!("CARGO_BIN_EXE_proofdrift"))
        .arg("--json")
        .arg("--config")
        .arg(&config)
        .args(["config", "validate"])
        .current_dir(&dir)
        .output()?;
    assert_eq!(output.status.code(), Some(64));
    let body = stdout_json(&output)?;
    assert_eq!(body["error"]["kind"], "config_error");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("unknown field"));
    fs::remove_dir_all(dir)?;
    Ok(())
}
