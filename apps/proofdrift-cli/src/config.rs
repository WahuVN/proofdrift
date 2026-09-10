use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const DEFAULT_POLICY: &str = "safe-local-dev";
const DEFAULT_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 86_400_000;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid config {path}: {message}")]
    Parse { path: String, message: String },
    #[error("invalid setting {name}: {message}")]
    InvalidSetting { name: &'static str, message: String },
    #[error("invalid configuration: {0}")]
    Validation(String),
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    output: Option<OutputConfig>,
    run: Option<RunConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputConfig {
    format: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunConfig {
    policy: Option<String>,
    timeout_ms: Option<u64>,
    max_output_bytes: Option<usize>,
}

#[derive(Clone, Debug)]
pub(crate) struct LoadedConfig {
    source: Option<PathBuf>,
    values: FileConfig,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EffectiveRunConfig {
    pub policy: String,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EffectiveConfigView {
    pub source: Option<String>,
    pub output: &'static str,
    pub run: EffectiveRunConfig,
}

impl LoadedConfig {
    pub(crate) fn load(explicit: Option<&Path>) -> Result<Self, ConfigError> {
        let selected = select_config_path(explicit)?;
        let Some(path) = selected else {
            return Ok(Self {
                source: None,
                values: FileConfig::default(),
            });
        };

        let text = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let values: FileConfig = toml::from_str(&text).map_err(|error| ConfigError::Parse {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        validate_file_config(&values)?;
        Ok(Self {
            source: Some(path),
            values,
        })
    }

    pub(crate) fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    pub(crate) fn resolve_json(&self, cli_output: Option<bool>) -> Result<bool, ConfigError> {
        if let Some(value) = cli_output {
            return Ok(value);
        }
        if let Some(value) = env::var_os("PROOFDRIFT_OUTPUT") {
            let value = value.to_string_lossy();
            return parse_output("PROOFDRIFT_OUTPUT", &value);
        }
        match self
            .values
            .output
            .as_ref()
            .and_then(|output| output.format.as_deref())
        {
            Some(value) => parse_output("config output.format", value),
            None => Ok(false),
        }
    }

    pub(crate) fn resolve_run(
        &self,
        cli_policy: Option<String>,
        cli_timeout_ms: Option<u64>,
        cli_max_output_bytes: Option<usize>,
    ) -> Result<EffectiveRunConfig, ConfigError> {
        let policy = match cli_policy {
            Some(value) => value,
            None => match env::var_os("PROOFDRIFT_POLICY") {
                Some(value) => value.to_string_lossy().into_owned(),
                None => self
                    .values
                    .run
                    .as_ref()
                    .and_then(|run| run.policy.clone())
                    .unwrap_or_else(|| DEFAULT_POLICY.to_owned()),
            },
        };

        let timeout_ms = match cli_timeout_ms {
            Some(value) => value,
            None => match env::var_os("PROOFDRIFT_TIMEOUT_MS") {
                Some(value) => parse_u64_env("PROOFDRIFT_TIMEOUT_MS", &value.to_string_lossy())?,
                None => self
                    .values
                    .run
                    .as_ref()
                    .and_then(|run| run.timeout_ms)
                    .unwrap_or(DEFAULT_TIMEOUT_MS),
            },
        };

        let max_output_bytes = match cli_max_output_bytes {
            Some(value) => value,
            None => match env::var_os("PROOFDRIFT_MAX_OUTPUT_BYTES") {
                Some(value) => {
                    parse_usize_env("PROOFDRIFT_MAX_OUTPUT_BYTES", &value.to_string_lossy())?
                }
                None => self
                    .values
                    .run
                    .as_ref()
                    .and_then(|run| run.max_output_bytes)
                    .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES),
            },
        };

        validate_run_values(&policy, timeout_ms, max_output_bytes)?;
        Ok(EffectiveRunConfig {
            policy,
            timeout_ms,
            max_output_bytes,
        })
    }

    pub(crate) fn effective_view(&self, json: bool) -> Result<EffectiveConfigView, ConfigError> {
        Ok(EffectiveConfigView {
            source: self.source().map(|path| path.display().to_string()),
            output: if json { "json" } else { "human" },
            run: self.resolve_run(None, None, None)?,
        })
    }
}

fn select_config_path(explicit: Option<&Path>) -> Result<Option<PathBuf>, ConfigError> {
    if let Some(path) = explicit {
        return Ok(Some(path.to_path_buf()));
    }
    if let Some(path) = env::var_os("PROOFDRIFT_CONFIG") {
        if path.is_empty() {
            return Err(ConfigError::InvalidSetting {
                name: "PROOFDRIFT_CONFIG",
                message: "path cannot be empty".into(),
            });
        }
        return Ok(Some(PathBuf::from(path)));
    }
    let default = env::current_dir()
        .map_err(|source| ConfigError::Read {
            path: ".".into(),
            source,
        })?
        .join(".proofdrift")
        .join("config.toml");
    Ok(default.exists().then_some(default))
}

fn validate_file_config(config: &FileConfig) -> Result<(), ConfigError> {
    if let Some(output) = &config.output {
        if let Some(format) = &output.format {
            parse_output("config output.format", format)?;
        }
    }
    if let Some(run) = &config.run {
        let policy = run.policy.as_deref().unwrap_or(DEFAULT_POLICY);
        validate_run_values(
            policy,
            run.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
            run.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT_BYTES),
        )?;
    }
    Ok(())
}

fn validate_run_values(
    policy: &str,
    timeout_ms: u64,
    max_output_bytes: usize,
) -> Result<(), ConfigError> {
    if policy.trim().is_empty() {
        return Err(ConfigError::Validation(
            "run.policy must not be empty".into(),
        ));
    }
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(ConfigError::Validation(format!(
            "run.timeout_ms must be between 1 and {MAX_TIMEOUT_MS}"
        )));
    }
    if max_output_bytes == 0 || max_output_bytes > MAX_OUTPUT_BYTES {
        return Err(ConfigError::Validation(format!(
            "run.max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}"
        )));
    }
    Ok(())
}

fn parse_output(name: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "json" => Ok(true),
        "human" => Ok(false),
        _ => Err(ConfigError::InvalidSetting {
            name,
            message: "expected 'human' or 'json'".into(),
        }),
    }
}

fn parse_u64_env(name: &'static str, value: &str) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidSetting {
            name,
            message: "expected a positive integer".into(),
        })
}

fn parse_usize_env(name: &'static str, value: &str) -> Result<usize, ConfigError> {
    value
        .parse::<usize>()
        .map_err(|_| ConfigError::InvalidSetting {
            name,
            message: "expected a positive integer".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields_and_invalid_limits() -> Result<(), Box<dyn std::error::Error>> {
        let unknown = toml::from_str::<FileConfig>("unknown = true");
        assert!(unknown.is_err());

        let invalid: FileConfig = toml::from_str("[run]\ntimeout_ms = 0\n")?;
        assert!(validate_file_config(&invalid).is_err());
        Ok(())
    }

    #[test]
    fn validates_output_modes() {
        assert_eq!(
            parse_output("config output.format", "json").ok(),
            Some(true)
        );
        assert_eq!(
            parse_output("config output.format", "human").ok(),
            Some(false)
        );
        assert!(parse_output("config output.format", "xml").is_err());
    }
}
