use crate::{
    CommandRunner, EnforcementLevel, ProcessError, ProcessInvocation, ProcessOutput,
    TokioCommandRunner,
};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DockerIsolationConfig {
    pub image: String,
    pub workspace: PathBuf,
    pub workspace_writable: bool,
    pub memory: String,
    pub cpus: String,
    pub pids_limit: u32,
    pub tmpfs_size: String,
}

impl DockerIsolationConfig {
    pub fn hardened(
        image: impl Into<String>,
        workspace: impl AsRef<Path>,
        workspace_writable: bool,
    ) -> Result<Self, ProcessError> {
        let image = image.into();
        validate_digest_pinned_image(&image)?;
        let workspace = workspace.as_ref().canonicalize().map_err(|error| {
            ProcessError::Runner(format!("canonicalize Docker workspace: {error}"))
        })?;
        let workspace_text = workspace.to_string_lossy();
        if workspace_text.contains(',') {
            return Err(ProcessError::Runner(
                "Docker --mount source paths containing commas are not supported by the hardened backend"
                    .into(),
            ));
        }
        Ok(Self {
            image,
            workspace,
            workspace_writable,
            memory: "512m".into(),
            cpus: "1.0".into(),
            pids_limit: 128,
            tmpfs_size: "64m".into(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DockerCommandRunner {
    config: DockerIsolationConfig,
}

impl DockerCommandRunner {
    pub fn new(config: DockerIsolationConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &DockerIsolationConfig {
        &self.config
    }

    fn docker_invocation(
        &self,
        invocation: &ProcessInvocation,
    ) -> Result<ProcessInvocation, ProcessError> {
        if invocation.program.trim().is_empty() {
            return Err(ProcessError::Runner(
                "isolated command program must not be empty".into(),
            ));
        }
        if !invocation.env.is_empty() {
            return Err(ProcessError::Runner(
                "Docker L2 backend does not pass arbitrary host environment values into the container"
                    .into(),
            ));
        }
        let container_cwd = self.container_cwd(invocation.cwd.as_deref())?;
        validate_limit_token("memory", &self.config.memory)?;
        validate_limit_token("cpus", &self.config.cpus)?;
        validate_limit_token("tmpfs_size", &self.config.tmpfs_size)?;
        if self.config.pids_limit == 0 {
            return Err(ProcessError::Runner(
                "Docker pids_limit must be greater than zero".into(),
            ));
        }

        let mut args = vec![
            "run".into(),
            "--rm".into(),
            "--pull=missing".into(),
            "--network=none".into(),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges:true".into(),
            format!("--pids-limit={}", self.config.pids_limit),
            format!("--memory={}", self.config.memory),
            format!("--cpus={}", self.config.cpus),
            "--user=65534:65534".into(),
            "--ulimit=nofile=1024:1024".into(),
            format!(
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={}",
                self.config.tmpfs_size
            ),
        ];
        let mount_mode = if self.config.workspace_writable {
            ""
        } else {
            ",readonly"
        };
        args.push(format!(
            "--mount=type=bind,src={},dst=/workspace{mount_mode}",
            self.config.workspace.to_string_lossy()
        ));
        args.push(format!("--workdir={container_cwd}"));
        args.push(self.config.image.clone());
        args.push(invocation.program.clone());
        args.extend(invocation.args.clone());

        let mut docker = ProcessInvocation::new("docker", args);
        docker.timeout_ms = invocation.timeout_ms;
        docker.max_output_bytes = invocation.max_output_bytes;
        Ok(docker)
    }

    fn container_cwd(&self, requested: Option<&Path>) -> Result<String, ProcessError> {
        let Some(requested) = requested else {
            return Ok("/workspace".into());
        };
        let requested = requested.canonicalize().map_err(|error| {
            ProcessError::Runner(format!("canonicalize requested cwd: {error}"))
        })?;
        let relative = requested
            .strip_prefix(&self.config.workspace)
            .map_err(|_| {
                ProcessError::Runner(
                    "Docker L2 command cwd must remain inside the mounted workspace".into(),
                )
            })?;
        if relative.as_os_str().is_empty() {
            return Ok("/workspace".into());
        }
        let relative = relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        Ok(format!("/workspace/{relative}"))
    }
}

#[async_trait]
impl CommandRunner for DockerCommandRunner {
    async fn run(&self, invocation: &ProcessInvocation) -> Result<ProcessOutput, ProcessError> {
        let docker = self.docker_invocation(invocation)?;
        TokioCommandRunner.run(&docker).await
    }

    fn enforcement_level(&self) -> EnforcementLevel {
        EnforcementLevel::L2Isolated
    }

    fn enforcement_scope(&self) -> &'static str {
        "docker-container: digest-pinned image, network none, read-only rootfs, non-root uid/gid, all Linux capabilities dropped, no-new-privileges, PID/memory/CPU limits; workspace bind is explicit"
    }

    fn adapter_id(&self) -> &'static str {
        "proofdrift-runtime-docker-isolation"
    }
}

fn validate_digest_pinned_image(image: &str) -> Result<(), ProcessError> {
    let Some((name, digest)) = image.rsplit_once("@sha256:") else {
        return Err(ProcessError::Runner(
            "Docker L2 image must be pinned by immutable @sha256:<64-hex> digest".into(),
        ));
    };
    if name.trim().is_empty()
        || name.chars().any(char::is_whitespace)
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProcessError::Runner(
            "Docker L2 image must use a valid immutable sha256 digest reference".into(),
        ));
    }
    Ok(())
}

fn validate_limit_token(name: &str, value: &str) -> Result<(), ProcessError> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(ProcessError::Runner(format!(
            "Docker {name} limit contains unsupported characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_image() -> String {
        format!("alpine@sha256:{}", "a".repeat(64))
    }

    #[test]
    fn image_must_be_digest_pinned() {
        assert!(validate_digest_pinned_image("alpine:latest").is_err());
        assert!(validate_digest_pinned_image(&digest_image()).is_ok());
        assert!(
            validate_digest_pinned_image(&format!("alpine@sha256:{}", "z".repeat(64))).is_err()
        );
    }

    #[test]
    fn hardened_runner_builds_expected_security_boundary() {
        let workspace = std::env::current_dir().unwrap();
        let runner = DockerCommandRunner::new(
            DockerIsolationConfig::hardened(digest_image(), &workspace, false).unwrap(),
        );
        let mut invocation = ProcessInvocation::new("sh", vec!["-c".into(), "id".into()]);
        invocation.cwd = Some(workspace);
        let docker = runner.docker_invocation(&invocation).unwrap();
        let joined = docker.args.join(" ");
        assert!(joined.contains("--network=none"));
        assert!(joined.contains("--read-only"));
        assert!(joined.contains("--cap-drop=ALL"));
        assert!(joined.contains("--security-opt=no-new-privileges:true"));
        assert!(joined.contains("--user=65534:65534"));
        assert!(joined.contains(",readonly"));
        assert_eq!(runner.enforcement_level(), EnforcementLevel::L2Isolated);
    }

    #[test]
    fn arbitrary_host_environment_is_not_forwarded() {
        let workspace = std::env::current_dir().unwrap();
        let runner = DockerCommandRunner::new(
            DockerIsolationConfig::hardened(digest_image(), &workspace, false).unwrap(),
        );
        let mut invocation = ProcessInvocation::new("printenv", vec![]);
        invocation.env.insert("SECRET".into(), "synthetic".into());
        assert!(runner.docker_invocation(&invocation).is_err());
    }
}
