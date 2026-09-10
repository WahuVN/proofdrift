# Support

## Release channels

- **Latest public preview:** receives bug fixes and security fixes while ProofDrift is pre-1.0.
- **Older previews:** best-effort only unless a security issue justifies a backport.
- **`main`:** development branch; use a tagged release when reproducibility matters.

## Platform matrix

| Surface | Linux x64 | Windows x64 | macOS ARM64 |
| --- | --- | --- | --- |
| Build/test CI | Supported | Supported | Supported |
| Release archive | Supported | Supported | Supported |
| `proofdrift run` L1 broker | Supported | Supported | Supported |
| L2 OS isolation | Not yet claimed | Not yet claimed | Not yet claimed |
| Production MCP transport | Not yet claimed | Not yet claimed | Not yet claimed |

“Supported” means the repository has an automated CI or release gate for that surface. It does not upgrade an L1 broker claim into OS isolation.

## Getting help
Use GitHub Issues for reproducible public bugs and feature requests. Use GitHub private vulnerability reporting for security-sensitive findings. Do not place real secrets, private repository content or personal data in public reports.
