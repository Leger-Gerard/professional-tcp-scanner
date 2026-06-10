# Threat Model

## Scope

This model covers the scanner CLI, local report generation, TCP network interactions, Docker image, and CI pipeline.

## Assets

- Operator workstation and filesystem
- Target scan authorization boundaries
- Generated reports, banners, and certificate metadata
- GitHub repository and release artifacts

## Trust Boundaries

- User-provided CLI input enters validation code.
- Network responses enter banner and TLS parsing.
- Report output may be opened in browsers or ingested by automation.
- CI executes dependency installation and security tooling.

## Primary Threats

| Threat | Mitigation |
| --- | --- |
| Unbounded scan causing local resource exhaustion | Thread, timeout, and policy limits |
| Invalid host or port input | Host, port, timeout, and thread validation |
| Malicious banner content in HTML reports | HTML escaping in report serializer |
| JSON output polluted by logs | Machine output suppresses console logging unless verbose |
| Container privilege abuse | Runtime runs as non-root user with nologin shell |
| Dependency or supply-chain issue | pip-audit, Dependency Review, CodeQL, SBOM, Trivy |

## Residual Risk

- Banner grabbing is protocol-light and should not be treated as full service fingerprinting.
- TLS inspection depends on Python/OpenSSL trust configuration.
- The scanner cannot verify authorization to scan a target; this remains an operator responsibility.
