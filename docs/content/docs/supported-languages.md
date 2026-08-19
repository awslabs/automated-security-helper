# Supported Languages & Frameworks

ASH is a **meta-scanner** — it orchestrates established open-source security tools rather than implementing its own analysis engine. This means you get the combined coverage of multiple specialized tools through a single interface, with unified SARIF output and consistent suppression handling.

## Scanner Matrix

| Scanner | Languages / Frameworks | What It Checks |
|---------|----------------------|----------------|
| **Bandit** | Python | Security anti-patterns: hardcoded passwords, subprocess injection, insecure deserialization, weak cryptography |
| **cdk-nag** | AWS CDK (TypeScript, Python) | AWS best practices for CDK constructs: overly permissive IAM, unencrypted storage, missing logging |
| **cfn-nag** | CloudFormation (YAML/JSON) | CloudFormation security misconfigurations: open security groups, missing encryption, wildcard IAM policies |
| **Checkov** | Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, ARM, Bicep, and 30+ more | IaC misconfigurations across cloud providers: insecure defaults, missing encryption, public exposure |
| **detect-secrets** | All (language-agnostic) | Hardcoded secrets, API keys, tokens, and credentials in any file type |
| **Grype** | Container images, SBOMs | Known vulnerabilities (CVEs) in OS packages and application libraries |
| **npm-audit** | JavaScript/TypeScript (npm, pnpm, yarn) | Known vulnerabilities in npm dependency trees |
| **OpenGrep** | Python, JavaScript, TypeScript, Java, Go, Ruby, C#, Kotlin, Scala, PHP, and more | SAST rules from the Semgrep/OpenGrep registry: injection flaws, authentication bugs, insecure configurations |
| **Semgrep** | Same as OpenGrep | SAST rules (overlaps with OpenGrep; ASH uses both for broader rule coverage) |
| **Syft** | All (language-agnostic) | Software Bill of Materials (SBOM) generation — inventories all packages and dependencies |

## Coverage Notes

- **IaC coverage** is strongest through Checkov, which supports Terraform (HCL), CloudFormation, Kubernetes, Docker, Helm, Serverless Framework, ARM templates, Bicep, Ansible, and more.
- **Secret detection** via detect-secrets is file-format agnostic — it scans any text file regardless of language.
- **Container scanning** via Grype works on built images or on SBOMs produced by Syft, covering OS-level and application-level packages.
- **SAST coverage** via OpenGrep/Semgrep draws from thousands of community rules. The exact language support depends on rule availability in the registry.

## Adding More Scanners

ASH's plugin system lets you add additional scanners. Community plugins exist for tools like Trivy, Snyk, and Ferret. See the [Plugin Development Guide](plugins/development-guide.md) for instructions on writing your own scanner plugin.
