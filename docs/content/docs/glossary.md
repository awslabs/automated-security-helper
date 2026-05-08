# Glossary

| Term | Definition |
|------|------------|
| **Actionable finding** | A finding that is not suppressed and has severity above the configured threshold. These appear in reports and affect exit codes. |
| **ASH** | Automated Security Helper — a meta-scanner that orchestrates multiple security tools and unifies their output. |
| **Converter** | A plugin that transforms input files into formats that scanners can process (e.g., extracting archives, rendering templates). |
| **CycloneDX** | An OWASP standard for Software Bill of Materials (SBOM) and vulnerability exchange. ASH can produce CycloneDX output via its reporter. |
| **Event Subscriber** | A plugin that reacts to lifecycle events during an ASH run (e.g., scan started, finding detected, run completed). Used for custom integrations. |
| **Finding** | A single security issue detected by a scanner, represented as a SARIF result with a rule ID, severity, location, and message. |
| **GHAS** | GitHub Advanced Security — GitHub's native security scanning platform. ASH can produce SARIF compatible with GHAS code scanning. |
| **IaC** | Infrastructure as Code — configuration files that define cloud resources (Terraform, CloudFormation, Kubernetes manifests, etc.). |
| **Inline Suppression** | A code comment (e.g., `# ash-ignore:rule-id`) that suppresses a specific finding at the line where it appears. |
| **MCP** | Model Context Protocol — a standard for connecting AI assistants to external tools. ASH exposes an MCP server for AI-driven security scanning. |
| **Mode** | How ASH executes: `local` (direct on host), `container` (inside Docker), or `precommit` (as a Git hook on staged files). |
| **OCSF** | Open Cybersecurity Schema Framework — a standard schema for security telemetry. ASH can emit findings in OCSF format. |
| **Phase** | A stage in the ASH pipeline: convert, scan, report, or inspect. Phases run sequentially in that order. |
| **Plugin** | A self-contained extension that adds scanning, reporting, converting, or event-handling capability to ASH. |
| **Pre-commit hook** | A Git hook that runs ASH automatically before each commit, scanning only staged files for fast feedback. |
| **Reporter** | A plugin that transforms aggregated SARIF findings into a specific output format (HTML, CSV, SARIF file, Security Hub, etc.). |
| **Rule ID** | A unique identifier for a class of finding (e.g., `B105` for Bandit's hardcoded password check, `CKV_AWS_18` for a Checkov rule). |
| **SARIF** | Static Analysis Results Interchange Format — an OASIS standard JSON format for static analysis output. ASH uses SARIF as its internal data model. |
| **SAST** | Static Application Security Testing — analysis of source code for vulnerabilities without executing it. |
| **SBOM** | Software Bill of Materials — a machine-readable inventory of all components in a software project. |
| **SCA** | Software Composition Analysis — identifying known vulnerabilities in third-party dependencies. |
| **Scanner** | A plugin that wraps a security tool, runs it against target code, and produces SARIF findings. |
| **Severity** | The impact level of a finding: Critical, High, Medium, Low, or Info (also called Note). Determines whether a finding is actionable. |
| **SPDX** | Software Package Data Exchange — an ISO standard for communicating SBOM information. |
| **Strategy** | How ASH runs multiple scanners: `parallel` (concurrent execution, default) or `sequential` (one at a time). |
| **Suppression** | A config-based rule in `.ash-config.yml` that marks specific findings as accepted, hiding them from actionable results. |
| **UV** | A fast Python package installer and resolver used by ASH to manage scanner tool installations. |
| **UVX** | A UV subcommand that runs Python CLI tools in isolated environments without permanent installation. ASH uses `uvx` to invoke scanners. |
