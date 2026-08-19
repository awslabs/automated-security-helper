# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | Yes                |
| 2.x     | No (end of life)   |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of the following channels:

- Email: aws-security@amazon.com
- GitHub Security Advisories: use the "Report a vulnerability" button on the [Security tab](../../security/advisories/new)

### What to include

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof of concept
- The affected version(s)
- Any suggested fix, if you have one

### Response timeline

- **Acknowledgment**: within 48 hours of receipt
- **Fix timeline**: depends on severity. Critical issues are prioritized for the next patch release; lower-severity issues are scheduled into the regular release cycle.

## Scope

### In scope

- Vulnerabilities in ASH source code (Python, shell scripts)
- Dependency vulnerabilities that affect ASH at runtime
- CI/CD injection or supply-chain risks in the build pipeline
- Authentication or authorization flaws in MCP server endpoints

### Out of scope

- False positives produced by scanners that ASH orchestrates (e.g., Semgrep, Bandit, cfn-lint)
- Bugs in third-party tools that ASH invokes but does not maintain
- Reports that require physical access to the machine running ASH
- Social engineering attacks against maintainers

## Preferred Languages

We accept vulnerability reports in English.
