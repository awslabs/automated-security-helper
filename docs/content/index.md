# Home

[![ASH - Core Pipeline](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-build-and-scan.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-build-and-scan.yml)
[![ASH - Matrix Unit Tests](https://github.com/awslabs/automated-security-helper/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/unit-tests.yml)

## Overview

ASH (Automated Security Helper) is a security scanning tool designed to help you identify potential security issues in your code, infrastructure, and IAM configurations as early as possible in your development process.

- ASH is not a replacement for human review or team/customer security standards
- It leverages lightweight, open-source tools for flexibility and portability
- ASH v3 has been completely rewritten in Python with significant improvements to usability and functionality

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=awslabs/automated-security-helper&type=Date)](https://www.star-history.com/#awslabs/automated-security-helper&Date)

## Key Features in ASH v3

- **Python-based CLI**: ASH now has a Python-based CLI entrypoint while maintaining backward compatibility with the shell script entrypoint
- **Multiple Execution Modes**: Run ASH in `local`, `container`, or `precommit` mode depending on your needs
- **Enhanced Configuration**: Support for YAML/JSON configuration files with overrides via CLI parameters
- **Improved Reporting**: Multiple report formats including JSON, Markdown, HTML, and CSV
- **Scanner Validation System**: Comprehensive validation ensures all expected scanners are registered, enabled, queued, executed, and included in results
- **Pluggable Architecture**: Extend ASH with custom plugins, scanners, and reporters
- **Unified Output Format**: Standardized output format that can be exported to multiple formats (SARIF, JSON, HTML, Markdown, CSV)
- **UV Package Management**: ASH now uses UV for faster dependency resolution and tool isolation
- **Comprehensive Testing**: Extensive integration test suite validates UV migration functionality across platforms

## Built-In Scanners

ASH v3 integrates multiple open-source security tools as scanners. Tools like Bandit, Checkov, and Semgrep are managed via UV's tool isolation system, which automatically installs and runs them in isolated environments without affecting your project dependencies:

| Scanner                                                       | Type      | Languages/Frameworks                                                                         | Installation (Local Mode)                                               |
|---------------------------------------------------------------|-----------|----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| [Bandit](https://github.com/PyCQA/bandit)                     | SAST      | Python                                                                                       | Managed via UV tool isolation (auto-installed: `bandit>=1.7.0`)        |
| [Semgrep](https://github.com/semgrep/semgrep)                 | SAST      | Python, JavaScript, TypeScript, Java, Go, C#, Ruby, PHP, Kotlin, Swift, Bash, and more       | Managed via UV tool isolation (auto-installed: `semgrep>=1.125.0`)     |
| [detect-secrets](https://github.com/Yelp/detect-secrets)      | Secrets   | All text files                                                                               | Included with ASH                                                       |
| [Checkov](https://github.com/bridgecrewio/checkov)            | IaC, SAST | Terraform, CloudFormation, Kubernetes, Dockerfile, ARM Templates, Serverless, Helm, and more | Managed via UV tool isolation (auto-installed: `checkov>=3.2.0,<4.0.0`) |
| [cfn_nag](https://github.com/stelligent/cfn_nag)              | IaC       | CloudFormation                                                                               | `gem install cfn-nag`                                                   |
| [cdk-nag](https://github.com/cdklabs/cdk-nag)                 | IaC       | CloudFormation                                                                               | Included with ASH                                                       |
| [npm-audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) | SCA       | JavaScript/Node.js                                                                           | Install Node.js/npm                                                     |
| [Grype](https://github.com/anchore/grype)                     | SCA       | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         | See [Grype Installation](https://github.com/anchore/grype#installation) |
| [Syft](https://github.com/anchore/syft)                       | SBOM      | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         | See [Syft Installation](https://github.com/anchore/syft#installation)   |

### Sample Output

```
                                                 ASH Scan Results Summary
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Scanner        ┃ Suppressed ┃ Critical ┃ High ┃ Medium ┃ Low ┃ Info ┃ Duration ┃ Actionable ┃ Result ┃ Threshold       ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ bandit         │ 7          │ 0        │ 1    │ 0      │ 56  │ 0    │ 19.9s    │ 1          │ FAILED │ MEDIUM (global) │
│ cdk-nag        │ 0          │ 0        │ 30   │ 0      │ 0   │ 5    │ 48.7s    │ 30         │ FAILED │ MEDIUM (global) │
│ cfn-nag        │ 0          │ 0        │ 0    │ 15     │ 0   │ 0    │ 45.1s    │ 15         │ FAILED │ MEDIUM (global) │
│ checkov        │ 10         │ 0        │ 25   │ 0      │ 0   │ 0    │ 38.9s    │ 25         │ FAILED │ MEDIUM (global) │
│ detect-secrets │ 0          │ 0        │ 48   │ 0      │ 0   │ 0    │ 18.9s    │ 48         │ FAILED │ MEDIUM (global) │
│ grype          │ 0          │ 0        │ 2    │ 1      │ 0   │ 0    │ 40.3s    │ 3          │ FAILED │ MEDIUM (global) │
└────────────────┴────────────┴──────────┴──────┴────────┴─────┴──────┴──────────┴────────────┴────────┴─────────────────┘
                                                     source-dir: '.'
                                              output-dir: '.ash/ash_output'

=== ASH Scan Completed in 1m 6s: Next Steps ===
View detailed findings...
  - SARIF: '.ash/ash_output/reports/ash.sarif'
  - JUnit: '.ash/ash_output/reports/ash.junit.xml'
  - ASH aggregated results JSON available at: '.ash/ash_output/ash_aggregated_results.json'

=== Actionable findings detected! ===
To investigate...
  1. Open one of the summary reports for a user-friendly table of the findings:
    - HTML report of all findings: '.ash/ash_output/reports/ash.html'
    - Markdown summary: '.ash/ash_output/reports/ash.summary.md'
    - Text summary: '.ash/ash_output/reports/ash.summary.txt'
  2. Use ash report to view a short text summary of the scan in your terminal
  3. Use ash inspect findings to explore the findings interactively
  4. Review scanner-specific reports and outputs in the '.ash/ash_output/scanners' directory

=== ASH Exit Codes ===
  0: Success - No actionable findings or not configured to fail on findings
  1: Error during execution
  2: Actionable findings detected when configured with `fail_on_findings: true`. Default is True. Current value: True
ERROR (2) Exiting due to 122 actionable findings found in ASH scan
```

## Output Files

ASH v3 produces several output files in the `.ash/ash_output/` directory:

- `ash_aggregated_results.json`: Complete machine-readable results
- `reports/ash.summary.txt`: Human-readable text summary
- `reports/ash.summary.md`: Markdown summary for GitHub PRs and other platforms
- `reports/ash.html`: Interactive HTML report
- `reports/ash.csv`: CSV report for filtering and sorting findings

## Feedback and Contributing

- Create an issue [in the GitHub repository](https://github.com/awslabs/automated-security-helper/issues)
- See [CONTRIBUTING](contributing.md) for contribution guidelines

## Security

See [CONTRIBUTING](contributing.md#security-issue-notifications) for security issue reporting information.

## License

This library is licensed under the Apache 2.0 License. See the [LICENSE](https://github.com/awslabs/automated-security-helper/blob/main/LICENSE) file.
