# ASH security scan analysis

> [!CAUTION]
> **Scan incomplete**
>
> 6 actionable findings. Some inputs or scanners were not evaluated.
>
> **6 actionable** · 4 below threshold · 1 suppressed · 6/9 scanners completed
>
> Next action: Review findings, resolve coverage gaps, and scan again.

Project: ASH

### Incomplete coverage

Targets left unevaluated:

- **cfn-nag**: evaluated 0 of 1 target(s); 1 could not be evaluated

**Scanners needing attention:** cfn-nag, npm-audit. Check their dependencies and execution logs.

## Generated analysis

Generated with Amazon Bedrock. Verify suggestions against the source findings.

## Contents

1. [Executive summary](#executive-summary)
2. [Findings by severity](#findings-by-severity)
   - [Critical findings](#critical-findings)
   - [High findings](#high-findings)
   - [Medium findings](#medium-findings)
3. [Recommendations](#recommendations)
4. [Risk assessment](#risk-assessment)
5. [Finding details](#finding-details)

## Executive summary

[stubbed model response 1]

## Findings by severity

### Critical findings

[stubbed model response 2]

### High findings

[stubbed model response 3]

### Medium findings

[stubbed model response 4]

## Recommendations

[stubbed model response 5]

## Risk assessment

[stubbed model response 6]

## Finding details

### Finding index

| Index | Rule ID | Severity | File | Line range | Description |
|-------|---------|----------|------|------------|-------------|
| 1 | B602 | HIGH | app/app.py | 9 | subprocess call with shell=True identified, sec... |
| 2 | B105 | LOW (below threshold) | app/app.py | 5 | Possible hardcoded password: 'hu\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*... |
| 3 | CKV\_AWS\_20 | HIGH | infra/main.tf | 6-9 | S3 Bucket has an ACL defined which allows publi... |
| 4 | CKV\_AWS\_18 | MEDIUM | infra/main.tf | 2-4 | Ensure the S3 bucket has access logging enabled |
| 5 | CKV\_DOCKER\_8 | MEDIUM | Dockerfile | 5 | Ensure the last USER is not root |
| 6 | CKV\_DOCKER\_2 | LOW (below threshold) | Dockerfile | 1-6 | Ensure that HEALTHCHECK instructions have been ... |
| 7 | dockerfile.security.last-user-is-root.last-user-is-root | LOW (below threshold) | Dockerfile | 5 | The last user in the container is 'root'. Switc... |
| 8 | python.lang.best-practice.unpinned-shell-command | INFO (below threshold) | app/app.py | 9 | Command string built with an f-string; prefer a... |
| 9 | SECRET-SECRET-KEYWORD | HIGH (suppressed) | app/app.py | 5 | Secret of type Secret Keyword detected in file ... |
| 10 | CVE-2018-18074-requests | CRITICAL | requirements.txt | 1 | A critical vulnerability in requests 2.19.1 (fi... |
| 11 | CVE-2023-32681-requests | MEDIUM | requirements.txt | 1 | A medium vulnerability in requests 2.19.1 (fixe... |


### Evidence

<details>
<summary>1. HIGH · B602</summary>

#### Finding 1: B602 (HIGH)

Location: app/app.py (lines 9-9)

subprocess call with shell=True identified, security issue.

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "B602",
  "level": "error",
  "message": {
    "text": "subprocess call with shell=True identified, security issue."
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "app/app.py"
        },
        "region": {
          "startLine": 9,
          "endLine": 9
        }
      }
    }
  ],
  "properties": {
    "tags": [
      "bandit"
    ],
    "issue_severity": "HIGH",
    "issue_confidence": "HIGH",
    "scanner_name": "bandit",
    "scanner_version": "1.8.6",
    "scanner_details": {
      "tool_name": "bandit",
      "tool_version": "1.8.6",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 1.25,
        "start_time": "2026-01-15T12:00:00+00:00",
        "end_time": "2026-01-15T12:00:01.250000+00:00"
      }
    }
  },
  "index": 1,
  "severity": "HIGH"
}
```
</details>

</details>

<details>
<summary>2. LOW · B105</summary>

#### Finding 2: B105 (LOW)

Location: app/app.py (lines 5-5)

Possible hardcoded password: 'hu\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*t'

</details>

<details>
<summary>3. HIGH · CKV_AWS_20</summary>

#### Finding 3: CKV\_AWS\_20 (HIGH)

Location: infra/main.tf (lines 6-9)

S3 Bucket has an ACL defined which allows public READ access.

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CKV_AWS_20",
  "level": "error",
  "message": {
    "text": "S3 Bucket has an ACL defined which allows public READ access."
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "infra/main.tf"
        },
        "region": {
          "startLine": 6,
          "endLine": 9
        }
      }
    }
  ],
  "properties": {
    "tags": [
      "checkov"
    ],
    "issue_severity": "HIGH",
    "scanner_name": "checkov",
    "scanner_version": "3.2.469",
    "scanner_details": {
      "tool_name": "checkov",
      "tool_version": "3.2.469",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 7.5,
        "start_time": "2026-01-15T12:00:01.250000+00:00",
        "end_time": "2026-01-15T12:00:08.750000+00:00"
      }
    }
  },
  "index": 3,
  "severity": "HIGH"
}
```
</details>

</details>

<details>
<summary>4. MEDIUM · CKV_AWS_18</summary>

#### Finding 4: CKV\_AWS\_18 (MEDIUM)

Location: infra/main.tf (lines 2-4)

Ensure the S3 bucket has access logging enabled

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CKV_AWS_18",
  "message": {
    "text": "Ensure the S3 bucket has access logging enabled"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "infra/main.tf"
        },
        "region": {
          "startLine": 2,
          "endLine": 4
        }
      }
    }
  ],
  "properties": {
    "tags": [
      "checkov"
    ],
    "issue_severity": "MEDIUM",
    "scanner_name": "checkov",
    "scanner_version": "3.2.469",
    "scanner_details": {
      "tool_name": "checkov",
      "tool_version": "3.2.469",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 7.5,
        "start_time": "2026-01-15T12:00:01.250000+00:00",
        "end_time": "2026-01-15T12:00:08.750000+00:00"
      }
    }
  },
  "level": "warning",
  "index": 4,
  "severity": "MEDIUM"
}
```
</details>

</details>

<details>
<summary>5. MEDIUM · CKV_DOCKER_8</summary>

#### Finding 5: CKV\_DOCKER\_8 (MEDIUM)

Location: Dockerfile (lines 5-5)

Ensure the last USER is not root

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CKV_DOCKER_8",
  "message": {
    "text": "Ensure the last USER is not root"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "Dockerfile"
        },
        "region": {
          "startLine": 5,
          "endLine": 5
        }
      }
    }
  ],
  "properties": {
    "tags": [
      "checkov"
    ],
    "issue_severity": "MEDIUM",
    "scanner_name": "checkov",
    "scanner_version": "3.2.469",
    "scanner_details": {
      "tool_name": "checkov",
      "tool_version": "3.2.469",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 7.5,
        "start_time": "2026-01-15T12:00:01.250000+00:00",
        "end_time": "2026-01-15T12:00:08.750000+00:00"
      }
    }
  },
  "level": "warning",
  "index": 5,
  "severity": "MEDIUM"
}
```
</details>

</details>

<details>
<summary>6. LOW · CKV_DOCKER_2</summary>

#### Finding 6: CKV\_DOCKER\_2 (LOW)

Location: Dockerfile (lines 1-6)

Ensure that HEALTHCHECK instructions have been added to container images

</details>

<details>
<summary>7. LOW · dockerfile.security.last-user-is-root.last-user-is-root</summary>

#### Finding 7: dockerfile.security.last-user-is-root.last-user-is-root (LOW)

Location: Dockerfile (lines 5-5)

The last user in the container is 'root'. Switch back to an unprivileged user.

</details>

<details>
<summary>8. INFO · python.lang.best-practice.unpinned-shell-command</summary>

#### Finding 8: python.lang.best-practice.unpinned-shell-command (INFO)

Location: app/app.py (lines 9-9)

Command string built with an f-string; prefer an argument list.

</details>

<details>
<summary>9. HIGH · SECRET-SECRET-KEYWORD</summary>

#### Finding 9: SECRET-SECRET-KEYWORD (HIGH)

Location: app/app.py (lines 5-5)

Secret of type Secret Keyword detected in file app/app.py at line 5

</details>

<details>
<summary>10. CRITICAL · CVE-2018-18074-requests</summary>

#### Finding 10: CVE-2018-18074-requests (CRITICAL)

Location: requirements.txt (lines 1-1)

A critical vulnerability in requests 2.19.1 (fixed in 2.20.0) was found at requirements.txt

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CVE-2018-18074-requests",
  "level": "error",
  "message": {
    "text": "A critical vulnerability in requests 2.19.1 (fixed in 2.20.0) was found at requirements.txt"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "requirements.txt"
        },
        "region": {
          "startLine": 1,
          "endLine": 1
        }
      }
    }
  ],
  "properties": {
    "tags": [
      "grype"
    ],
    "issue_severity": "CRITICAL",
    "scanner_name": "grype",
    "scanner_version": "0.100.0",
    "scanner_details": {
      "tool_name": "grype",
      "tool_version": "0.100.0",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 3.0,
        "start_time": "2026-01-15T12:00:13.250000+00:00",
        "end_time": "2026-01-15T12:00:16.250000+00:00"
      }
    }
  },
  "index": 10,
  "severity": "CRITICAL"
}
```
</details>

</details>

<details>
<summary>11. MEDIUM · CVE-2023-32681-requests</summary>

#### Finding 11: CVE-2023-32681-requests (MEDIUM)

Location: requirements.txt (lines 1-1)

A medium vulnerability in requests 2.19.1 (fixed in 2.31.0) was found at requirements.txt

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CVE-2023-32681-requests",
  "message": {
    "text": "A medium vulnerability in requests 2.19.1 (fixed in 2.31.0) was found at requirements.txt"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "requirements.txt"
        },
        "region": {
          "startLine": 1,
          "endLine": 1
        }
      }
    }
  ],
  "properties": {
    "tags": [
      "grype"
    ],
    "issue_severity": "MEDIUM",
    "scanner_name": "grype",
    "scanner_version": "0.100.0",
    "scanner_details": {
      "tool_name": "grype",
      "tool_version": "0.100.0",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 3.0,
        "start_time": "2026-01-15T12:00:13.250000+00:00",
        "end_time": "2026-01-15T12:00:16.250000+00:00"
      }
    }
  },
  "level": "warning",
  "index": 11,
  "severity": "MEDIUM"
}
```
</details>

</details>



Build with <3 at Amazon Web Services
