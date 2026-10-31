# ASH security scan analysis

> [!CAUTION]
> **Scan incomplete**
>
> 2 actionable findings. Some inputs or scanners were not evaluated.
>
> **2 actionable** · 1 below threshold · 0 suppressed · 3/4 scanners completed
>
> Next action: Review findings, resolve coverage gaps, and scan again.

Project: workspace

**Scanners needing attention:** npm-audit. Check their dependencies and execution logs.

## Generated analysis

Generated with Amazon Bedrock. Verify suggestions against the source findings.

## Contents

1. [Executive summary](#executive-summary)
2. [Findings by severity](#findings-by-severity)
   - [High findings](#high-findings)
   - [Medium findings](#medium-findings)
3. [Recommendations](#recommendations)
4. [Risk assessment](#risk-assessment)
5. [Finding details](#finding-details)

## Executive summary

[stubbed model response 1]

## Findings by severity

### High findings

[stubbed model response 2]

### Medium findings

[stubbed model response 3]

## Recommendations

[stubbed model response 4]

## Risk assessment

[stubbed model response 5]

## Finding details

### Finding index

| Index | Rule ID | Severity | File | Line range | Description |
|-------|---------|----------|------|------------|-------------|
| 1 | B602 | HIGH | app.py | 7 | subprocess call with shell=True identified, sec... |
| 2 | CKV\_AWS\_20 | HIGH | main.tf | 1-4 | S3 Bucket has an ACL defined which allows publi... |
| 3 | terraform.aws.best-practice.s3-bucket-name-hardcoded | MEDIUM | main.tf | 2 | Bucket name is hardcoded; derive it from a vari... |


### Evidence

<details>
<summary>1. HIGH · B602</summary>

#### Finding 1: B602 (HIGH)

Location: app.py (lines 7-7)

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
          "uri": "app.py",
          "uriBaseId": "PROJECTROOT"
        },
        "region": {
          "startLine": 7,
          "endLine": 7
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
        "duration": 1.0,
        "start_time": "2026-01-15T12:00:00+00:00",
        "end_time": "2026-01-15T12:00:01+00:00"
      }
    },
    "workspace_project": "api",
    "workspace_uri": "api/app.py"
  },
  "index": 1,
  "severity": "HIGH"
}
```
</details>

</details>

<details>
<summary>2. HIGH · CKV_AWS_20</summary>

#### Finding 2: CKV\_AWS\_20 (HIGH)

Location: main.tf (lines 1-4)

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
          "uri": "main.tf",
          "uriBaseId": "PROJECTROOT"
        },
        "region": {
          "startLine": 1,
          "endLine": 4
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
        "duration": 2.0,
        "start_time": "2026-01-15T12:00:00+00:00",
        "end_time": "2026-01-15T12:00:02+00:00"
      }
    },
    "workspace_project": "web",
    "workspace_uri": "web/main.tf"
  },
  "index": 2,
  "severity": "HIGH"
}
```
</details>

</details>

<details>
<summary>3. MEDIUM · terraform.aws.best-practice.s3-bucket-name-hardcoded</summary>

#### Finding 3: terraform.aws.best-practice.s3-bucket-name-hardcoded (MEDIUM)

Location: main.tf (lines 2-2)

Bucket name is hardcoded; derive it from a variable.

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "terraform.aws.best-practice.s3-bucket-name-hardcoded",
  "message": {
    "text": "Bucket name is hardcoded; derive it from a variable."
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "main.tf",
          "uriBaseId": "PROJECTROOT"
        },
        "region": {
          "startLine": 2,
          "endLine": 2
        }
      }
    }
  ],
  "properties": {
    "tags": [
      "semgrep"
    ],
    "issue_severity": "MEDIUM",
    "scanner_name": "semgrep",
    "scanner_version": "1.140.0",
    "scanner_details": {
      "tool_name": "semgrep",
      "tool_version": "1.140.0",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 1.5,
        "start_time": "2026-01-15T12:00:02+00:00",
        "end_time": "2026-01-15T12:00:03.500000+00:00"
      }
    },
    "workspace_project": "web",
    "workspace_uri": "web/main.tf"
  },
  "level": "warning",
  "index": 3,
  "severity": "MEDIUM"
}
```
</details>

</details>



Build with <3 at Amazon Web Services
