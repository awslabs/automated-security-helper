# Security Scan Summary Report

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Findings by Severity](#findings-by-severity)
   - [Warning Level Findings](#warning-level-findings)
3. [Recommendations](#recommendations)
4. [Risk Assessment](#risk-assessment)
5. [Finding Details](#finding-details)

## Executive Summary

[stubbed model response 1]

## Findings by Severity

### Warning Level Findings

[stubbed model response 2]

### None Level Findings

[stubbed model response 3]

## Recommendations

[stubbed model response 4]

## Risk Assessment

[stubbed model response 5]

## Finding Details

This section contains detailed information about each finding referenced in the report.

### Finding Index Reference

| Index | Rule ID | Severity | File | Line Range | Description |
|-------|---------|----------|------|------------|-------------|
| 1 | Unknown | None | app.py | 7 | subprocess call with shell=True identified, sec... |
| 2 | Unknown | None | main.tf | 1-4 | S3 Bucket has an ACL defined which allows publi... |
| 3 | Unknown | Warning | main.tf | 2 | Bucket name is hardcoded; derive it from a vari... |


### Full Finding Details

<details>
<summary>Click to expand full finding details</summary>

#### Finding 1: Unknown (None)

**Location**: app.py (lines 7-7)

**Description**: subprocess call with shell=True identified, security issue.

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "B602",
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
  "index": 1
}
```
</details>

#### Finding 2: Unknown (None)

**Location**: main.tf (lines 1-4)

**Description**: S3 Bucket has an ACL defined which allows public READ access.

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CKV_AWS_20",
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
  "index": 2
}
```
</details>

#### Finding 3: Unknown (Warning)

**Location**: main.tf (lines 2-2)

**Description**: Bucket name is hardcoded; derive it from a variable.

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "terraform.aws.best-practice.s3-bucket-name-hardcoded",
  "level": "warning",
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
  "index": 3
}
```
</details>

</details>
