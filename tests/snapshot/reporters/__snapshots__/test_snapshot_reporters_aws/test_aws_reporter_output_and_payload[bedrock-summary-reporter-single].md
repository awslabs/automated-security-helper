# Security Scan Summary Report

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Findings by Severity](#findings-by-severity)
   - [Warning Level Findings](#warning-level-findings)
   - [Note Level Findings](#note-level-findings)
   - [None Level Findings](#none-level-findings)
3. [Recommendations](#recommendations)
4. [Risk Assessment](#risk-assessment)
5. [Finding Details](#finding-details)

## Executive Summary

[stubbed model response 1]

## Findings by Severity

### Warning Level Findings

[stubbed model response 2]

### Note Level Findings

[stubbed model response 3]

### None Level Findings

[stubbed model response 4]

## Recommendations

[stubbed model response 5]

## Risk Assessment

[stubbed model response 6]

## Finding Details

This section contains detailed information about each finding referenced in the report.

### Finding Index Reference

| Index | Rule ID | Severity | File | Line Range | Description |
|-------|---------|----------|------|------------|-------------|
| 1 | Unknown | None | app/app.py | 9 | subprocess call with shell=True identified, sec... |
| 2 | Unknown | Note | app/app.py | 5 | Possible hardcoded password: 'hunter2-not-a-rea... |
| 3 | Unknown | None | infra/main.tf | 6-9 | S3 Bucket has an ACL defined which allows publi... |
| 4 | Unknown | Warning | infra/main.tf | 2-4 | Ensure the S3 bucket has access logging enabled |
| 5 | Unknown | Warning | Dockerfile | 5 | Ensure the last USER is not root |
| 6 | Unknown | Note | Dockerfile | 1-6 | Ensure that HEALTHCHECK instructions have been ... |
| 7 | Unknown | Note | Dockerfile | 5 | The last user in the container is 'root'. Switc... |
| 8 | Unknown | None | app/app.py | 9 | Command string built with an f-string; prefer a... |
| 9 | Unknown | None | app/app.py | 5 | Secret of type Secret Keyword detected in file ... |
| 10 | Unknown | None | requirements.txt | 1 | A critical vulnerability in requests 2.19.1 (fi... |
| 11 | Unknown | Warning | requirements.txt | 1 | A medium vulnerability in requests 2.19.1 (fixe... |


### Full Finding Details

<details>
<summary>Click to expand full finding details</summary>

#### Finding 1: Unknown (None)

**Location**: app/app.py (lines 9-9)

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
          "uri": "app/app.py"
        },
        "region": {
          "startLine": 9,
          "endLine": 9,
          "snippet": {
            "text": "    return subprocess.run(f\"pg_dump orders --where id={customer_id}\", shell=True)"
          }
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
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 1
}
```
</details>

#### Finding 2: Unknown (Note)

**Location**: app/app.py (lines 5-5)

**Description**: Possible hardcoded password: 'hunter2-not-a-real-secret'

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "B105",
  "level": "note",
  "message": {
    "text": "Possible hardcoded password: 'hunter2-not-a-real-secret'"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "app/app.py"
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
      "bandit"
    ],
    "issue_severity": "LOW",
    "issue_confidence": "MEDIUM",
    "scanner_name": "bandit",
    "scanner_version": "1.8.6",
    "scanner_details": {
      "tool_name": "bandit",
      "tool_version": "1.8.6",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 1.25,
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 2
}
```
</details>

#### Finding 3: Unknown (None)

**Location**: infra/main.tf (lines 6-9)

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
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 3
}
```
</details>

#### Finding 4: Unknown (Warning)

**Location**: infra/main.tf (lines 2-4)

**Description**: Ensure the S3 bucket has access logging enabled

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CKV_AWS_18",
  "level": "warning",
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
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 4
}
```
</details>

#### Finding 5: Unknown (Warning)

**Location**: Dockerfile (lines 5-5)

**Description**: Ensure the last USER is not root

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CKV_DOCKER_8",
  "level": "warning",
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
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 5
}
```
</details>

#### Finding 6: Unknown (Note)

**Location**: Dockerfile (lines 1-6)

**Description**: Ensure that HEALTHCHECK instructions have been added to container images

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CKV_DOCKER_2",
  "level": "note",
  "message": {
    "text": "Ensure that HEALTHCHECK instructions have been added to container images"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "Dockerfile"
        },
        "region": {
          "startLine": 1,
          "endLine": 6
        }
      }
    }
  ],
  "properties": {
    "tags": [
      "checkov"
    ],
    "issue_severity": "LOW",
    "scanner_name": "checkov",
    "scanner_version": "3.2.469",
    "scanner_details": {
      "tool_name": "checkov",
      "tool_version": "3.2.469",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 7.5,
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 6
}
```
</details>

#### Finding 7: Unknown (Note)

**Location**: Dockerfile (lines 5-5)

**Description**: The last user in the container is 'root'. Switch back to an unprivileged user.

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "dockerfile.security.last-user-is-root.last-user-is-root",
  "level": "note",
  "message": {
    "text": "The last user in the container is 'root'. Switch back to an unprivileged user."
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
      "semgrep"
    ],
    "issue_severity": "LOW",
    "scanner_name": "semgrep",
    "scanner_version": "1.140.0",
    "scanner_details": {
      "tool_name": "semgrep",
      "tool_version": "1.140.0",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 4.0,
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 7
}
```
</details>

#### Finding 8: Unknown (None)

**Location**: app/app.py (lines 9-9)

**Description**: Command string built with an f-string; prefer an argument list.

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "python.lang.best-practice.unpinned-shell-command",
  "level": "none",
  "message": {
    "text": "Command string built with an f-string; prefer an argument list."
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
      "semgrep"
    ],
    "issue_severity": "INFO",
    "scanner_name": "semgrep",
    "scanner_version": "1.140.0",
    "scanner_details": {
      "tool_name": "semgrep",
      "tool_version": "1.140.0",
      "tool_invocation": {
        "exit_code": 0,
        "duration": 4.0,
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 8
}
```
</details>

#### Finding 9: Unknown (None)

**Location**: app/app.py (lines 5-5)

**Description**: Secret of type Secret Keyword detected in file app/app.py at line 5


```
</details>

#### Finding 10: Unknown (None)

**Location**: requirements.txt (lines 1-1)

**Description**: A critical vulnerability in requests 2.19.1 (fixed in 2.20.0) was found at requirements.txt

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CVE-2018-18074-requests",
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
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 10
}
```
</details>

#### Finding 11: Unknown (Warning)

**Location**: requirements.txt (lines 1-1)

**Description**: A medium vulnerability in requests 2.19.1 (fixed in 2.31.0) was found at requirements.txt

<details>
<summary>Raw JSON</summary>

```json
{
  "ruleId": "CVE-2023-32681-requests",
  "level": "warning",
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
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    }
  },
  "index": 11
}
```
</details>

</details>
