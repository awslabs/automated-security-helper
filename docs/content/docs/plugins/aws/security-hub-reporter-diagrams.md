# Security Hub Reporter Diagrams

These diagrams show what the [Security Hub Reporter](security-hub-reporter.md) does during a scan in which it is enabled.

## Sequence

```mermaid
sequenceDiagram
    participant RP as ReportPhase
    participant SHR as aws-security-hub reporter
    participant STS as AWS STS
    participant SH as AWS Security Hub

    RP->>SHR: validate_plugin_dependencies()
    SHR->>SHR: Region set
    SHR->>SH: DescribeHub
    SH-->>SHR: hub ARN (Security Hub is enabled)
    opt account_id not set
        SHR->>STS: GetCallerIdentity
        STS-->>SHR: account ID
    end
    RP->>SHR: report(results)
    SHR->>SHR: enabled, config valid, not a workspace's unified results
    SHR->>SHR: Region set, findings_scope set
    SHR->>STS: GetCallerIdentity
    STS-->>SHR: caller account (must equal account_id when set)
    SHR->>SHR: one ASFF finding per SARIF result
    SHR->>SHR: drop exact duplicates (same Id)
    loop Each page of findings already stored for the scan target
        SHR->>SH: GetFindings (ProductArn, ash/target)
        SH-->>SHR: Findings, NextToken
    end
    SHR->>SHR: keep stored CreatedAt, build archive records
    loop Each batch of at most 100 findings and archive records
        SHR->>SH: BatchImportFindings
        SH-->>SHR: SuccessCount, FailedCount, FailedFindings
    end
    SHR-->>RP: receipt (written to reports/ash.aws-security-hub.asff.json)
```

`GetFindings` runs only when `archive_resolved_findings` is true (it is false by default).

## Finding identity

```mermaid
flowchart LR
    N[findings_scope option] --> H["sha256(json.dumps([target, key]))"]
    S[scanner, rule] --> K[key]
    F["file path, one spelling, or a converted file's path under the converted files"] --> K
    P[package name and path] --> K
    W[workspace project key] --> K
    FP{usable fingerprints?}
    FP -->|yes| FG[fingerprints or partialFingerprints] --> K
    FP -->|no: none, placeholder, or shared by two locations| L[start line, end line] --> K
    L --> O{other results with this key?}
    O -->|yes| OS["occurrence: 8 hex of sha256([column, message]); ordinal for exact duplicates"] --> K
    K --> H
    H --> I["Id = ash/&lt;digest&gt;"]
```

The scan time, the report id, the message, the severity, the column and the package version are not in the key, so a re-scan updates the same finding. The column and message only tell apart findings that share a key.

## Which stored findings are archived

Only with `archive_resolved_findings: true`.

```mermaid
flowchart TD
    S{one shard, changed files only, or no changed-files or scan_source marker?} -->|Yes| K0[nothing is archived]
    S -->|No| A[stored finding from GetFindings]
    A --> B{ACTIVE, Id starts with ash/?}
    B -->|No| K[left alone]
    B -->|Yes| C{produced by this scan?}
    C -->|Yes| K
    C -->|No| O{same ash/target and workspace project?}
    O -->|No| K
    O -->|Yes| D{its scanner PASSED or FAILED, and no target failed?}
    D -->|No| K
    D -->|Yes| SC{same ash/scope: recorded directory and converted tree?}
    SC -->|No| K
    SC -->|Yes| E{last updated before this scan?}
    E -->|No| K
    E -->|Yes| X[re-imported with RecordState ARCHIVED]
```

## Failure handling

```mermaid
flowchart TD
    A[report] --> R0{enabled, config valid, not workspace results?}
    R0 -->|No| X0[SecurityHubImportError: what to fix]
    R0 -->|Yes| B{findings_scope and Region set?}
    B -->|No| X[SecurityHubImportError: what to set]
    B -->|Yes| C{Findings, or anything to archive?}
    C -->|No| R[Receipt with imported 0, no AWS call]
    C -->|Yes| AC{caller's account matches account_id?}
    AC -->|No| XA[SecurityHubImportError: use that account's credentials]
    AC -->|Yes| GF{GetFindings succeeded?}
    GF -->|No| GE[import without archiving, then SecurityHubImportError: grant GetFindings]
    GF -->|Yes| D[Send next batch]
    D --> E{Request succeeded?}
    E -->|Throttled| F[Back off and retry, up to max_retries]
    F --> E
    E -->|Failed| Y[SecurityHubImportError: cause, imported so far, not sent]
    E -->|Yes| G{Every finding in the batch rejected with InvalidAccess?}
    G -->|Yes| J
    G -->|No| I{More batches?}
    I -->|Yes| D
    I -->|No| J{Any finding rejected or not sent?}
    J -->|Yes| K[Log each rejected Id and error, then SecurityHubImportError with the counts by error code]
    J -->|No| R2[Receipt with the imported and archived findings]
```

A `SecurityHubImportError` makes the reporter fail: ReportPhase logs it and writes no receipt, and `ash report` exits 1.
