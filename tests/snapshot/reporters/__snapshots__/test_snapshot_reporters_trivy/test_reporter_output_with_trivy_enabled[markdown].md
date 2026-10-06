# ASH Security Scan Report

- **Report generated**: 2026-01-15T12:00:42+00:00
- **Time since scan**: 0 minutes

## Scan Metadata

- **Project**: ASH
- **Scan executed**: 2026-01-15T12:00:00+00:00
- **ASH version**: <ASH_VERSION>

## Summary

### Scanner Results

The table below shows findings by scanner, with status based on severity thresholds and dependencies:

- **Severity levels**:
  - **Suppressed (S)**: Findings that have been explicitly suppressed and don't affect scanner status
  - **Critical (C)**: Highest severity findings that require immediate attention
  - **High (H)**: Serious findings that should be addressed soon
  - **Medium (M)**: Moderate risk findings
  - **Low (L)**: Lower risk findings
  - **Info (I)**: Informational findings with minimal risk
- **Actionable**: Number of findings at or above the threshold severity level that require attention
- **Result**:
  - **PASSED** = No findings at or above threshold
  - **FAILED** = Findings at or above threshold
  - **MISSING** = Required dependencies not available
  - **SKIPPED** = Scanner explicitly disabled
  - **ERROR** = Scanner execution error
- **Threshold**: The minimum severity level that will cause a scanner to fail
  - Thresholds: ALL, LOW, MEDIUM, HIGH, CRITICAL
  - Source: Values in parentheses indicate where the threshold is set:
    - `global` (global_settings section in the ASH_CONFIG used)
    - `config` (scanner config section in the ASH_CONFIG used)
    - `scanner` (default configuration in the plugin, if explicitly set)
- **Statistics calculation**:
  - All statistics are calculated from the final aggregated SARIF report
  - Suppressed findings are counted separately and do not contribute to actionable findings
  - Scanner status is determined by comparing actionable findings to the threshold

| Scanner | Suppressed | Critical | High | Medium | Low | Info | Actionable | Result | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| trivy | 0 | 0 | 3 | 7 | 0 | 0 | 10 | FAILED | MEDIUM (global) |

### Top 2 Hotspots

Files with the highest number of security findings:

| Finding Count | File Location |
| ---: | --- |
| 5 | package-lock.json |
| 5 | requirements.txt |

<h2>Detailed Findings</h2>

<details>
<summary>Show 10 actionable findings</summary>

### Finding 1: CVE-2021-23337

- **Severity**: HIGH
- **Scanner**: trivy
- **Rule ID**: CVE-2021-23337
- **Location**: package-lock.json:13-17

**Description**:
Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2021-23337
Severity: HIGH
Fixed Version: 4.17.21
Link: [CVE-2021-23337](https://avd.aquasec.com/nvd/cve-2021-23337)

---

### Finding 2: CVE-2026-4800

- **Severity**: HIGH
- **Scanner**: trivy
- **Rule ID**: CVE-2026-4800
- **Location**: package-lock.json:13-17

**Description**:
Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2026-4800
Severity: HIGH
Fixed Version: 4.18.0
Link: [CVE-2026-4800](https://avd.aquasec.com/nvd/cve-2026-4800)

---

### Finding 3: CVE-2020-28500

- **Severity**: MEDIUM
- **Scanner**: trivy
- **Rule ID**: CVE-2020-28500
- **Location**: package-lock.json:13-17

**Description**:
Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2020-28500
Severity: MEDIUM
Fixed Version: 4.17.21
Link: [CVE-2020-28500](https://avd.aquasec.com/nvd/cve-2020-28500)

---

### Finding 4: CVE-2025-13465

- **Severity**: MEDIUM
- **Scanner**: trivy
- **Rule ID**: CVE-2025-13465
- **Location**: package-lock.json:13-17

**Description**:
Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2025-13465
Severity: MEDIUM
Fixed Version: 4.17.23
Link: [CVE-2025-13465](https://avd.aquasec.com/nvd/cve-2025-13465)

---

### Finding 5: CVE-2026-2950

- **Severity**: MEDIUM
- **Scanner**: trivy
- **Rule ID**: CVE-2026-2950
- **Location**: package-lock.json:13-17

**Description**:
Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2026-2950
Severity: MEDIUM
Fixed Version: 4.18.0
Link: [CVE-2026-2950](https://avd.aquasec.com/nvd/cve-2026-2950)

---

### Finding 6: CVE-2018-18074

- **Severity**: HIGH
- **Scanner**: trivy
- **Rule ID**: CVE-2018-18074
- **Location**: requirements.txt:2

**Description**:
Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2018-18074
Severity: HIGH
Fixed Version: 2.20.0
Link: [CVE-2018-18074](https://avd.aquasec.com/nvd/cve-2018-18074)

---

### Finding 7: CVE-2023-32681

- **Severity**: MEDIUM
- **Scanner**: trivy
- **Rule ID**: CVE-2023-32681
- **Location**: requirements.txt:2

**Description**:
Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2023-32681
Severity: MEDIUM
Fixed Version: 2.31.0
Link: [CVE-2023-32681](https://avd.aquasec.com/nvd/cve-2023-32681)

---

### Finding 8: CVE-2024-35195

- **Severity**: MEDIUM
- **Scanner**: trivy
- **Rule ID**: CVE-2024-35195
- **Location**: requirements.txt:2

**Description**:
Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2024-35195
Severity: MEDIUM
Fixed Version: 2.32.0
Link: [CVE-2024-35195](https://avd.aquasec.com/nvd/cve-2024-35195)

---

### Finding 9: CVE-2024-47081

- **Severity**: MEDIUM
- **Scanner**: trivy
- **Rule ID**: CVE-2024-47081
- **Location**: requirements.txt:2

**Description**:
Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2024-47081
Severity: MEDIUM
Fixed Version: 2.32.4
Link: [CVE-2024-47081](https://avd.aquasec.com/nvd/cve-2024-47081)

---

### Finding 10: CVE-2026-25645

- **Severity**: MEDIUM
- **Scanner**: trivy
- **Rule ID**: CVE-2026-25645
- **Location**: requirements.txt:2

**Description**:
Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2026-25645
Severity: MEDIUM
Fixed Version: 2.33.0
Link: [CVE-2026-25645](https://avd.aquasec.com/nvd/cve-2026-25645)

</details>

---

*Report generated by [Automated Security Helper (ASH)](https://github.com/awslabs/automated-security-helper) at 2026-01-15T12:00:42+00:00*
