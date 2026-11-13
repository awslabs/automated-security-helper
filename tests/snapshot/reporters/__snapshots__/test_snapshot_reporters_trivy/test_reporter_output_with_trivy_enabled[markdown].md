# ASH security scan report

> [!CAUTION]
> **Review required**
>
> 10 findings at or above the configured scanner thresholds.
>
> **10 actionable** · 0 below threshold · 0 suppressed · 1/1 scanners completed
>
> Next action: Review findings by severity, then inspect the source.

Project: ASH · Scan executed: 2026-01-15T12:00:00+00:00

## Summary

### Scanner results

| Scanner | Suppressed | Critical | High | Medium | Low | Info | Actionable | Result | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| trivy | 0 | 0 | 3 | 7 | 0 | 0 | 10 | FAILED | MEDIUM (global) |

<details>
<summary>How to read scanner results</summary>

**Severity levels:** Critical, High, Medium, Low, Info. Suppressed findings are counted separately.

**Actionable** counts findings at or above each scanner's threshold.

**Result:** PASSED = no actionable findings; FAILED = threshold exceeded; MISSING = dependencies unavailable; SKIPPED = did not run (disabled, or nothing to scan); ERROR = execution error.

**Threshold** shows the minimum severity and its source: `global`, `config`, or `scanner`.

**Statistics calculation:** final aggregated SARIF, with suppressed findings excluded from actionable counts.

</details>


### Top 2 hotspots

Files with the most actionable findings.

| Finding count | File location |
| ---: | --- |
| 5 | /src/package-lock.json |
| 5 | /src/requirements.txt |

## Detailed findings

Showing 10 of 10 actionable findings, highest severity first.

<details>
<summary>1. HIGH · CVE-2021-23337 · /src/package-lock.json:13-17</summary>

### Finding 1: CVE-2021-23337

- Severity: HIGH
- Scanner: trivy
- Rule ID: CVE-2021-23337
- Location: /src/package-lock.json:13-17

Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2021-23337
Severity: HIGH
Fixed Version: 4.17.21
Link: \[CVE-2021-23337\](`https://avd.aquasec.com/nvd/cve-2021-23337`)

</details>

<details>
<summary>2. HIGH · CVE-2026-4800 · /src/package-lock.json:13-17</summary>

### Finding 2: CVE-2026-4800

- Severity: HIGH
- Scanner: trivy
- Rule ID: CVE-2026-4800
- Location: /src/package-lock.json:13-17

Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2026-4800
Severity: HIGH
Fixed Version: 4.18.0
Link: \[CVE-2026-4800\](`https://avd.aquasec.com/nvd/cve-2026-4800`)

</details>

<details>
<summary>3. HIGH · CVE-2018-18074 · /src/requirements.txt:2</summary>

### Finding 3: CVE-2018-18074

- Severity: HIGH
- Scanner: trivy
- Rule ID: CVE-2018-18074
- Location: /src/requirements.txt:2

Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2018-18074
Severity: HIGH
Fixed Version: 2.20.0
Link: \[CVE-2018-18074\](`https://avd.aquasec.com/nvd/cve-2018-18074`)

</details>

<details>
<summary>4. MEDIUM · CVE-2020-28500 · /src/package-lock.json:13-17</summary>

### Finding 4: CVE-2020-28500

- Severity: MEDIUM
- Scanner: trivy
- Rule ID: CVE-2020-28500
- Location: /src/package-lock.json:13-17

Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2020-28500
Severity: MEDIUM
Fixed Version: 4.17.21
Link: \[CVE-2020-28500\](`https://avd.aquasec.com/nvd/cve-2020-28500`)

</details>

<details>
<summary>5. MEDIUM · CVE-2025-13465 · /src/package-lock.json:13-17</summary>

### Finding 5: CVE-2025-13465

- Severity: MEDIUM
- Scanner: trivy
- Rule ID: CVE-2025-13465
- Location: /src/package-lock.json:13-17

Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2025-13465
Severity: MEDIUM
Fixed Version: 4.17.23
Link: \[CVE-2025-13465\](`https://avd.aquasec.com/nvd/cve-2025-13465`)

</details>

<details>
<summary>6. MEDIUM · CVE-2026-2950 · /src/package-lock.json:13-17</summary>

### Finding 6: CVE-2026-2950

- Severity: MEDIUM
- Scanner: trivy
- Rule ID: CVE-2026-2950
- Location: /src/package-lock.json:13-17

Package: lodash
Installed Version: 4.17.20
Vulnerability CVE-2026-2950
Severity: MEDIUM
Fixed Version: 4.18.0
Link: \[CVE-2026-2950\](`https://avd.aquasec.com/nvd/cve-2026-2950`)

</details>

<details>
<summary>7. MEDIUM · CVE-2023-32681 · /src/requirements.txt:2</summary>

### Finding 7: CVE-2023-32681

- Severity: MEDIUM
- Scanner: trivy
- Rule ID: CVE-2023-32681
- Location: /src/requirements.txt:2

Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2023-32681
Severity: MEDIUM
Fixed Version: 2.31.0
Link: \[CVE-2023-32681\](`https://avd.aquasec.com/nvd/cve-2023-32681`)

</details>

<details>
<summary>8. MEDIUM · CVE-2024-35195 · /src/requirements.txt:2</summary>

### Finding 8: CVE-2024-35195

- Severity: MEDIUM
- Scanner: trivy
- Rule ID: CVE-2024-35195
- Location: /src/requirements.txt:2

Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2024-35195
Severity: MEDIUM
Fixed Version: 2.32.0
Link: \[CVE-2024-35195\](`https://avd.aquasec.com/nvd/cve-2024-35195`)

</details>

<details>
<summary>9. MEDIUM · CVE-2024-47081 · /src/requirements.txt:2</summary>

### Finding 9: CVE-2024-47081

- Severity: MEDIUM
- Scanner: trivy
- Rule ID: CVE-2024-47081
- Location: /src/requirements.txt:2

Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2024-47081
Severity: MEDIUM
Fixed Version: 2.32.4
Link: \[CVE-2024-47081\](`https://avd.aquasec.com/nvd/cve-2024-47081`)

</details>

<details>
<summary>10. MEDIUM · CVE-2026-25645 · /src/requirements.txt:2</summary>

### Finding 10: CVE-2026-25645

- Severity: MEDIUM
- Scanner: trivy
- Rule ID: CVE-2026-25645
- Location: /src/requirements.txt:2

Package: requests
Installed Version: 2.19.1
Vulnerability CVE-2026-25645
Severity: MEDIUM
Fixed Version: 2.33.0
Link: \[CVE-2026-25645\](`https://avd.aquasec.com/nvd/cve-2026-25645`)

</details>

<details>
<summary>Scan metadata</summary>

## Scan metadata

- Project: ASH
- Scan executed: 2026-01-15T12:00:00+00:00
- Report generated: 2026-01-15T12:00:42+00:00
- ASH version: <ASH_VERSION>

</details>

*Report generated by [Automated Security Helper (ASH)](https://github.com/awslabs/automated-security-helper) at 2026-01-15T12:00:42+00:00*

Build with <3 at Amazon Web Services
