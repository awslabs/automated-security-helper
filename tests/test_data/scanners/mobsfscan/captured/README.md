# Captured mobsfscan 1.2.0 output

`positive.sarif`, `negative.sarif` and `semgrep_missing.sarif` are the SARIF a real
mobsfscan 1.2.0 wrote (installed by uv 0.13.1 on Linux x86_64, CPython 3.12, semgrep
1.172.0), re-serialized to one line with `json.dumps(..., separators=(",", ":"))`.
`semgrep_missing.json` is the JSON format of the same run as `semgrep_missing.sarif`.
The unit tests serve them from a fake subprocess, so they run on every platform
without mobsfscan.

Argv, run from inside each input tree (the working directory ASH uses) through uv:

```text
uv tool run --offline --from mobsfscan==1.2.0 mobsfscan --sarif --output=<file> \
  --no-fail --config=<empty.mobsf> -- .
```

`empty.mobsf` holds `ignore-rules: []`, the stub ASH writes.

Inputs:

* `positive/Main.java`: `setAllowFileAccess(true)` on a WebView, a hard-coded
  password with a fabricated value, and an `AES/ECB/PKCS5Padding` cipher.
* `positive/app.js`: an `eval` of a variable.
* `negative/Clean.java`: a method that adds two ints.

Facts the captures show and the scanner relies on:

* A result's `level` is `error` for an ERROR rule (`aes_ecb_mode`), `note` for an INFO
  rule, and absent for a WARNING rule (`hardcoded_password`,
  `webview_set_allow_file_access`, `js_dynamic_code_execution`): SARIF's default is
  `warning`, so ASH rates an absent level MEDIUM.
* The six Android best-practice rules (`android_*`) report on any tree, including the
  clean one, at `note` level with uri `.` and the snippet `Missing Best Practice`.
  `negative.sarif` is therefore six LOW notes, not an empty report.
* The driver names the version in both `version` and `semanticVersion`.
* `semgrep_missing.*` was produced by running the installed `mobsfscan` with semgrep
  off PATH. mobsfscan exits 0, the JSON `errors` list holds `semgrep not found.
  Install with: pip install semgrep`, and the SARIF holds no Java finding and no
  mention of the error. This is the false-clean shape the scanner's semgrep guard
  prevents.
* The fabricated password value appears in the SARIF snippet as the tool wrote it;
  the scanner redacts it before it reaches a report.
