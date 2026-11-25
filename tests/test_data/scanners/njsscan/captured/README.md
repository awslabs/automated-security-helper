# Captured njsscan 1.0.2 output

`positive.sarif`, `negative.sarif` and `errored.sarif` are the SARIF the pinned njsscan
(PyPI `njsscan==1.0.2`, installed with `uv tool install --python '>=3.10'` on CPython 3.12,
Linux x86_64, 2026-11-25) wrote, compacted to one line (`json.dumps(..., separators=(",", ":"))`).
The unit tests serve them from a fake subprocess, so they run on every platform without the
tool.

Argv, from the directory of each input (the working directory ASH uses):

```text
njsscan --sarif --output=<file> --config=<file holding "ignore-rules: []"> -- .
```

Inputs:

- `positive.sarif`: one file, `app.js`, with `Math.random().toString(36)` on line 4 and
  `eval(req.query.code)` on line 8. Exit status 1.
- `negative.sarif`: one file, `app.js`, holding an arrow function and a `module.exports`.
  Exit status 0.
- `errored.sarif`: the positive input run with njsscan's own environment `bin` directory
  missing from `PATH`, so libsast could not start `semgrep` ("semgrep not found"). Exit
  status 1, `results` empty, `executionSuccessful` false. It is what a scan that read no
  file looks like, and it is what the incomplete-scan gate must see.

Facts the captures show and the scanner relies on:

- The WARNING finding (`node_insecure_random_generator`) carries NO `level` key: njsscan
  omits SARIF's default (`warning`). The ERROR finding carries `"level": "error"`.
  The scanner reads the missing level as MEDIUM.
- Every result has `properties` with `owasp-web` and `cwe`, each one string
  (`"CWE-327: Use of a Broken or Risky Cryptographic Algorithm"`); the rule carries the same
  CWE as a tag (`external/cwe/cwe-327`).
- A clean scan lists no `rules` at all; a scan with findings lists only the rules that fired.
- The driver is named `nodejsscan`, not `njsscan`.
- Exit status 1 does not tell findings from read errors: `executionSuccessful` does.
- `semgrep` must be on `PATH`. njsscan finds it through `PATH` only, so a run from the
  uv tool's `bin` symlink alone, with the tool environment's `bin` off `PATH`, fails as
  `errored.sarif` shows. `uv tool run` puts that directory first.
