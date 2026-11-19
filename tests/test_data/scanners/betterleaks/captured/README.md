# Captured Betterleaks 1.10.1 output

`positive.sarif` and `negative.sarif` are the SARIF the pinned Betterleaks (v1.10.1,
linux/amd64 release asset, checked against ASH's digest) wrote, compacted to one line (`jq -c .`). The unit
tests serve them from a fake subprocess, so they run on every platform without the
binary.

Argv, from the directory of each input (the working directory ASH uses):

```text
betterleaks dir --report-format=sarif --report-path=<file> --redact=100 --exit-code=2 \
  --no-banner --no-color --gitleaks-ignore-path=<empty directory> --ignore-gitleaks-allow \
  --config=<min.toml> -- .
```

`min.toml` holds one rule, `github-pat` with the regex `ghp_[0-9a-zA-Z]{36}`, so the
report's `rules` list has one entry; with Betterleaks' built-in rules the list is 466
entries long and says nothing the tests read. The inputs were two Python files holding
one fabricated GitHub token each (`src/app.py` line 4, `src/services/settings.py` line
3) and one clean file. The tokens are not kept: the report holds `REDACTED`, which is
what these tests assert on. Exit status was 2 for the positive run and 0 for the
negative one.

Two facts the captures show and the scanner relies on: the driver's `semanticVersion` is
`v8.0.0` (a gitleaks-era constant, not the release), and every result's
`partialFingerprints` holds five empty strings in `dir` mode.
