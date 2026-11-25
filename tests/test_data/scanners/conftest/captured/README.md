# Captured Conftest 0.62.0 output

`positive.sarif` and `negative.sarif` are the SARIF a real Conftest 0.62.0 (OPA 1.6.0,
linux/x86_64 release asset, binary sha256
`662883d33542df02efbf6505de08f307a3e9d15fb40d189a853b76e38d8d31f2`) wrote to stdout.
The unit tests serve them from a fake subprocess, so they run on every platform without
the binary.

Argv, from the directory of each input (the working directory ASH uses):

```text
conftest test --output=sarif --no-fail --no-color --policy=policy --all-namespaces -- <files>
```

The policy is `policy/base.rego`, package `main`, with one `deny` rule (a `Pod` with
`spec.runAsRoot`, message `pod must not run as root`) and one `warn` rule (image
`app:latest`, message `image uses the latest tag`).

- `positive.sarif`: files `deploy/bad.yaml` (violates both rules) and `deploy/good.yaml`
  (violates neither). Exit status 0 under `--no-fail`; the report's own invocation says
  `exitCode` 1, "Policy violations found".
- `negative.sarif`: `deploy/good.yaml` alone. Exit status 0.

Facts the captures show and the scanner relies on:

- A result has no `region`: Conftest reports the file, not a line.
- Each file with no failure gets a `main/success` result at level `none`; ASH drops it.
- `rules` lists only the rules that produced a result, so `ruleIndex` is per report.
- stderr was empty for both runs.
