# Polaris captured output

Real output of `polaris audit` v10.2.6 (linux/amd64, release archive SHA256
`87856194124409f7f21912775c0d6ac0804061ddaded5b527a1326f1850e9491`), run on 2026-11-25
from the directory that holds `in/`:

```
polaris audit --audit-path=in/pos --format=json --only-show-failed-tests=true \
  --set-exit-code-on-danger=true --disallow-exemptions=true --output-file=pos.json
polaris audit --audit-path=in/neg --format=json --only-show-failed-tests=true \
  --set-exit-code-on-danger=true --disallow-exemptions=true --output-file=neg.json
```

| File | What it is |
|---|---|
| `in/pos/deploy.yaml` | The input: a Deployment `web` in namespace `demo` with a privileged `nginx:latest` container. |
| `positive.json` | Polaris's report for it (exit 3, four danger-level failures). Re-serialized by the repository's JSON formatter (two-space indent, sorted keys); no value changed. |
| `in/neg/readme.yaml` | The input: a YAML file that is not a Kubernetes object. |
| `negative.json` | Polaris's report for it (exit 0, `Results` empty). Re-serialized the same way. |
| `positive.sarif` | What `PolarisScanner.convert_polaris_output` writes for `positive.json` over the tree in `in/pos`. Regenerate it with the test `test_the_committed_sarif_is_what_the_converter_writes`. |

The SARIF file is the corpus the facets register's consistency gate reads.
