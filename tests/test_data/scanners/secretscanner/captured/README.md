# SecretScanner sample output

These files are NOT captured from a run. Deepfence publishes no SecretScanner
binary (the v2.5.8 release lists no assets), the tool needs a Docker daemon and
a built binary, and no run was possible when they were written. The JSON is
written by hand from the tool's output structs (`output/output.go` and
YaraHunter's `pkg/output` at v2.5.8). The matched text is a plain placeholder,
not a credential. When a real run is captured, replace `positive.json` and
`negative.json` with it and regenerate the SARIF files.

| File | What it is |
| --- | --- |
| `positive.json` | The tool's `-output=json` object with three findings, one per severity. |
| `negative.json` | The same object with an empty `IOC` list. |
| `positive.sarif` | What `SecretScannerScanner.convert_output` writes for `positive.json`. |
| `negative.sarif` | What `convert_output` writes for `negative.json`. |

`tests/unit/plugin_modules/ash_secretscanner_plugins/test_secretscanner_scanner_behavior.py`
converts each JSON file and fails when the result no longer equals the SARIF
file beside it.
