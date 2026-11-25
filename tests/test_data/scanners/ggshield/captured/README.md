# ggshield 1.56.1 output, written by ggshield's own CLI

`positive.sarif` and `negative.sarif` are the SARIF that ggshield 1.56.1 (PyPI, the
release ASH pins) wrote from its real `secret scan path` command: its file walk, its
chunking and its `SecretSARIFOutputHandler`, driven in-process by click's test runner
from a uv environment holding `ggshield==1.56.1`. Both files are compact one-line
JSON, as ggshield writes them.

## What is real and what is stubbed

A scan needs a GitGuardian API key, which this capture did not use. Two calls into
the `pygitguardian` HTTP client were replaced; nothing else was:

* the key check (`check_client_api_key`, `GGClient.read_metadata`) returns success;
* `GGClient.multi_content_scan`, the call that sends file content to the service,
  returns one policy break for any file holding a fixed marker string, with the
  `apikey` match type and the span of the marker, and none for any other file.

So the detector name (`Generic High Entropy Secret`), the match type and the span are
a stand-in for what the service would answer, and the hash in
`partialFingerprints["secret/v1"]` is ggshield's own hash over that fabricated match.
Everything the SARIF writer does with them is real: the field set, the 1-based
regions, the `file://` URI form, the `relatedLocations`, the empty `results` list when
nothing is found, and the exit codes below. A capture against the live service would
differ in the detector names and in `extensions[0].version` (here `null`, the
secrets-engine version the stub never learned), not in the shape.

## Argv and the working directory

```text
ggshield --verbose secret scan path --recursive --yes --all-secrets --format=sarif \
  --output=<file> -- <absolute path>
```

(`--verbose` is a top-level option and is not part of what ASH runs.) The positive run
scanned a directory holding `config.py` (a marker on line 2) and `clean.py`; the negative
run scanned `clean.py` alone. Exit status: 1 for the positive run, 0 for the negative
run, the exit code ASH reads.

## Facts the capture settles

* `--output` writes a report when nothing is found: `results` is an empty list, so an
  empty-results report is a clean scan and a missing report is a failure.
* The location URI is `file://` plus the absolute path ggshield was given. The captured
  files hold `file:///work/app/config.py`: the run's directory prefix was replaced with
  `/work` (the only edit made), and the scanner tests rewrite `/work` to the scan path.
* The SARIF carries no `rules` array, no `properties` and no snippet; every result has
  level `error` and one `secret/v1` fingerprint.
* Run without the stubbed key check and with an unusable key, the same command printed
  `Error: Invalid GitGuardian API key.` and exited 3 (`ExitCode.AUTHENTICATION_ERROR`).

## Upstream license

The installed distribution's `ggshield-1.56.1.dist-info/licenses/LICENSE` begins
"MIT License / Copyright (c) 2019 GitGuardian" (sha256
`c6e6d1dbc34c4a7908f1b40fb6b487e946d4db9a7cd9386550f8fc39f2ccbdc4`), and the METADATA
says `License: MIT`.
