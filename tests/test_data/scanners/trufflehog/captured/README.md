# Captured TruffleHog 3.100.0 output

`positive.sarif` and `negative.sarif` are the SARIF TruffleHog 3.100.0 (the
darwin/arm64 release asset, checked against the release's checksums file) wrote to
stdout, compacted to one line (`jq -c .`). The unit tests serve them from a fake
subprocess, so they run on every platform without the binary.

Argv, from the directory of each input (the working directory ASH uses):

```text
trufflehog filesystem --sarif --no-update --no-color --fail-on-scan-errors \
  --no-verification --no-ignore-tag --exclude-paths=<file> -- .
```

The exclusion file held the one pattern ASH writes, `(^|[/\\])\.git([/\\]|$)`.

The positive input was three files holding one fabricated GitHub token each and one
clean file:

- `src/app.py`, line 4: an assignment.
- `src/services/settings.py`, line 3: an assignment followed by a
  `trufflehog:ignore` comment. It is reported because of `trufflehog --no-ignore-tag`.
- `src/remote.cfg`, line 2: the token as the password of an `https://` URL. Both
  the `Github` and the generic `URI` detector report it.

The tokens were random and are not kept: TruffleHog's SARIF does not hold the
secret, which is what these tests assert on. The `trufflehogFingerprint/v1` of each
result is a SHA-256 over the detector, the path, the line and a SHA-256 of the
secret. Exit status was 0 for both runs.
