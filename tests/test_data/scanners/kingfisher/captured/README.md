# Captured Kingfisher 2.19.1 output

`positive.sarif` and `negative.sarif` are the SARIF Kingfisher 2.19.1 wrote for a
directory holding one fabricated GitHub token in `creds.txt` (positive) and for a clean
directory (negative), run from inside the directory with the argv ASH uses:

```text
kingfisher scan --no-validate --no-update-check --quiet --redact --no-ignore \
  --git-history=none --format=sarif --output=<file> -- .
```

Only the scanned directory's absolute path, the run id and the timings are replaced
(`/scanned/dir`, an all-zero run id); the snippet is Kingfisher's own `--redact`
output, `[REDACTED:<hash>]`, so no secret is in either file. Both files hold the same
bytes the unit tests used to carry inline; they were moved here so the facets register
can read them as its corpus.

What the captures show, and the scanner relies on:

- every result's SARIF `level` is `error` and its `kind` is `review`; ASH rewrites both
  (see "Severity" in the scanner's module docstring);
- locations are written with a leading `./`, which the scanner removes;
- `partialFingerprints.fingerprint` is a non-empty decimal string;
- the run's `properties` hold a repository audit naming the scanned directory, which
  the scanner drops.

The tool was not re-run when these files were moved; re-capture them with the argv
above when the pinned version changes.
