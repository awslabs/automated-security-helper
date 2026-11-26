# Captured YARA-X 1.23.0 output

`positive.ndjson` is the standard output `yr` 1.23.0 wrote for the command below, and
`negative.ndjson` is what the same command wrote over a tree with no match: nothing,
with exit status 0. The unit tests serve both from a fake subprocess, so they run on
every platform without the binary.

Both were re-captured on 2026-11-26 with the release binary ASH pins (the linux/x86_64
archive, SHA256
`da0c17f23fc743dcd44ad6d3135c906a4c0d197685b661c4cdc923c2f8967a64`; `yr --version`
prints `yara-x-cli 1.23.0`). The standard output of both runs is byte-identical to the
files committed here, and both runs exited 0.

Argv, run from the scanned directory (the working directory ASH uses):

```text
yr scan --output-format=ndjson --print-meta --print-tags --disable-console-logs \
  --recursive -- rules .
```

Inputs: a tree holding `src/a.txt` (the word `hello`) and `b.txt` (the word `clean`),
with the rules directory `rules/` inside it. The tree for the negative run holds only
`b.txt` and `rules/`. `rules/rules.yar` holds two rules that both match `src/a.txt`:

```text
rule demo_marker : sample {
    meta:
        severity = "high"
        description = "demo marker"
    strings:
        $a = { 68 65 6C 6C 6F }
    condition:
        $a
}

rule no_sev {
    strings:
        $a = { 68 65 6C 6C 6F }
    condition:
        $a
}
```

The rule file spells `hello` as a hex pattern, so it does not match itself. The
compiler prints a `text_as_hex` warning for each rule on standard error, which
`yr scan --disable-console-logs` does not silence; standard output holds only the
results.

| File | What it is |
|---|---|
| `positive.ndjson` | `yr`'s standard output for the tree holding `src/a.txt`: one line. |
| `negative.ndjson` | `yr`'s standard output for the tree without it: empty. |
| `positive.sarif` | What `convert_ndjson` writes for `positive.ndjson` with no tool version, in two-space indent with sorted keys. The test `test_the_committed_sarif_is_what_the_converter_writes` compares the two. |
| `../transcripts.json` | The recording of the positive run: its argv, exit status, tool version and the SHA256 of `positive.sarif` and `positive.ndjson`. |

The SARIF file is the corpus the facets register's consistency gate reads, both through
the corpus table and through the transcript.

Facts the captures show and the scanner relies on:

- One JSON object per file that matched at least one rule. A file that matched nothing
  prints nothing, so a clean scan has an empty standard output.
- `meta` is a list of `[key, value]` pairs, not an object.
- The reported path is `./`-prefixed relative to the working directory.
- `yr scan --print-strings` is never passed, so the output holds no matched bytes and no
  match offsets.

A `yr` upgrade needs a fresh capture before the new version is trusted.

The tree holds no secrets: the file contents are the words `hello` and `clean`.
