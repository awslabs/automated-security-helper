# Captured YARA-X 1.23.0 output

`positive.ndjson` is the standard output `yr` 1.23.0 (the release binary; `yr
--version` prints `yara-x-cli 1.23.0`) wrote for the command below. `negative.ndjson`
is what the same command wrote over a tree with no match: nothing, with exit status 0.
The unit tests serve both from a fake subprocess, so they run on every platform without
the binary.

Argv, run from the source directory (the working directory ASH uses):

```text
yr scan --output-format=ndjson --print-meta --print-tags --disable-console-logs \
  --recursive -- rules .
```

Inputs: a tree holding `src/a.txt` and `b.txt`, and a rules directory holding two rules
that both match `src/a.txt`. The first rule has `meta: severity = "high"` and
`description = "demo marker"` and the tag `sample`; the second has no metadata and no
tag. In the positive capture they are `demo_marker` and `no_sev`.

Facts the captures show and the scanner relies on:

- One JSON object per file that matched at least one rule. A file that matched nothing
  prints nothing, so a clean scan has an empty standard output.
- `meta` is a list of `[key, value]` pairs, not an object.
- The reported path is `./`-prefixed relative to the working directory.
- `--print-strings` is never passed, so the output holds no matched bytes and no match
  offsets.

The tree holds no secrets: the file contents are the words `hello` and `clean`.
