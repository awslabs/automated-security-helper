# DevSkim captured output

Real output of `devskim analyze` 1.0.103 (`devskim --version`: `devskim 1.0.103+7f8e5e24f6`),
the net8.0 build of the `Microsoft.CST.DevSkim.CLI` 1.0.103 package (SHA256
`ea8c70cca113563919909b64534b6d50f97af4b2941e1ea4bb434db7890a28af`, the pin in
`ash_devskim_plugins/devskim_install.py`), run on 2026-11-26 on linux/amd64 with the .NET
10.0.15 runtime, from inside each input directory, with the argv ASH uses:

```
dotnet --roll-forward Major devskim.dll analyze --source-code=. \
  --output-file=positive.sarif --file-format=sarif --disable-supression      # in in/pos
dotnet --roll-forward Major devskim.dll analyze --source-code=. \
  --output-file=negative.sarif --file-format=sarif --disable-supression      # in in/neg
```

Both runs exited 0 and wrote nothing to standard output or standard error. The two SARIF
files are the bytes DevSkim wrote (`positive.sarif` SHA256
`a28df261c7649f66c19942acc235331ff3fc36ef031ece544b2095d3cdf393de`, `negative.sarif`
`0e4b231176f2c03b07e73251e5deb099c46bda6a6629fd7c0fccdc68de33c64c`); nothing in them was
replaced, since DevSkim writes relative paths and no invocation, time or host.

| File | What it is |
|---|---|
| `in/pos/` | The input: `copy.c` (`strcpy`, `strlen`), `hashing.py` (two `hashlib.md5` calls, the second with a `# DevSkim: ignore DS126858` comment), `notes.py` (a `TODO` comment), `request.js` (a plain-HTTP URL and `eval`). |
| `positive.sarif` | DevSkim's report for it: 7 results, one or more for each of DevSkim's five severities (Critical DS126858 twice, Important DS185832, Moderate DS137138, BestPractice DS140021, ManualReview DS176209 and DS189424). |
| `in/neg/clean.py` | The input: a function with nothing DevSkim flags. |
| `negative.sarif` | DevSkim's report for it: no results and no rules. |

What the captures show, and the scanner relies on:

- the result `level` is `error` for Critical and Important, `warning` for Moderate and
  `note` for BestPractice and ManualReview, and the result property `DevSkimSeverity`
  names the severity exactly;
- every result has a region with start and end line and column and a `snippet`, a
  `tags` list and `DevSkimConfidence`; five of the seven carry `fixes`; none carries a
  fingerprint;
- every rule carries a `helpUri` (its guidance page) and a `help` text; no rule or
  result names a CWE.

Run the same way without `--disable-supression`, DevSkim reported 6 results: the
`hashing.py` line with the `DevSkim: ignore` comment was missing, so DevSkim honors its
inline comments by default and the flag ASH passes turns them off. That run is not
committed.

A second run of the same argv, through the `devskim` launcher that the module's installer
(`install_devskim`, which downloaded and verified the pinned package) wrote, gave
`negative.sarif` byte for byte and a `positive.sarif` of the same size with the same seven
results in the same order and the same six rules in a different order. DevSkim does not
keep the order of `tool.driver.rules` from one run to the next, so compare a re-capture by
content, not by bytes.

Both SARIF files are the corpus the facets register's consistency gate reads. Re-capture
them with the argv above when the pinned version changes.
