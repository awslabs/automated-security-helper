# OpenSSF Scorecard captured output

Real output of `scorecard` v5.7.0 (linux/amd64, release archive SHA256
`3b08ec0a8681806c3e744ec9210742a502c7d66f06f25523b70f7128738235d3`, executable SHA256
`9b2868dec1ca9f9c32fda97caeb7f3aba28bc74c1f982bd222f16749fe4b9211`), run on 2026-11-26
from the directory that holds `in/`, with no GitHub token in the environment and every
proxy variable pointed at a port that refuses connections:

<!-- doctest: illustrative reason="runs the scorecard binary, which this repository does not install" -->
```bash
scorecard --local=in/pos --format=json --show-details \
  --checks=Binary-Artifacts,Dangerous-Workflow,Dependency-Update-Tool,License,Pinned-Dependencies,Security-Policy,Token-Permissions \
  > positive.json
scorecard --local=in/pos --format=json --show-details > check-error.json
```

Why `scorecard --local` and not the plugin's `scorecard --repo`: a repository run reads
the hosted repository through the GitHub API and needs a token.
`scorecard --format=json --show-details` prints the same document either way
(`JSONScorecardResultV2`); a local run holds only the file-based checks, and its `repo`
reads `file://in/pos` with commit `unknown` where a repository run names the repository
and its commit. The converter does not read `repo`: the scanner passes the repository it
scored.

| File | What it is |
|---|---|
| `in/pos/` | The input: a workflow with read permissions at the top level and `security-events: write` on its job, one action pinned by commit and one by tag, and a `pip install` by name; a security policy with a link and no disclosure wording; no license file and no dependency-update configuration. |
| `positive.json` | Scorecard's report for the seven file-based checks (exit 0, nothing on stderr): Dependency-Update-Tool 0, License 0, Pinned-Dependencies 3 and Security-Policy 9, the rest 10. Re-serialized by the repository's JSON formatter (two-space indent, sorted keys); no value changed. |
| `check-error.json` | Scorecard's report for every default check of a local run, over the same input: exit 1. Fuzzing could not reach the network, so it is -1 with the refused connection as its reason, and Scorecard printed the whole document on stdout and `Error: one or more checks failed during execution` on stderr. Re-serialized the same way. |
| `positive.sarif` | What `convert_scorecard_result` writes for `positive.json` with `repo="github.com/example-org/example-repo"`, serialized as the scanner writes its results file and re-serialized by the JSON formatter. The test `test_the_committed_sarif_is_what_the_converter_writes` fails when the converter's output and this file differ. |

The SARIF file is the corpus the facets register's consistency gate reads.
