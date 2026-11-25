# Captured bundler-audit 0.9.3 output

`positive.json` and `negative.json` are the JSON reports the real tool wrote.
`positive.sarif` and `negative.sarif` are what `convert_bundler_audit_report` makes of
them (`json.dumps(indent=2)`), so the facets corpus gate reads the same SARIF the scanner
hands the pipeline. `positive.Gemfile.lock` is the lockfile the positive run read.

Tool: bundler-audit 0.9.3 (`gem install bundler-audit -v 0.9.3`, RubyGems 3.4.19, Ruby
3.2.8, linux/x86_64), advisory database ruby-advisory-db at commit
`c87703e7f2c64f8745ce032711308a17d10cda55` (2026-11-22), both read on 2026-11-25.

Argv, as ASH assembles it (`--update` was left off for the two small captures; the
database had been cloned by an earlier `--update` run in the same HOME):

```text
bundler-audit check --format=json --quiet --output=<file> --config=<file holding "ignore: []"> \
  --gemfile-lock=Gemfile.lock -- <directory holding the Gemfile.lock>
```

Inputs:

* positive: `positive.Gemfile.lock` (rexml 3.2.4, thor 0.19.0 and a `git://` gem source).
  Exit status 1, seven results of type `unpatched_gem` (all rexml, two `high`, five
  `medium`) and one `insecure_source`. thor 0.19.0 matches no advisory.
* negative: a lockfile with only `rake (13.2.1)`. Exit status 0, `"results":[]`.

Edits to the raw output: the advisory `path` field held the capture host's home
directory and is rewritten to `/home/user/...` (the scanner never copies it). The
`created_at` value is as the tool wrote it. The repository's `pretty-format-json` hook
then re-indented the two JSON files and sorted their keys; no value changed.

What the captures show that the adapter relies on: a finding run exits 1 and writes the
report, a clean run exits 0 and writes `results: []`; an advisory with no CVSS score
carries `criticality: null` (none appears in these two inputs; the unscored rating is
tested over a hand-built result); `cvss_v3` is a number and `cvss_v2` is null for every
advisory here.
