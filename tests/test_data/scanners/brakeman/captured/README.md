# Captured Brakeman 8.1.1 output

`positive.sarif` and `negative.sarif` are the SARIF Brakeman 8.1.1 (the gem, installed
with `gem install brakeman` on Ruby 3.2) wrote, compacted to one line (`jq -c .`). The
unit tests serve them from a fake subprocess, so they run on every platform without Ruby
or the gem. Brakeman is not redistributed: only its output is committed here.

Argv, from the root of each input (the working directory ASH uses), with the same two
empty configuration files ASH writes outside the tree:

```text
brakeman --format=sarif --output=<file> --no-pager --quiet --no-progress \
  --config-file=<file holding "{}"> \
  --ignore-config=<file holding {"ignored_warnings": [], "brakeman_version": ""}> \
  --path=.
```

The positive input is one controller, `app/controllers/users_controller.rb`:
`User.where("name = '#{params[:name]}'")` on line 3, `system("tar czf ... #{params[:dir]}")`
on line 7 and `redirect_to params[:next]` on line 8. It yielded three results,
`BRAKE0014` (command injection, `error`, line 7), `BRAKE0018` (redirect, `error`, line 8)
and `BRAKE0000` (SQL injection, `warning`, line 3), with exit status 3. The negative input
holds the same controller with a hash-form `where` and nothing else; it yielded no results
and exit status 0. A tree with no top-level `app` directory exits 4 and writes no report
(`Please supply the path to a Rails application`), which the scanner reads as nothing to
scan.

What the captures show and the scanner relies on:

* A result has `ruleId`, `ruleIndex`, `level`, `message.text` and one location whose
  region is `startLine` only: no `endLine`, no column, no snippet, no fingerprints.
* The level is Brakeman's confidence: high is `error`, medium `warning`. No weak (`note`)
  result was produced by these inputs; the `note` row of the severity mapping is tested
  over the positive capture with the level replaced, not over a captured `note`.
* Rules carry `helpUri`, a `help` link and `properties.tags` naming the warning family
  (`Execute`, `Redirect`, `SQL`). They carry no CWE and no security-severity.
* The driver's `semanticVersion` is the release, `8.1.1`.
