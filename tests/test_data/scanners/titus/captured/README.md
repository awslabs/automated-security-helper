# Captured Titus reports

Both files are reports Titus printed on stdout for the invocation ASH uses:

```text
titus scan --format=sarif --output=:memory: --accessibility=private --context-lines=0 -- .
```

- Tool: Titus v1.3.0, release asset `titus-linux-amd64`, sha256
  `74c665b8222501793e9399052c4c4b6ffb3ecee1cd83a78950c759b2112fdabc` (equal to the
  line in the release's `checksums.txt`). Exit status 0 for both runs.
- Run on 2026-11-25 on linux/amd64, `env -i` with a scratch HOME, over a scratch tree.
- `positive.sarif`: a tree of four small files with three synthetic secret-shaped
  strings (a generic key line, a Slack bot token shape, a GitHub token shape). Titus
  reported all three; the AWS documentation example key pair in the same tree was
  reported only as a generic key.
- `negative.sarif`: a tree with one file, `print(1)`. Zero results.

Edits made to the capture, and nothing else:

1. `tool.driver.rules` is cut to the rules the results name (Titus lists all 502 of
   its rules in every report, about 160 KB); `negative.sarif` therefore has none.
2. Each `region.snippet.text`, which Titus fills with the matched text, is replaced
   with `FIXTURE-PLACEHOLDER-FOR-MATCHED-TEXT`, so no token-shaped string is
   committed. ASH replaces the real text with `REDACTED` either way.
3. Each `properties.absolute_path`, which held the scratch tree's absolute path, is
   replaced with `/lane/src/<uri>`.

What the capture shows that the earlier hand-written fixture did not: results carry
`properties.titus_score` and `properties.absolute_path` beside `security-severity`; a
rule can carry `helpUri` and a non-empty `shortDescription`; the driver version is
`0.1.0`.
