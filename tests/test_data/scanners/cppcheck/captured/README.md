# Captured Cppcheck 2.17.1 output

`positive.sarif` and `negative.sarif` are the SARIF a real Cppcheck 2.17.1 wrote, with its
bytes unchanged apart from being compacted to one line (including the `\/` escapes its JSON
writer emits). The unit tests serve them from a fake subprocess, so they run on every
platform without the binary.

The binary was built from the GitHub source tag `2.17.1` (tarball sha256
`bfd681868248ec03855ca7c2aea7bcb1f39b8b18860d76aec805a92a967b966c`) with
`make CXXFLAGS="-O0" cppcheck` on linux/amd64; `cppcheck --version` printed `Cppcheck 2.17.1`.

Argv, from the directory of each input (the working directory ASH uses):

```text
cppcheck --output-format=sarif --output-file=<file> --error-exitcode=2 \
  --enable=warning,style,performance,portability --quiet .
```

Inputs: `bad.c` (an out-of-bounds write `buf[10]` into `char buf[4]`, a `malloc` that is never
freed, and an unused static function) for the positive run, and a four-line `good.c` holding
one `add` function for the negative run. Exit status was 2 for the positive run and 0 for the
negative one.

Facts the captures show and the scanner relies on:

- Every result's `level` is `warning`, including `memleak` and `arrayIndexOutOfBounds`, which
  Cppcheck rates `error` natively: its writer maps the error and warning severities to the
  SARIF level `warning` and everything else to `note`. The level alone therefore never
  yields HIGH.
- The security-relevant rules carry `properties.security-severity` of `9.9` on their entry in
  `tool.driver.rules` (with the tag `security`); `unreadVariable` carries none. The scanner
  reads that number to rate a finding HIGH.
- `artifactLocation.uri` is relative to the working directory with no `./` prefix.
- `driver.semanticVersion` is the Cppcheck version.
