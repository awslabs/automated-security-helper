# Captured Secretlint 14.0.1 output

`positive.sarif` and `negative.sarif` are the SARIF the pinned Secretlint
(`secretlint@14.0.1` with `@secretlint/secretlint-formatter-sarif@14.0.1`, both from the
npm registry, Node.js v22.23.3) wrote, byte for byte as the tool produced them. The unit
tests serve them from a fake subprocess, so they run on every platform without Node.js.

Argv, from the directory of each input (the working directory ASH uses):

```text
secretlint --format=@secretlint/secretlint-formatter-sarif --output=<file> \
  --secretlintrcJSON={"rules":[{"id":"@secretlint/secretlint-rule-preset-recommend"}]} \
  --no-gitignore --no-color --no-terminalLink **/*
```

The positive input was one file, `app.yml`, holding one fabricated GitHub token on line 1
(`token: ghp_` plus 36 characters). A second file with the AWS documentation example key
pair produced no result: the AWS rule skips the documented example values. The negative
input was one file with the text `hello world`. Exit status was 0 for both runs, the
positive one included, because `--output` is given.

Facts the captures show and the scanner relies on:

- The message masks the secret (`found GitHub Token(*****...): ****...`), so the report
  holds no secret value.
- The driver's `version` is the constant `1.0.0` (not the tool's version), which the
  scanner drops.
- The rule id is `<preset> > <rule package>`, the result level is `error`, and the
  report has no `partialFingerprints` and no `region.snippet`.
- The rule entry carries a `helpUri` to the rule documentation.
