# Captured Composer 2.11.3 audit output

`composer-2.11.3-vulnerable-abandoned.json` is the document a real `composer audit`
wrote over the committed `composer.json` and `composer.lock` beside it. Captured
2026-11-25 on Amazon Linux 2023 (aarch64) with PHP 8.5.13 (cli) and Composer 2.11.3
(2026-11-24); the composer.phar was the latest-stable download, checked against its
published sha256. The unit tests read the document and lock directly, so they run on
every platform without Composer or PHP. The audit document and `composer.json` are
re-serialized by the repository's pretty-format-json hook (sorted keys, two-space
indent; the parsed content is unchanged, the way the Betterleaks captures are
compacted with `jq -c`); `composer.lock` is byte-identical to what Composer wrote.

Argv, from this directory (the working directory ASH uses), with `COMPOSER_POLICY`
and `COMPOSER_AUDIT_ABANDONED` removed from the environment as the scanner does:

```text
composer audit --locked --format=json --abandoned=report --no-plugins --no-scripts \
  --no-interaction --no-ansi --working-dir=.
```

Exit status was 1: advisories were found (bit 1 of Composer's audit exit code), and
`--abandoned=report` deliberately does not fail the run for the two abandoned
packages, so bit 2 stays clear.

The lock was resolved from `composer.json` with
`composer update --no-install --no-plugins --no-scripts --no-interaction --no-ansi`.
`config.platform.php` is pinned to 7.4.0 so resolution does not depend on the host's
PHP. `config.policy.advisories.block` is false because Composer 2.11's default
resolution policy refuses to lock an advisory-affected version at all (naming the six
advisory ids below); that policy gates resolution only and silences nothing in the
audit, which the six advisories in the captured document show.

What the document holds:

* `guzzlehttp/psr7` 1.8.3: six advisories, all rated medium by Packagist at capture
  time, each carrying a CVE. The two long-published ones the fixture was built
  around: `PKSA-gvzg-s447-b5b5` is CVE-2022-24775 (GHSA-q7rv-6hp3-vh96, fixed in
  1.8.4) and `PKSA-hn62-zkx4-1y5q` is CVE-2023-29197 (GHSA-wxmh-65f7-jcvw, fixed in
  1.9.1). A re-capture may see more advisories than six if Packagist publishes more;
  the committed document is frozen and the fixture test pins its contents.
* `abandoned`: `zendframework/zend-stdlib` maps to its suggested replacement
  `laminas/laminas-stdlib`, and `fzaninotto/faker` maps to null (no replacement
  suggested), covering both abandoned message shapes.
* Two Composer 2.11 top-level keys the earlier modeled fixture did not have:
  `cooldown` and `filter` (both empty arrays here). The parser tolerates them as
  unknown keys.

`audit.sarif` is the SARIF the adapter produces from this document and lock
(`parse_audit_document` then `convert_audit_document` with `uri="composer.lock"`,
rules sorted by id under a `Composer Audit` driver, serialized with
`json.dumps(..., indent=2, sort_keys=True)`), kept for the scanner SARIF corpus.
Regenerate it after any adapter change by re-running that conversion over these two
committed inputs.
