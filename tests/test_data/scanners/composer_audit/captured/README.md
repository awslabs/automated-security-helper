# Captured Composer 2.11.3 audit output

`composer-2.11.3-vulnerable-abandoned.json` is the document a real `composer audit`
wrote over the project committed beside it as `composer.json.capture` and
`composer.lock.capture`. Captured 2026-11-25 on Amazon Linux 2023 (aarch64) with PHP
8.5.13 (cli) and Composer 2.11.3 (2026-11-24); the composer.phar was the latest-stable
download, checked against its published sha256 (Composer publishes
`04f8b003da4e3a2459056591fbfebd02b4dc3e5adeb158616b90cf55a65113ec` for the 2.11.3 phar,
the digest `ash_composer_audit_plugins/composer_install.py` pins). The unit tests read
the document and lock directly, so they run on every platform without Composer or PHP.
The audit document and the manifest are re-serialized by the repository's
pretty-format-json hook (sorted keys, two-space indent; the parsed content is
unchanged, the way the Betterleaks captures are compacted with `jq -c`); the lock is
byte-identical to what Composer wrote.

The two project files carry a `.capture` suffix so that GitHub's dependency graph,
which reads files named exactly `composer.json` and `composer.lock`, does not take a
pinned, known-vulnerable fixture for this repository's own dependencies (no Dependabot
alert and no update pull request against it; an update would quietly invalidate the
frozen capture). To capture again, copy them into an empty directory under their plain
names.

Argv, from that directory (the working directory ASH uses), with `COMPOSER_POLICY`
and `COMPOSER_AUDIT_ABANDONED` removed from the environment as the scanner does:

```text
composer audit --locked --format=json --abandoned=report --no-plugins --no-scripts \
  --no-interaction --no-ansi --working-dir=.
```

Exit status was 1. At 2.11.3, `Auditor::audit` returns 0 or 1, and 1 means a policy
whose audit mode is `fail` matched: here the six advisories (the advisories audit fails
by default). `composer audit --abandoned=report` keeps the two abandoned packages from
counting.

The lock was resolved from the manifest with
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
* `filter` and `cooldown`, both empty here (`[]`, PHP's empty map). Read in Composer
  2.11.3's `Advisory/Auditor.php`: `filter` maps a package to the filter-list entries
  its locked version matches (`packageName`, `listName`, `constraint`, `url`, `reason`,
  `id`, `source`); the `malware` list is audited, and fails the audit, by default, and
  the scanner reports each entry. `cooldown` maps a package to the release dates of a
  locked version still inside a `policy.cooldown` period the project configured
  (audited only when the project asks); the scanner does not report it. Neither key
  hides an advisory: advisories a project ignores move to `ignored-advisories`.

`audit.sarif` is the SARIF the adapter produces from this document and lock
(`parse_audit_document` then `convert_audit_document` with `uri="composer.lock"`,
rules sorted by id under a `Composer Audit` driver, each model dumped as the scanner
dumps its report, serialized with `json.dumps(..., indent=2, sort_keys=True)` and a
final newline), kept for the scanner SARIF corpus. `rebuild_audit_sarif()` in
`tests/unit/plugin_modules/ash_composer_audit_plugins/test_composer_audit_fixture_report.py`
builds that text and a test there compares it with the committed file, so an adapter
change that moves the output fails until the file is regenerated from that function.

`../transcripts.json` indexes this capture for the plugin conformance gate: one attested
transcript carrying the argv and exit status above and the digests of the document and
of the two project files. The harness reads it through the `composer-audit` adapter prep
(`core/plugin_conformance.py`), which converts the document with the lock the
transcript's fixture tree names, as the scanner converts Composer's stdout. Editing any
of those three files means writing their new digests into the transcript.
