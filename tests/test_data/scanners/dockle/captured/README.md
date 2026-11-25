# Captured Dockle output

Real output of Dockle 0.4.15 (the Linux 64-bit release tarball, sha256
`8bfc9183d1d3d67800edb45bea4bb63ddf1d28bec5f89944075a07007d79caad`, matching the
release's own `checksums.txt`), used by
`tests/unit/plugin_modules/ash_dockle_plugins/test_dockle_scanner_behavior.py`
(`TestCapturedReports`).

Each SARIF file is the output of the argv `DockleScanner` builds for a saved image,
run on Linux with no Docker daemon and no network:

| File | Input | Command |
| --- | --- | --- |
| `positive.sarif` | `positive-image.tar` | `dockle --format=sarif --output=positive.sarif --no-color --input=positive-image.tar` |
| `negative.sarif` | `negative-image.tar` | the same, with `negative-image.tar` |

The two tarballs are built by `build_fixture_image.py` (`python3 -I
build_fixture_image.py <dir>`) in `docker save` format. Every value in them is a
placeholder. The positive image runs as root, holds an `etc/shadow` with an empty
password, a file named `id_rsa` and a `DB_PASSWORD` variable, and so produces all four
SARIF levels (`error`, `warning`, `note`, `none`). The negative image has a non-root
user and one ordinary file; Dockle still reports two `note` results (no content trust,
no HEALTHCHECK) that no image built this way can avoid, so "negative" means no `error`
and no `warning`.

Regenerate these when the pinned Dockle version moves.
