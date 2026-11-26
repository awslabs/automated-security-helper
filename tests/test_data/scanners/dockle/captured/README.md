# Captured Dockle output

Real output of Dockle 0.4.15 (the Linux 64-bit release tarball, sha256
`8bfc9183d1d3d67800edb45bea4bb63ddf1d28bec5f89944075a07007d79caad`, matching the
release's own `checksums.txt`), used by
`tests/unit/plugin_modules/ash_dockle_plugins/test_dockle_scanner_behavior.py`
(`TestCapturedReports`, and `TestImageScan`, which hands `positive-image.tar` to the
image dispatch) and by the facets register's corpus gate
(`tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`).

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

`../transcripts.json` records both runs (argv, exit code, environment names, and the
digests of the saved image and the SARIF). A re-run of the pinned release over the
committed tarballs reproduces both SARIF files byte for byte. Regenerate these, and
re-record the transcripts, when the pinned Dockle version moves; the freshness gate in
`tests/unit/plugin_conformance/test_the_committed_transcripts_are_sound_and_fresh.py`
fails until they are.
