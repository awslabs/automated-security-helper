# Saved-image fixture

`secret-image.tar` is a tiny `docker save` archive built from nothing: one
gzip-compressed layer holding `app/creds.txt` with a fake GitHub token, a config
naming the uncompressed layer's diff id, and a `manifest.json`. No image was
pulled to make it and none is needed to use it. The layer is compressed so the
token's text is not in the committed bytes, which a repository secret scan would
otherwise report.

| File | sha256 |
|---|---|
| `secret-image.tar` | `aa302850a04b138bc2c9f7a3c0f8a303cea61b0ec02199a941bff4f308929c7b` |

Every mtime is 0 and every owner is root. The deflate output is whatever the
building zlib writes, so the digest pins this committed file, and the builder is
checked by what the archive decompresses to. To rebuild it and read the new digest:

<!-- doctest: illustrative reason="rewrites this repository's committed fixture with a script from its tests/utils directory, so it needs a checkout of this repository" -->
```bash
python3 -I -B tests/utils/image_archive_fixture.py tests/test_data/images/secret-image.tar
```

A unit test checks the committed file against the digest here, and the builder's
output against the committed archive member by member, so a change to either that
is not matched by the other fails. The integration test that scans it with the
real trivy is
`tests/integration/scanners/test_image_archive_real_scan.py`; the layout
re-pack of it is covered by `tests/unit/utils/test_oci_layout_archive.py`.
