# Source-archive fixtures

Three zip files that real zip writers made from one small tree. Most archives in the
source-archive tests are built with `zipfile` or byte by byte, which gives only the
layouts their author thought of. These are what `git archive` and Info-ZIP's `zip`
write, so the rules in `automated_security_helper/utils/source_archive.py` are also
held to the archives people hand to `ash scan fs --archive` and to the MCP source-zip
finalize.

Both entry points have to extract each file into the tree below.
`tests/unit/utils/test_source_archive.py` pins that tree member by member (the
`ADMITTED` rows named after each writer) and checks that each file still has the layout
described here (`TestTheWritersArchivesAreWhatTheirReadmeSays`).

| File | Writer | Layout |
|---|---|---|
| `git-archive.zip` | git 2.50.1, `git archive --format=zip HEAD` | 13 members. CRC-32 and sizes in every local header, no data descriptors. A 40-byte archive comment holding the commit id. An extended-timestamp extra field and nothing else. Stored where deflate does not shrink a file (`bin/run.sh`, `data/blob.bin`, the empty `__init__.py`). No `empty/` directory, since git tracks none. |
| `info-zip-file.zip` | Zip 3.0, `zip -X`, written to a file | 14 members. Zip goes back to each local header when its output can be sought, so CRC-32 and sizes are in the headers and there are no data descriptors. No extra fields. Stored where deflate does not shrink a file. |
| `info-zip-pipe.zip` | Zip 3.0, `zip -X`, written to a pipe | 14 members. The output cannot be sought, so every file member (the empty one too) is followed by a data descriptor with its signature and four-byte sizes, and its local header gives the size but a zero CRC-32 and compressed size. No extra fields. Every non-empty file is deflated, `data/blob.bin` included, which grows from 256 to 261 bytes. |

## The tree

| Path | Bytes | Note |
|---|---|---|
| `README.md` | 135 | text |
| `app/main.py` | 358 | text |
| `app/util/__init__.py` | 0 | empty file |
| `app/util/helpers.py` | 211 | text |
| `bin/run.sh` | 62 | text, mode 755 |
| `data/blob.bin` | 256 | eight SHA-256 digests, which no writer can shrink |
| `data/repeated.txt` | 85,000 | one 17-byte line 5,000 times, which deflates to 243 bytes and takes two steps of output to inflate |
| `docs/guide.md` | 291 | text |
| `empty/` | | an empty directory (Info-ZIP archives only) |

The bytes of every text file are `_FIXTURE_TREE` in the test module; change the tree
and that dictionary together.

## How they were made

In a scratch directory outside the repository, holding the tree above with every file
and directory dated 2026-01-02 03:04:06 (`touch -d '2026-01-02 03:04:06'`, on a host
whose time zone was UTC), so that every member reads 03:04:06 in all three archives:
Info-ZIP records the file's time, and git archive stamps each member with its commit's
time, which was set to the same instant.

```bash
python3 -I -B -c 'import hashlib, sys; sys.stdout.buffer.write(b"".join(hashlib.sha256(bytes([i])).digest() for i in range(8)))' > data/blob.bin
python3 -I -B -c 'import sys; sys.stdout.buffer.write(b"0123456789abcdef\n" * 5000)' > data/repeated.txt

# From the tree's root. The -x options only matter when the tree is also the git work
# tree, as it was here.
zip -X -r -q ../info-zip-file.zip . -x '.git' -x '.git/*'
zip -X -r -q - . -x '.git' -x '.git/*' | cat > ../info-zip-pipe.zip

# After committing the tree once, with author and committer dates 2026-01-02T03:04:06Z:
git archive --format=zip -o ../git-archive.zip HEAD
```

Plain `zip` also writes an extended-timestamp field and a Unix owner field into every
header, and the owner field is the numeric user and group id of the account that ran
it. `-X` leaves both out, so the two Info-ZIP archives carry no account ids.

Tool versions: git 2.50.1, Zip 3.0 (July 5th 2008) and UnZip 6.00 for the checks
(`unzip -tq`, and `diff -r` of an extraction against the tree). The files are bytes in
the repository so that the tests need neither `zip` nor a particular version of git,
and a fixed byte string keeps what a row means from changing with the tool.

## Limits

- Writing the archives again with other versions of the tools can change bytes and
  layout details. What has to stay true is what the tests above say, not these exact
  bytes.
- git writes a data descriptor only for a blob larger than `core.bigFileThreshold`
  (512 MiB by default), so no file here has one from git. `git -c
  core.bigFileThreshold=200 archive --format=zip HEAD` on the same commit would give
  one to every file over 200 bytes. The Info-ZIP pipe archive is the data-descriptor
  layout from a real writer.
- None of the three holds a symbolic link, a name outside ASCII, a zip64 record, an
  encrypted member, a member in a method other than stored and deflated, or an extra
  field besides the extended timestamp in `git-archive.zip`. The rows built in the test
  module cover those.
