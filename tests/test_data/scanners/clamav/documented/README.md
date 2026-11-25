# ClamAV `clamscan --log` fixtures (documented format, not captured)

`positive.log` and `negative.log` are written from ClamAV's own source and manual
(`clamscan/manager.c` for the `<path>: <signature> FOUND`, `<path>: OK` and
`<path>: <message> ERROR` lines, `clamscan/clamscan.c` for the SCAN SUMMARY block,
`docs/man/clamscan.1.in` for the flags and exit codes). They were NOT produced by a
`clamscan` binary: no ClamAV install exists on the hosts this module was built on,
and the signature database is a separate download. The directory is named
`documented` for that reason; it is not `captured`.

The unit tests serve them from a fake subprocess that writes the file where
`--log=` says, so they run on every platform without the binary.

Argv ASH uses, run from the scan directory:

```text
clamscan --recursive --follow-dir-symlinks=0 --follow-file-symlinks=0 --log=<file> .
```

Contents:

- `positive.log`: two detections (the second path itself contains `: `), one clean
  file, and a summary whose `Infected files: 2` agrees with them. Exit status 1.
- `negative.log`: two clean files and `Infected files: 0`. Exit status 0.

To replace these with a real capture, run the argv above on a directory holding the
EICAR test string (the standard, harmless anti-virus test file) with a freshclam
database installed, and keep the log as `positive.log`.
