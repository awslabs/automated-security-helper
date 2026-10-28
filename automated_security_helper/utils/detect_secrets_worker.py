"""Run one detect-secrets scan in its own process and write the collection as JSON.

The detect-secrets scanner used to call ``SecretsCollection.scan_files`` inside the
ASH process, where no OS sandbox can reach it. It now starts this module as a
subprocess through ASH's spawn helpers, so ``--sandbox`` wraps it like any other
scanner tool. The work done here is exactly what the scanner did in-process, in the
same order: load the baseline (when there is one), set ``root``, then scan the file
list under ``transient_settings``.

Usage: ``python -m automated_security_helper.utils.detect_secrets_worker REQUEST OUTPUT``

REQUEST is a JSON file with ``root`` (str), ``baseline`` (the parsed baseline document,
or null), ``settings`` (the dict handed to ``transient_settings``), ``paths`` (the
absolute file names to scan) and ``verify`` (whether candidate secrets may be sent to
their issuers; missing means no). The file list goes in a file rather than on the
command line because a large repository's list exceeds the Windows command-line limit.

Unless ``verify`` is true, every HTTP request made through ``requests`` fails before
it is sent. The scanner already removes the verification filter from ``settings``
when verification may not run; this also stops a filter or plugin that verifies under
another name. Every detect-secrets plugin's ``verify()`` uses ``requests``, and
detect-secrets reads a failed request as "unverified", so the secret is reported.
``run()`` also sets ``ASH_DETECT_SECRETS_REFUSE_HTTP=1`` in its own environment before
it scans, which this module reads when it runs as the worker or as a pool process: the
processes of a ``spawn`` multiprocessing pool (macOS, Windows) import it again, as
``__mp_main__``, rather than inherit the worker's state, and refuse too. ``run()``
puts the variable back to its previous state (the old value, or absent) once the pool
has shut down. The scanner
sets the same variable when it starts the worker, so the worker's own import refuses
from its first line; a caller that does not set it gets the pool refusal all the same.

OUTPUT is written only on success, as a JSON list of ``[key, [secret, ...]]`` pairs in
the collection's own key order, each secret in ``PotentialSecret.json()`` form. The key
is kept separately from the secret's ``filename`` because they differ: scan_files keys a
multi-file scan by the path relative to ``root`` while the secret keeps the absolute
name.

A secret found by this scan also carries ``ash_start_column``, the 1-based column its
value starts at in its line, when the value is found there. detect-secrets reports no
column, and without one two secrets of one type on one line are indistinguishable to
ASH. The column is worked out here because only this process holds the secret's
value; the value is not written to OUTPUT.

Deliberately imports nothing from ASH beyond ``utils.process_env`` (itself standard
library only, and required so the environment write below lands under
``ENVIRON_LOCK``), the standard library and detect-secrets, so starting it does not
load the plugin registry.
"""

import itertools
import json
import multiprocessing
import os
import sys
from typing import Any, Dict, List, Optional

from automated_security_helper.utils.process_env import (
    apply_environ_overrides,
    restore_environ,
)

#: The key of the column in each secret written to OUTPUT.
START_COLUMN_KEY = "ash_start_column"


def _read_lines(filename: str, count: int) -> Optional[List[str]]:
    """The first *count* lines of *filename*, numbered as detect-secrets numbers them.

    Opened as detect-secrets opens a file it scans, ``open(filename)``: text mode,
    the default encoding and error handling, universal newlines. Iterating the
    handle ends a line only at ``\\n``, ``\\r`` and ``\\r\\n``. Not
    ``str.splitlines``, which also ends one at ``\\v``, ``\\f``, ``\\x1c``-``\\x1e``,
    NEL, U+2028 and U+2029, and so numbers a line below any of them differently
    from detect-secrets. None for a file that cannot be read or decoded.
    """
    try:
        with open(filename) as handle:
            return list(itertools.islice(handle, count))
    except (OSError, UnicodeDecodeError):
        return None


def _start_column(
    secret: Any, lines_by_file: Dict[str, Optional[List[str]]]
) -> Optional[int]:
    """The 1-based column *secret*'s value starts at in its line, or None.

    None for a secret loaded from a baseline (it has no value), for a file that
    cannot be read again, and for a value that is not in its line as written, as
    when a transformer (YAML, INI) rebuilt the line before detect-secrets read it.

    *lines_by_file* holds, for each file, its lines read so far, or None when it
    cannot be read. A file is read only as far as the furthest line asked for,
    and again only for a line beyond that.
    """
    value = getattr(secret, "secret_value", None)
    line_number = getattr(secret, "line_number", 0) or 0
    if not value or line_number < 1:
        return None
    filename = str(secret.filename)
    lines = lines_by_file.get(filename, [])
    if lines is not None and line_number > len(lines):
        lines = _read_lines(filename, line_number)
        lines_by_file[filename] = lines
    if lines is None or line_number > len(lines):
        return None
    index = lines[line_number - 1].find(value)
    return index + 1 if index >= 0 else None


def _with_column(
    secret: Any, lines_by_file: Dict[str, Optional[List[str]]]
) -> Dict[str, Any]:
    record = secret.json()
    column = _start_column(secret, lines_by_file)
    if column is not None:
        record[START_COLUMN_KEY] = column
    return record


def _scan_files(collection: Any, paths: List[str]) -> None:
    """``collection.scan_files(*paths)``, with a lone file scanned at the path given.

    detect-secrets (1.5.0) scans a list of one file through
    ``SecretsCollection.scan_file``, which passes the name through
    ``convert_local_os_path``. On POSIX that rewrites every backslash to a slash,
    and a backslash is an ordinary character in a POSIX file name: a file under
    ``src-C:\\out\\`` was looked for at a path that does not exist, and the scan
    found nothing and said nothing. Two or more files go through its process pool,
    which scans each at the path given. So on POSIX a lone file is scanned here as
    ``scan_file`` scans it, keyed by the name it was handed, without the rewrite. On
    Windows a file name holds neither separator, the rewrite loses nothing, and
    detect-secrets is called as before.
    """
    if len(paths) != 1 or os.sep != "/":
        collection.scan_files(*paths)
        return
    from detect_secrets.core import scan

    filename = paths[0]
    for secret in scan.scan_file(os.path.join(collection.root, filename)):
        collection[filename].add(secret)


#: Set to "1" in the worker's environment when requests are refused; see above.
REFUSE_HTTP_ENV = "ASH_DETECT_SECRETS_REFUSE_HTTP"


def refuse_http_requests() -> None:
    """Make every request sent through ``requests`` fail with ConnectionError.

    This replaces ``requests.adapters.HTTPAdapter.send`` and nothing else. A plugin
    or filter that opens its own socket, or uses another HTTP client, is not
    stopped here. Under --sandbox the network policy bounds those; without a
    sandbox nothing does.
    """
    import requests
    from requests.adapters import HTTPAdapter

    def refuse(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        raise requests.exceptions.ConnectionError(
            "secret verification is off for this scan, so no request is sent to "
            f"{request.url}",
            request=request,
        )

    setattr(HTTPAdapter, "send", refuse)


def run(request: Dict[str, Any]) -> List[List[Any]]:
    from detect_secrets.core.secrets_collection import SecretsCollection
    from detect_secrets.settings import transient_settings

    refusing = request.get("verify") is not True
    previous: Dict[str, Optional[str]] = {}
    if refusing:
        # Set before scan_files so that spawned pool processes, which import this
        # module again and inherit the environment, read it and refuse too. The
        # caller does not have to have set it. It is put back below, once the pool
        # has shut down, so a caller of run() gets its own environment back. The
        # write goes through process_env so it lands under ENVIRON_LOCK, the
        # package-wide rule for every runtime os.environ change.
        previous = apply_environ_overrides({REFUSE_HTTP_ENV: "1"})
        refuse_http_requests()

    try:
        # scan_files uses a multiprocessing pool for two or more files. The scanner
        # set 'fork' on Linux before calling it in-process; the same applies here.
        # Elsewhere the platform default ('spawn' on macOS and Windows) is safe
        # because this module is the __main__ of its own process and guarded below.
        if sys.platform == "linux":
            try:
                multiprocessing.set_start_method("fork", force=True)
            except RuntimeError:
                pass

        baseline = request.get("baseline")
        collection = (
            SecretsCollection.load_from_baseline(baseline=baseline)
            if baseline is not None
            else SecretsCollection()
        )
        collection.root = request["root"]
        with transient_settings(request["settings"]):
            _scan_files(collection, request["paths"])
        lines_by_file: Dict[str, Optional[List[str]]] = {}
        return [
            [key, [_with_column(secret, lines_by_file) for secret in secrets]]
            for key, secrets in collection.data.items()
        ]
    finally:
        if refusing:
            restore_environ(previous)


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(
            "usage: python -m automated_security_helper.utils.detect_secrets_worker "
            "REQUEST OUTPUT\n"
        )
        return 2
    request_path, output_path = argv
    with open(request_path, encoding="utf-8") as f:
        request = json.load(f)
    # Parsed, so the file has done its job. It holds the scan settings,
    # environment-derived values included, in the results directory, which is
    # what CI uploads: removing it here shrinks the window a run killed
    # mid-scan leaves it behind from the whole scan to this parse. The caller
    # still removes it in a finally for a worker that never got here, and a
    # sandbox that refuses the unlink only puts that back in charge.
    try:
        os.unlink(request_path)
    except OSError:
        pass
    result = run(request)
    # Created, never opened: ASH removes the path before it starts the worker, so
    # anything there now, a symlink included, was put there by something else.
    with open(output_path, "x", encoding="utf-8") as f:
        json.dump(result, f)
    return 0


# Only as the worker itself (``python -m``) or as a spawned pool process, which
# imports the worker as ``__mp_main__``. ASH imports this module for REFUSE_HTTP_ENV,
# and the variable must not turn off HTTP in ASH's own process.
if __name__ in ("__main__", "__mp_main__") and os.environ.get(REFUSE_HTTP_ENV) == "1":
    refuse_http_requests()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
