"""Run one detect-secrets scan in its own process and write the collection as JSON.

The detect-secrets scanner used to call ``SecretsCollection.scan_files`` inside the
ASH process, where no OS sandbox can reach it. It now starts this module as a
subprocess through ASH's spawn helpers, so ``--sandbox`` wraps it like any other
scanner tool. The work done here is exactly what the scanner did in-process, in the
same order: load the baseline (when there is one), set ``root``, then scan the file
list under ``transient_settings``.

Usage: ``python -m automated_security_helper.utils.detect_secrets_worker REQUEST OUTPUT``

REQUEST is a JSON file with ``root`` (str), ``baseline`` (the parsed baseline document,
or null), ``baseline_trusted`` (whether the operator named that baseline, so its audit
may drop entries; missing means no), ``settings`` (the dict handed to
``transient_settings``), ``paths`` (the absolute file names to scan) and ``verify``
(whether candidate secrets may be sent to their issuers; missing means no). The file
list goes in a file rather than on the command line because a large repository's list
exceeds the Windows command-line limit.

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
has shut down. The module-level gate refuses unless the variable reads exactly "0":
the scanner states "0" when the scan may verify and "1" otherwise, so the worker's own
import refuses from its first line for a non-verifying scan, and a variable that an
executor or an environment filter dropped on the way fails safe (unverified findings,
no request); a caller that does not set it gets the refusal all the same.

OUTPUT is written only on success, as a JSON list of ``[key, [secret, ...]]`` pairs in
the collection's own key order, each secret in ``PotentialSecret.json()`` form. The key
is kept separately from the secret's ``filename`` because they differ: scan_files keys a
multi-file scan by the path relative to ``root`` while the secret keeps the absolute
name. A baseline's entries are in the collection too. When the request marks the
baseline trusted (the operator named it), one the baseline's audit marked
``is_secret: false`` (accepted as not a secret) is left out of OUTPUT; otherwise every
entry is reported, because a baseline the scanned repository wrote itself (the in-tree
file the scanner loads by default) may mark a finding but may not remove it. Trusted
or not, the baseline's copy of a secret the scan found again is left out, since the
scanned copy reports it once, and the scanned copy carries the audit marks
(``is_secret``, ``is_verified``) of the copy that was left out. A baseline with no
``results`` mapping holds no entries. OUTPUT is created with mode 0600, as the request file is.

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
from typing import Any, Dict, List, Optional, Set, Tuple

from automated_security_helper.utils.process_env import (
    apply_environ_overrides,
    restore_environ,
)

#: The key of the column in each secret written to OUTPUT.
START_COLUMN_KEY = "ash_start_column"

#: The REQUEST key the scanner sets to ``true`` only for a baseline the operator
#: named. Only then may the baseline's audit drop an entry from OUTPUT.
BASELINE_TRUSTED_KEY = "baseline_trusted"


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
    index = _value_index(lines[line_number - 1], value)
    return index + 1 if index >= 0 else None


def _is_name_character(character: str) -> bool:
    return character.isalnum() or character == "_"


def _names_a_key(line: str, before: str, end: int) -> bool:
    """Whether the token ending at *end* in *line* is a key rather than a value.

    A key is followed by ``=`` or ``:`` (so also ``=>``), past the quote that
    closes it when *before*, the character ahead of the token, opened one, and
    past spaces and tabs. Reading only the one character after the token took
    ``password = password``, ``{"password": "password"}``, ``"password" =
    "password"`` and ``'password' => 'password'`` for values, so the column
    pointed at the key, and two secrets on one such line could share it.
    """
    cursor = end
    if before in ('"', "'") and cursor < len(line) and line[cursor] == before:
        cursor += 1
    while cursor < len(line) and line[cursor] in (" ", "\t"):
        cursor += 1
    return cursor < len(line) and line[cursor] in ("=", ":")


def _value_index(line: str, value: str) -> int:
    """Where *value* starts in *line*, or -1.

    Of the places the value occurs, the first that is a whole token is taken: not
    inside a longer run of letters, digits and underscores, and not a key
    (``_names_a_key``: followed by ``=`` or ``:``, past its closing quote and any
    spaces). The first occurrence of any kind is the fallback. The first
    occurrence alone gave the wrong column when the value was the start of a
    longer secret earlier in the line, or spelled the same as the variable it is
    assigned to (``password=password``), and two secrets of one type on one line
    then shared a column.
    """
    whole_tokens = []
    start = line.find(value)
    while start != -1:
        end = start + len(value)
        before = line[start - 1] if start > 0 else ""
        after = line[end] if end < len(line) else ""
        bounded = not (before and _is_name_character(before)) and not (
            after and _is_name_character(after)
        )
        if bounded:
            if not _names_a_key(line, before, end):
                return start
            whole_tokens.append(start)
        start = line.find(value, start + 1)
    if whole_tokens:
        return whole_tokens[0]
    return line.find(value)


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


#: A baseline entry its audit accepted as not a secret: its key in the baseline,
#: the secret's type and its hash.
_Accepted = Set[Tuple[str, str, str]]


def _accepted_by_the_baseline(collection: Any) -> _Accepted:
    """The entries of *collection*, as loaded from the baseline, that the
    baseline's audit marked ``is_secret: false``.

    Taken before the scan adds to the collection. The baseline was loaded into
    the same collection the scan adds to, so its entries are in the result too,
    each keeping the audit result the baseline recorded (a secret found again
    under the baseline's key is the same set element). One audited and accepted as not
    a secret is not reported; an unaudited one, or one audited as a secret, is.
    Called only for a baseline the request marks trusted; see ``run()``.
    """
    return {
        (key, secret.type, secret.secret_hash)
        for key, secrets in collection.data.items()
        for secret in secrets
        if getattr(secret, "is_secret", None) is False
    }


def _is_accepted(accepted: _Accepted, key: str, secret: Any, root: str) -> bool:
    """Whether *secret*, keyed by *key* in the scanned collection, is one the
    baseline accepted.

    A multi-file scan keys a secret by its path relative to ``root``, as the
    baseline does; a lone file is keyed by the name it was handed, an absolute
    one, so that key is also tried relative to ``root``.
    """
    if not accepted:
        return False
    keys = {key}
    if root and os.path.isabs(key):
        keys.add(os.path.relpath(key, root))
    return any((k, secret.type, secret.secret_hash) in accepted for k in keys)


def run(request: Dict[str, Any]) -> List[List[Any]]:
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

        collection = _collection_from(request.get("baseline"))
        collection.root = request["root"]
        # A baseline the operator named may drop what its audit accepted. One the
        # scanned repository wrote (the in-tree default) is untrusted: it may mark
        # an entry but every entry still reaches OUTPUT. Absent, or anything but
        # the JSON true, reads as untrusted.
        accepted: _Accepted = set()
        if request.get(BASELINE_TRUSTED_KEY) is True:
            accepted = _accepted_by_the_baseline(collection)
        with transient_settings(request["settings"]):
            _scan_files(collection, request["paths"])
        return _output_of(collection, accepted)
    finally:
        if refusing:
            restore_environ(previous)


def _collection_from(baseline: Optional[Dict[str, Any]]) -> Any:
    """A SecretsCollection holding *baseline*'s results, or an empty one.

    ``load_from_baseline`` reads the ``results`` mapping and nothing else, and
    raises KeyError for a baseline without one: a settings-only baseline (one
    ``detect-secrets scan`` wrote with nothing found, or one kept for its plugins
    and filters alone), which failed the whole source scan. Such a baseline holds
    no results, so the collection starts empty, as with no baseline at all.
    """
    from detect_secrets.core.secrets_collection import SecretsCollection

    if baseline is None:
        return SecretsCollection()
    results = baseline.get("results") if isinstance(baseline, dict) else None
    if not isinstance(results, dict):
        return SecretsCollection()
    return SecretsCollection.load_from_baseline(baseline=baseline)


def _output_of(collection: Any, accepted: _Accepted) -> List[List[Any]]:
    """The OUTPUT pairs for *collection*: one record per secret, in key order.

    A secret that is both in the baseline and still in the code is in the
    collection twice: the baseline's copy carries the file name the baseline
    wrote, and the scanned copy the absolute name the scan was given, and
    detect-secrets compares file names, so the two are distinct set elements
    (under one key, or under a relative and an absolute spelling of the same
    key). Reported twice, the finding was counted twice. The baseline's copy is
    left out wherever the scan found the same secret (same type and hash, same
    file relative to ``root``); the scanned copy is the one with a column.
    """
    root = collection.root
    found_again = {
        (_relative_key(key, root), secret.type, secret.secret_hash)
        for key, secrets in collection.data.items()
        for secret in secrets
        if getattr(secret, "secret_value", None)
    }
    marks = _marks_of_dropped_copies(collection, found_again, root)
    return [
        [key, _records_of(key, secrets, accepted, root, found_again, marks)]
        for key, secrets in collection.data.items()
    ]


#: The audit marks a baseline records for a secret: ``is_secret`` (None when it
#: was never audited) and ``is_verified``, by the relative key, type and hash.
_Marks = Dict[Tuple[str, str, str], Tuple[Optional[bool], bool]]


def _marks_of_dropped_copies(
    collection: Any, found_again: Set[Tuple[str, str, str]], root: str
) -> _Marks:
    """The audit marks of each baseline copy that ``_records_of`` leaves out
    because the scan found its secret again.

    A copy with no value is the baseline's. Its marks are what the scanned copy
    would otherwise lose: ``is_secret`` from the first copy that has one, and
    ``is_verified`` if any copy was verified.
    """
    marks: _Marks = {}
    for key, secrets in collection.data.items():
        relative = _relative_key(key, root)
        for secret in secrets:
            triple = (relative, secret.type, secret.secret_hash)
            if getattr(secret, "secret_value", None) or triple not in found_again:
                continue
            is_secret, is_verified = marks.get(triple, (None, False))
            if is_secret is None:
                is_secret = getattr(secret, "is_secret", None)
            marks[triple] = (
                is_secret,
                is_verified or bool(getattr(secret, "is_verified", False)),
            )
    return marks


def _with_baseline_marks(secret: Any, relative: str, marks: Optional[_Marks]) -> Any:
    """*secret* carrying the marks of the baseline copy the scan found again.

    The rule of ``SecretsCollection.merge``: ``is_secret`` is taken only when the
    scanned copy has none, and ``is_verified`` only upward. A baseline copy has no
    value, so only a scanned secret takes marks.
    """
    if not marks or not getattr(secret, "secret_value", None):
        return secret
    is_secret, is_verified = marks.get(
        (relative, secret.type, secret.secret_hash), (None, False)
    )
    if getattr(secret, "is_secret", None) is None and is_secret is not None:
        secret.is_secret = is_secret
    if is_verified and not getattr(secret, "is_verified", False):
        secret.is_verified = True
    return secret


def _relative_key(key: str, root: str) -> str:
    """*key* relative to *root*, for an absolute key (a lone file's)."""
    if root and os.path.isabs(key):
        return os.path.relpath(key, root)
    return key


def _records_of(
    key: str,
    secrets: Any,
    accepted: _Accepted,
    root: str,
    found_again: Optional[Set[Tuple[str, str, str]]] = None,
    marks: Optional[_Marks] = None,
) -> List[Any]:
    """The OUTPUT records of the secrets keyed by *key*, each with its column.

    A secret the baseline accepted as not a secret is left out, and so is a
    baseline copy (no value) of a secret the scan found again (*found_again*:
    the relative key, type and hash of each scanned secret); the scanned copy
    takes that copy's audit marks (*marks*). The lines read for
    the column are cached for this key only: every secret under one key is in
    one file, so a cache shared by every key held every finding file's lines for
    the whole collection, and is released with the key's records.
    """
    lines_by_file: Dict[str, Optional[List[str]]] = {}
    relative = _relative_key(key, root)
    return [
        _with_column(_with_baseline_marks(secret, relative, marks), lines_by_file)
        for secret in secrets
        if not _is_accepted(accepted, key, secret, root)
        and not (
            found_again
            and not getattr(secret, "secret_value", None)
            and (relative, secret.type, secret.secret_hash) in found_again
        )
    ]


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
    _write_output(output_path, run(request))
    return 0


def _write_output(output_path: str, result: List[List[Any]]) -> None:
    """Write *result* as OUTPUT: a new file this account alone can read.

    Created, never opened: ASH removes the path before it starts the worker, so
    anything there now, a symlink included, was put there by something else.
    Mode 0600, as the caller makes the request file: OUTPUT holds every finding's
    hashed secret, file name and line, in the results directory, and the default
    mode let every account on the host read it.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(result, f)


# Only as the worker itself (``python -m``) or as a spawned pool process, which
# imports the worker as ``__mp_main__``. ASH imports this module for REFUSE_HTTP_ENV,
# and the variable must not turn off HTTP in ASH's own process. The requests are
# refused unless the variable says exactly "0", which the scanner states for a scan
# that may verify: a variable an executor or an environment filter dropped or
# rewrote then fails safe (the secrets are reported unverified) rather than letting
# candidate secrets reach their issuers.
if __name__ in ("__main__", "__mp_main__") and os.environ.get(REFUSE_HTTP_ENV) != "0":
    refuse_http_requests()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
