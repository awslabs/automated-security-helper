"""Run one detect-secrets scan in its own process and write the collection as JSON.

The detect-secrets scanner used to call ``SecretsCollection.scan_files`` inside the
ASH process, where no OS sandbox can reach it. It now starts this module as a
subprocess through ASH's spawn helpers, so ``--sandbox`` wraps it like any other
scanner tool. The work done here is exactly what the scanner did in-process, in the
same order: load the baseline (when there is one), set ``root``, then scan the file
list under ``transient_settings``.

Usage: ``python -m automated_security_helper.utils.detect_secrets_worker REQUEST OUTPUT``

REQUEST is a JSON file with ``root`` (str), ``baseline`` (the parsed baseline document,
or null), ``settings`` (the dict handed to ``transient_settings``) and ``paths`` (the
absolute file names to scan). The file list goes in a file rather than on the command
line because a large repository's list exceeds the Windows command-line limit.

OUTPUT is written only on success, as a JSON list of ``[key, [secret, ...]]`` pairs in
the collection's own key order, each secret in ``PotentialSecret.json()`` form. The key
is kept separately from the secret's ``filename`` because they differ: scan_files keys a
multi-file scan by the path relative to ``root`` while the secret keeps the absolute
name.

Deliberately imports nothing from ASH beyond the standard library and detect-secrets,
so starting it does not load the plugin registry.
"""

import json
import multiprocessing
import sys
from typing import Any, Dict, List


def run(request: Dict[str, Any]) -> List[List[Any]]:
    from detect_secrets.core.secrets_collection import SecretsCollection
    from detect_secrets.settings import transient_settings

    # scan_files uses a multiprocessing pool for two or more files. The scanner set
    # 'fork' on Linux before calling it in-process; the same applies here. Elsewhere
    # the platform default ('spawn' on macOS and Windows) is safe because this module
    # is the __main__ of its own process and guarded below.
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
        collection.scan_files(*request["paths"])
    return [
        [key, [secret.json() for secret in secrets]]
        for key, secrets in collection.data.items()
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
    result = run(request)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
