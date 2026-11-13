# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A fake site-packages holding pygit2, yara and the shared libraries their wheels bundle.

The image's version probes for pygit2, libgit2, libssh2, OpenSSL, PCRE and the
OpenSSL 1.1 that yara-python bundles run in
GuardDog's uv tool environment. These tests run the probes' real code with the
real interpreter against this tree, so a probe that reads the wrong file or the
wrong pattern fails here instead of only in an image build.
"""

from pathlib import Path
from typing import Dict, Optional

from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES


def bundled_versions() -> Dict[str, str]:
    """Each probed component's version as its probe prints it."""
    return {
        name: THIRD_PARTY_LICENSES[name].version.lstrip("v")
        for name in ("libgit2", "libssh2", "openssl", "openssl-1.1", "pcre", "pygit2")
    }


def fake_pygit2_site(
    root: Path,
    overrides: Optional[Dict[str, Optional[bytes]]] = None,
    yara_overrides: Optional[Dict[str, Optional[bytes]]] = None,
) -> Path:
    """Write the tree under ``root`` and return the directory to put on PYTHONPATH.

    ``overrides`` maps a pygit2.libs file name to its bytes, or to None to leave
    that file out; ``yara_overrides`` does the same for yara_python.libs.
    """
    versions = bundled_versions()
    package = root / "pygit2"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        f'LIBGIT2_VERSION = "{versions["libgit2"]}"\n'
        f'__version__ = "{versions["pygit2"]}"\n',
        encoding="utf-8",
    )
    libs = root / "pygit2.libs"
    libs.mkdir()
    # Hashed names and surrounding bytes as auditwheel and the linker leave them.
    ssh = versions["libssh2"].removeprefix("libssh2-")
    ssl = versions["openssl"].removeprefix("openssl-")
    files: Dict[str, Optional[bytes]] = {
        "libgit2-39727f45.so.1.9.1": b"\x7fELF libgit2",
        "libssh2-7af77739.so.1.0.1": b"\x7fELF\x00SSH-2.0-libssh2_"
        + ssh.encode()
        + b"\x00",
        "libcrypto-909d00cf.so.3": b"\x7fELF\x00OpenSSL "
        + ssl.encode()
        + b" 11 Feb 2025\x00",
        "libssl-fb7fb2a0.so.3": b"\x7fELF libssl",
        "libpcre-0dd207b5.so.1.2.10": b"\x7fELF\x00"
        + versions["pcre"].encode()
        + b" 2018-03-20\x00",
    }
    files.update(overrides or {})
    for name, data in files.items():
        if data is not None:
            (libs / name).write_bytes(data)
    # yara-python installs a top-level extension module, yara.<abi>.so, beside
    # yara_python.libs; a plain module stands in for it.
    (root / "yara.py").write_text("", encoding="utf-8")
    yara_libs = root / "yara_python.libs"
    yara_libs.mkdir()
    yara_files: Dict[str, Optional[bytes]] = {
        "libcrypto-0ec7d250.so.1.1": b"\x7fELF\x00OpenSSL "
        + versions["openssl-1.1"].encode()
        + b"  11 Sep 2023\x00",
    }
    yara_files.update(yara_overrides or {})
    for name, data in yara_files.items():
        if data is not None:
            (yara_libs / name).write_bytes(data)
    return root
