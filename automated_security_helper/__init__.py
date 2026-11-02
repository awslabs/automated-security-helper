# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The automated_security_helper package.

``__version__`` is read on first use, not at import: ``get_version`` comes from
utils/version_management, which on Python 3.10 imports ``tomli``, a third-party
package. Importing it here made every module under the package depend on it
through the package import, so ``python -m
automated_security_helper.utils.content_databases``, written to run on the
standard library alone, was not standard-library only on 3.10.
"""

from typing import Any

__all__ = ["__version__"]


def __getattr__(name: str) -> Any:
    if name == "__version__":
        from automated_security_helper.utils.version_management import get_version

        version = get_version()
        globals()["__version__"] = version
        return version
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
