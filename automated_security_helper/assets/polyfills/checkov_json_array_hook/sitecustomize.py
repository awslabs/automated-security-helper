# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Polyfill for bridgecrewio/checkov#7777 on CPython 3.15 and later.

CPython 3.15 made ``array_hook`` a required argument of
``json.decoder.JSONArray``. checkov's ``Decoder.json_array``
(``checkov/common/parsers/json/decoder.py``) calls it without one, so every JSON
document that holds an array fails to parse and checkov's parallel runner can
deadlock on the resulting worker errors.

The runtime-compat row that names this shim
(``automated_security_helper/base/scanner_operational_facets.py``) puts this
directory on the tool's ``PYTHONPATH``; CPython imports a ``sitecustomize``
module at startup, before any tool code runs and in ``multiprocessing``
children too. The wrapper below supplies the stdlib default (``list``) when
the call leaves ``array_hook`` out, and delegates everything else.

Two gates keep the shim inert where it is not needed. The runtime gate is the
version check, which mirrors the row's ``runtime_request`` (``>=3.15``; a test
holds the two equal). The signature gate is the check that ``array_hook`` is a
required parameter: on an interpreter whose ``JSONArray`` has the older
signature nothing is wrapped, even if the version gate were wrong.

Shipped as the tested alternative to the interpreter PIN checkov declares: the
PIN is the default and this shim backs it behind the same facet family.
"""

from __future__ import annotations

import sys

#: The lowest interpreter this shim acts on; the facet row's ``runtime_request``
#: is ``>=`` this, as a PEP 440 string.
MINIMUM_RUNTIME = (3, 15)

#: What the stdlib supplied before the argument became required.
DEFAULT_ARRAY_HOOK = list


def _patch(decoder_module: object) -> bool:
    """Wrap ``JSONArray`` in *decoder_module*; True when it was wrapped."""
    import functools
    import inspect

    original = getattr(decoder_module, "JSONArray", None)
    if original is None:
        return False
    try:
        signature = inspect.signature(original)
    except (TypeError, ValueError):
        return False
    parameter = signature.parameters.get("array_hook")
    if parameter is None or parameter.default is not inspect.Parameter.empty:
        return False

    @functools.wraps(original)
    def json_array(*args, **kwargs):  # type: ignore[no-untyped-def]
        try:
            signature.bind(*args, **kwargs)
        except TypeError:
            if "array_hook" in kwargs:
                raise
            kwargs["array_hook"] = DEFAULT_ARRAY_HOOK
        return original(*args, **kwargs)

    json_array._ash_runtime_compat_polyfill = "checkov_json_array_hook"  # type: ignore[attr-defined]
    setattr(decoder_module, "JSONArray", json_array)
    return True


def _apply() -> None:
    if sys.version_info[:2] < MINIMUM_RUNTIME:
        return
    try:
        import json.decoder as decoder_module
    except Exception:  # pragma: no cover - the stdlib json module always imports
        return
    _patch(decoder_module)


_apply()
