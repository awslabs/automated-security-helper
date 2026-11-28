"""The operator at the end of the key of a ``--config-overrides`` entry.

An entry is ``KEY=VALUE``, which replaces the value at KEY, ``KEY+=VALUE``, which
adds to the list at KEY, or ``KEY-=VALUE``, which removes items from it.
``split_override_key`` is the one reader of that operator: every module that routes
an override by its key calls it, so an append and a removal reach every check that
a replacement reaches. The module imports nothing from the package, so a module in
any layer can import it.
"""

from typing import Final, Literal, Tuple

OverrideOp = Literal["=", "+=", "-="]

#: ``KEY=VALUE``: the value replaces what KEY holds.
REPLACE: Final = "="
#: ``KEY+=VALUE``: the items are added to the end of the list KEY holds.
APPEND: Final = "+="
#: ``KEY-=VALUE``: every occurrence of each item is taken out of the list KEY holds.
REMOVE: Final = "-="


def split_override_key(entry: str) -> Tuple[str, OverrideOp]:
    """The key path of an override entry, or of its key part, and its operator.

    The key part is ``str(entry).partition("=")[0]``, exactly as written: no
    whitespace is removed, so a caller strips the key the way it stripped it
    before. Its last character decides the operator: a ``+`` is an append and a
    ``-`` a removal, and either is cut from the key returned; any other character
    leaves the whole key part and ``REPLACE``.

    >>> split_override_key("scanners.trivy.options.scanners+=[secret]")
    ('scanners.trivy.options.scanners', '+=')
    >>> split_override_key("scanners.trivy.options.scanners-=vuln")
    ('scanners.trivy.options.scanners', '-=')
    >>> split_override_key("project_name=demo")
    ('project_name', '=')
    >>> split_override_key("global_settings.ignore_paths +=x")
    ('global_settings.ignore_paths ', '+=')
    """
    key = str(entry).partition("=")[0]
    if key.endswith("+"):
        return key[:-1], APPEND
    if key.endswith("-"):
        return key[:-1], REMOVE
    return key, REPLACE
