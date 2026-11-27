"""Whether replacing one CRD with another can strand objects already stored under it.

The API server checks little of this itself. It refuses an update that drops a
version still listed in ``status.storedVersions``, and nothing else here: removing a
property, making a field required or changing a type is accepted, and the cost shows
up later. A removed property is pruned from every stored object the next time it is
read or written, so an upgrade that drops a status field erases it from every finished
scan. A newly required field makes every existing object fail validation on its next
update, including the status patch the operator writes.

:func:`upgrade_problems` reports those cases for an old and a new CRD. The e2e runs it
on the CRD the cluster actually holds before an upgrade and the one the upgrade
applies, and the unit suite runs it on planted pairs so a check that stopped finding
anything fails there.
"""

from __future__ import annotations

from typing import Any


def _versions(crd: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {v["name"]: v for v in (crd.get("spec") or {}).get("versions") or []}


def _schema(version: dict[str, Any]) -> dict[str, Any]:
    return ((version.get("schema") or {}).get("openAPIV3Schema")) or {}


def _walk(old: dict[str, Any], new: dict[str, Any], path: str, problems: list[str]) -> None:
    if new.get("x-kubernetes-preserve-unknown-fields") is True and not new.get("properties"):
        # The new schema keeps whatever is stored here, so nothing below can be pruned.
        return
    old_type, new_type = old.get("type"), new.get("type")
    if old_type and new_type and old_type != new_type:
        problems.append(f"{path} changes type from {old_type} to {new_type}")
        return

    old_props = old.get("properties") or {}
    new_props = new.get("properties") or {}
    for name in sorted(old_props):
        child = f"{path}.{name}"
        if name not in new_props:
            if new.get("x-kubernetes-preserve-unknown-fields") is True:
                continue
            problems.append(f"{child} is removed, so it is pruned from every stored object")
            continue
        _walk(old_props[name], new_props[name], child, problems)

    added_required = sorted(set(new.get("required") or []) - set(old.get("required") or []))
    for name in added_required:
        problems.append(
            f"{path}.{name} becomes required, so every stored object without it fails "
            f"validation on its next update"
        )

    if "items" in old and "items" in new:
        _walk(old["items"], new["items"], f"{path}[]", problems)


def upgrade_problems(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Everything about replacing *old* with *new* that can strand stored objects."""
    problems: list[str] = []
    old_spec, new_spec = old.get("spec") or {}, new.get("spec") or {}
    for key in ("group", "scope"):
        if old_spec.get(key) != new_spec.get(key):
            problems.append(f"spec.{key} changes from {old_spec.get(key)} to {new_spec.get(key)}")
    if (old_spec.get("names") or {}).get("plural") != (new_spec.get("names") or {}).get("plural"):
        problems.append("spec.names.plural changes, which makes it a different resource")

    old_versions, new_versions = _versions(old), _versions(new)
    storage = [name for name, v in new_versions.items() if v.get("storage")]
    if len(storage) != 1:
        problems.append(f"the new CRD has {len(storage)} storage versions, not exactly one")
    stored = ((old.get("status") or {}).get("storedVersions")) or [
        name for name, v in old_versions.items() if v.get("storage")
    ]
    for name in stored:
        if name not in new_versions:
            problems.append(
                f"version {name} holds stored objects and the new CRD drops it; the API "
                f"server refuses this update"
            )
    for name, version in sorted(old_versions.items()):
        if not version.get("served"):
            continue
        replacement = new_versions.get(name)
        if replacement is None:
            if name not in stored:
                problems.append(f"served version {name} is removed")
            continue
        if not replacement.get("served"):
            problems.append(f"version {name} stops being served")
        if "status" in (version.get("subresources") or {}) and "status" not in (
            replacement.get("subresources") or {}
        ):
            problems.append(f"version {name} drops the status subresource")
        _walk(_schema(version), _schema(replacement), name, problems)
    return problems
