# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Sandbox grants a config file the scanned repository could have written may not make.

The repository being scanned is untrusted. Anyone who can commit to it can write a
config file there, and ASH picks up ``.ash/.ash.yaml`` from the scan root without
being asked. These sandbox settings grant scanners access:

* ``sandbox.network_scanners`` gives the scanners it names a network.
* ``sandbox.extra_read_paths`` mounts host paths into every sandbox.
* ``sandbox.read_path_scanners`` and ``sandbox.env_scanners`` let the scanners they
  name have the read paths and environment variables their own options ask for
  (see ``SandboxRequirements.read_paths_require_grant`` and ``env_requires_grant``).

A config file can't make these grants if it is inside any git checkout, meaning a
directory at or above it, by its own path or its resolved path, holds a ``.git``
entry (a directory, or the file a submodule or linked worktree has). The rule
doesn't ask how the scan root is named, because symlinks, workspace files and the
shell's working directory give one tree many names, and every rule that depended on
them had a way around it. A checkout is what someone else can push to. For a scan
root outside any checkout, a config file inside the scan root can't grant either,
by any of the root's names: as given, resolved, or through ``$PWD``.

If any file the config was built from (the root config, any ``extends`` base, or
the file ``ASH_CONFIG`` names when no other config is used) is such a file, the
grants are taken from the trusted base plus ``--config-overrides`` instead. The
trusted base is the operator's config file when it is outside every checkout, else
``ASH_CONFIG``'s when that is, else the defaults. Comparing against that resolution,
and not against override key names, is what makes ``key+=[...]``, the dashed
spelling, and a whole-``sandbox`` override behave the same as a plain ``key=value``.

The untrusted ``network_scanners`` is kept as a limit (``SandboxConfig.network_limit``):
a scanner it does not name gets no network. A repository can still take network
away from its own scan, which is what the docs recommend for detect-secrets. It just
can't add network.

``sandbox.mode`` is a restriction, so it is honored from any source, as a floor. When
``--sandbox``, ``ASH_CONFIG`` or the operator's config file turns the sandbox on, an
untrusted file can't turn it off or switch it to another backend. The operator's
mode counts wherever the operator's file lives, even inside a checkout, because a
mode other than ``off`` never grants access. Only ``--sandbox off`` or a
``sandbox.mode`` override turns it back off. When no operator source turns the
sandbox on, an untrusted mode applies, because a sandbox the repository asks for only
takes access away.

The scanned tree is the outermost directory at or above the scan root that holds a
``.git`` entry (a directory, or the file a submodule or linked worktree has), or the
scan root itself outside a repository. Outermost, so a ``.git`` file inside the
repository can't make the superproject look like it is outside. The repository being
scanned controls all of it, not only the part being scanned. The root is looked up
from the scan root as given, from its resolved path, and, when the scan root is the
working directory or below it, from the shell's logical working directory
(``$PWD``). That way a scan root that is a symlink out of the repository still counts
the repository, including after ``cd vendor && ash scan``, where the operating system
reports only the physical directory. ``$PWD`` is used only when it names the working
directory, and it can only add a tree, never remove one. The check looks for the
entry on disk and does not run git, which reads configuration from the repository.

Whether a file is in the tree is decided with ``os.path.samefile`` on each of the
file's parents, not by comparing path strings. A symlink, a ``..`` segment, or a
case-only difference on a case-insensitive filesystem therefore can't make an
in-tree file look like it is outside. A file reached through a symlink inside the
tree counts as in the tree wherever the link points, because the repository wrote
the link: a ``.ash/.ash.yaml`` that links to a file elsewhere is held to the same
limits as one written in place (``files_inside``).

Known limitation: a trusted config file kept in a checkout of its own (an ops or
dotfiles repository) can't grant either. Its grants are dropped with a warning that
names the file and the setting; pass them with ``--config-overrides``.
"""

import os
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Sequence

from automated_security_helper.config.ash_config import SandboxConfig
from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.link_locations import link_locations
from automated_security_helper.utils.log import ASH_LOGGER


def is_within(path: Path, root: Path) -> bool:
    """True when ``path``, or a directory above it, is the same file as ``root``."""
    real = Path(os.path.realpath(path))
    for candidate in (real, *real.parents):
        try:
            if os.path.samefile(candidate, root):
                return True
        except OSError:
            continue
    return False


def as_named(path: Path) -> Path:
    """``path`` made absolute, with ``..`` applied the way the kernel applies it.

    Every other component stays as spelled, so a symlink is judged by where it
    sits. A ``..`` steps up from what the path before it resolves to: in
    ``link/..`` the kernel follows ``link`` first, which a plain textual fold of the
    path would not, and in ``src/../ops`` the result is no longer inside ``src``.
    """
    absolute = Path(path).absolute()
    named = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        if part == "..":
            named = Path(os.path.realpath(named)).parent
        elif part not in ("", "."):
            named = named / part
    return named


def checkout_containing(path: Path) -> Optional[Path]:
    """The nearest directory at or above ``path`` holding a ``.git`` entry, or None.

    Looked up from the path as given and from its resolved path, so a symlink into
    or out of a checkout counts either way.
    """
    for start in (as_named(path), Path(os.path.realpath(path))):
        for candidate in (start, *start.parents):
            if os.path.lexists(candidate / ".git"):
                return candidate
    return None


#: Symlinks followed before resolution gives up, as the kernel's ELOOP limit does.
_MAX_LINKS = 40


def links_followed(path: Path) -> List[Path]:
    """Every symlink resolving ``path`` follows, by the link's own location.

    Resolves one component at a time, as the kernel does, so a link reached only
    through another link is found too: ``ops/cur.yaml -> repo/.ash/.ash.yaml ->
    ../../other.yaml`` follows ``repo/.ash/.ash.yaml``, which neither the name
    ``ops/cur.yaml`` nor the resolved ``other.yaml`` shows. Whoever can write the
    directory a link sits in chooses where it points. Each location is returned
    with its directory resolved.
    """
    absolute = Path(path).absolute()
    resolved = Path(absolute.anchor)
    rest = list(absolute.parts[1:])
    links: List[Path] = []
    while rest:
        part = rest.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            resolved = resolved.parent
            continue
        candidate = resolved / part
        if not os.path.islink(candidate):
            resolved = candidate
            continue
        if len(links) >= _MAX_LINKS:
            break
        links.append(candidate)
        try:
            target = Path(os.readlink(candidate))
        except OSError:
            break
        if target.is_absolute():
            resolved = Path(target.anchor)
            rest = list(target.parts[1:]) + rest
        else:
            rest = list(target.parts) + rest
    return links


def in_any_checkout(path: Path) -> bool:
    """True when ``path`` is inside a git checkout, by its own or its resolved path."""
    return checkout_containing(path) is not None


def _logical_paths(scan_root: Path) -> List[Path]:
    """``scan_root`` as the shell names it, when it is the working directory or below.

    ASH builds an absolute scan root from the physical working directory, so a root
    whose text starts with it is rejoined to ``$PWD`` from the rest of its text,
    ``..`` and symlinks included. A root reached some other way is matched by its
    resolved path.
    """
    pwd = os.environ.get("PWD")
    if not pwd or not os.path.isabs(pwd):
        return []
    try:
        cwd = os.getcwd()
        if not os.path.samefile(pwd, cwd):
            return []
    except OSError:
        return []
    root = os.fspath(scan_root)
    if not os.path.isabs(root):
        return [Path(os.path.normpath(os.path.join(pwd, root)))]
    names: List[Path] = []
    prefix = cwd.rstrip(os.sep) + os.sep
    if root == cwd or root.startswith(prefix):
        names.append(Path(os.path.normpath(os.path.join(pwd, root[len(prefix) :]))))
    real_cwd = os.path.realpath(cwd)
    real_root = os.path.realpath(root)
    try:
        if os.path.commonpath([real_cwd, real_root]) == real_cwd:
            relative = os.path.relpath(real_root, real_cwd)
            name = Path(os.path.normpath(os.path.join(pwd, relative)))
            if name not in names:
                names.append(name)
    except ValueError:  # different drives on Windows
        pass
    return names


def scan_root_names(scan_root: Path) -> List[Path]:
    """Every name the scan root has: as given, resolved, and through ``$PWD``."""
    names: List[Path] = []
    for name in (
        as_named(scan_root),
        Path(os.path.realpath(scan_root)),
        *_logical_paths(scan_root),
    ):
        if name not in names:
            names.append(name)
    return names


#: The reason ``confine_sandbox_grants`` gives by default: why a file may not grant.
REPOSITORY_WRITTEN = (
    "the file is inside a git checkout or the scanned directory, so someone other "
    "than the operator may have written it"
)


def untrusted_reason(path: Path, scan_root: Path) -> Optional[str]:
    """Why the scanned repository could have written ``path``, or None if it could not.

    Inside any git checkout, by the path as given or as resolved, or inside the
    scan root by any of the root's names; or reached through a symlink that sits
    in one (``links_followed``). Pass the path as it was named, not resolved: every
    spelling is checked here, and resolving first would hide a symlink's own
    location.
    """
    checkout = checkout_containing(path)
    if checkout is not None:
        return f"it is inside the git checkout at {checkout.as_posix()}"
    names = scan_root_names(scan_root)
    if any(is_within(path, name) for name in names) or _named_within(path, names):
        return f"it is inside the scanned directory {Path(scan_root).as_posix()}"
    for link in links_followed(path):
        checkout = checkout_containing(link.parent)
        if checkout is not None:
            return (
                f"it is reached through {link.as_posix()}, a link inside the git "
                f"checkout at {checkout.as_posix()}"
            )
        if any(is_within(link.parent, name) for name in names):
            return (
                f"it is reached through {link.as_posix()}, a link inside the "
                f"scanned directory {Path(scan_root).as_posix()}"
            )
    return None


def scanned_checkouts(scan_root: Path) -> List[Path]:
    """The outermost git checkout holding ``scan_root``, by its own and resolved path.

    The tree the scanned repository wrote: for a submodule or a vendored checkout,
    the superproject around it too. Empty for a scan root outside every checkout.
    """
    found: List[Path] = []
    for start in (as_named(scan_root), Path(os.path.realpath(scan_root))):
        outermost = None
        for candidate in (start, *start.parents):
            if os.path.lexists(candidate / ".git"):
                outermost = candidate
        if outermost is not None and outermost not in found:
            found.append(outermost)
    return found


def in_tree_reason(path: Path, scan_root: Path) -> Optional[str]:
    """Why ``path`` is inside the scanned tree itself, or None.

    Narrower than ``untrusted_reason``: inside the scan root, or the outermost
    checkout holding it, by any of their names, or reached through a link inside
    them. Another checkout, such as an operator's ops repository, is not the
    scanned tree. Used for a path the operator named
    (``config/path_trust.py``), which the operator may keep in a checkout of their
    own; a path a repository's config names follows ``untrusted_reason``.
    """
    names = scan_root_names(scan_root)
    roots = [*scanned_checkouts(scan_root), *names]
    label = Path(scan_root).as_posix()
    if any(is_within(path, root) for root in roots) or _named_within(path, roots):
        return f"it is inside the scanned tree at {label}"
    for link in links_followed(path):
        if any(is_within(link.parent, root) for root in roots):
            return (
                f"it is reached through {link.as_posix()}, a link inside the "
                f"scanned tree at {label}"
            )
    return None


def untrusted_path(path: Path, scan_root: Path) -> bool:
    """Whether the scanned repository could have written ``path``.

    The one per-path rule: config files (``repository_written``) and the files
    scanner options name (``config/path_trust.py``) are both judged by it. See
    ``untrusted_reason``.
    """
    return untrusted_reason(path, scan_root) is not None


def repository_written(
    chain: Iterable[Path],
    scan_root: Path,
    lexical: Iterable[Path] = (),
    *,
    all_untrusted: bool = False,
) -> List[Path]:
    """The files of a config ``chain`` that may not grant sandbox access.

    Args:
        chain: The files a config was built from, as resolved paths.
        scan_root: The directory being scanned.
        lexical: The same files as they were named, where that is known (the
            config path the operator passed or ASH discovered). A file whose name
            is in a checkout counts even when its resolved path is not.
        all_untrusted: Every file of the chain, wherever it is: for a config a
            caller other than the operator supplied (an MCP client's upload).
    """
    chain = list(chain)
    if all_untrusted:
        return chain or [Path(path) for path in lexical]
    untrusted = [path for path in chain if untrusted_path(path, scan_root)]
    for path in lexical:
        path = Path(path)
        if path not in untrusted and untrusted_path(path, scan_root):
            untrusted.append(path)
    return untrusted


def _named_within(path: Path, names: Iterable[Path]) -> bool:
    """Whether ``path``, as spelled, sits inside one of the scan root's names.

    Walks the unresolved parents, so a config file that is a symlink out of the
    scan root still counts as inside it.
    """
    names = list(names)
    lexical = as_named(path)
    for candidate in (lexical, *lexical.parents):
        for name in names:
            try:
                if os.path.samefile(candidate, name):
                    return True
            except OSError:
                continue
    return False


def _outermost_checkout(start: Path) -> Path:
    found = start
    for candidate in (start, *start.parents):
        if os.path.lexists(candidate / ".git"):
            found = candidate
    return found


def scanned_trees(scan_root: Path) -> List[Path]:
    """The trees the scanned repository controls, from every name the scan root has."""
    trees = []
    for start in (
        Path(os.path.abspath(scan_root)),
        Path(os.path.realpath(scan_root)),
        *_logical_paths(scan_root),
    ):
        tree = _outermost_checkout(start)
        if tree not in trees:
            trees.append(tree)
    return trees


def files_inside(
    chain: Iterable[Path],
    trees: Iterable[Path],
    names: Optional[Mapping[Path, Sequence[Path]]] = None,
) -> List[Path]:
    """The files of ``chain`` that the scanned repository wrote or chose.

    A file is one when it is inside a tree, or when it was reached through a
    symlink that sits inside one: the repository wrote the link, so it chose the
    file the link reaches, wherever that is. Each file is judged by its own path
    and by each path in ``names`` it was reached by
    (``config_sources.ResolvedConfigDocument.names``), and each of those at
    every symlink on the way (``utils/link_locations``).
    """
    trees = list(trees)
    return [path for path in chain if tree_holding(path, trees, names) is not None]


def tree_holding(
    path: Path,
    trees: Iterable[Path],
    names: Optional[Mapping[Path, Sequence[Path]]] = None,
) -> Optional[Path]:
    """The tree of ``trees`` that ``path`` is inside or was reached through, or None.

    ``files_inside``'s test for one file, which names the tree, so a refusal can
    say which tree to move the file out of.
    """
    trees = list(trees)
    for name in (path, *(names or {}).get(path, ())):
        places = [name, *(link.parent for link in link_locations(name))]
        for tree in trees:
            if any(is_within(place, tree) for place in places):
                return tree
    return None


def confine_sandbox_grants(
    sandbox: SandboxConfig,
    trusted: SandboxConfig,
    in_tree: List[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
) -> None:
    """Replace the grants in ``sandbox`` with ``trusted``'s, keeping its list as a limit.

    Args:
        sandbox: The resolved settings, from the config files plus the overrides.
        trusted: The same settings resolved from the trusted base plus the
            overrides. Must be a separate resolution: comparing ``sandbox`` with
            itself, or with a copy of itself, would keep every grant.
        in_tree: The files that may not grant (see ``repository_written``).
            Named in the warning.
        source: Why those files are not the operator's, and the fix, for the
            warning.
    """
    if trusted is sandbox:
        raise ValueError("the trusted sandbox settings must not be the subject")
    ignored = []
    if sandbox.network_scanners != trusted.network_scanners:
        ignored.append("sandbox.network_scanners")
    for key in ("extra_read_paths", "read_path_scanners", "env_scanners"):
        if list(getattr(sandbox, key)) != list(getattr(trusted, key)):
            ignored.append(f"sandbox.{key}")
    if trusted.mode != "off" and sandbox.mode != trusted.mode:
        ignored.append("sandbox.mode")
        sandbox.mode = trusted.mode
    limit = sandbox.network_scanners
    sandbox.network_scanners = (
        list(trusted.network_scanners) if trusted.network_scanners is not None else None
    )
    sandbox.extra_read_paths = list(trusted.extra_read_paths)
    sandbox.read_path_scanners = list(trusted.read_path_scanners)
    sandbox.env_scanners = list(trusted.env_scanners)
    sandbox.network_limit = list(limit) if limit is not None else None
    if ignored:
        files = ", ".join(describe_config_path(path) for path in in_tree)
        tail = (
            f"{source.scanner_steps_note}."
            if source.scanner_steps_note
            else "A network_scanners list there still removes network from scanners "
            "it does not name, and a sandbox mode there still applies when nothing "
            f"else turns the sandbox on. {source.remedy}"
        )
        ASH_LOGGER.warning(
            f"Ignoring {', '.join(ignored)} from {files}: {source.reason}. {tail}"
        )
