# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The git double the characterization cells share.

``test_get_scan_set_git`` pins how ASH drives git to find a scan set; the MCP source
delivery and workspace execution cells clone and diff with the same double. It lives
here, not in a test file, so no cell file has to import another to use it.
"""

from __future__ import annotations

import posixpath
from pathlib import Path
from typing import Dict, Optional, Sequence

from tests.unit.characterization._harness import (
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

NOT_A_REPOSITORY = (
    "fatal: not a git repository (or any of the parent directories): .git\n"
)

#: What the double's clone writes into the target, as a short real checkout would.
CLONED_README = (
    b"# Delivered by the characterization git double\n"
    b"\n"
    b"This tree stands in for a shallow clone. The scan that follows reads it as\n"
    b"the session's source directory.\n"
)
CLONED_HEAD = b"ref: refs/heads/main\n"


class GitDouble(ToolDouble):
    """git, as far as ASH drives it: rev-parse, diff, clone, fetch and checkout.

    ``toplevel`` is the repository root ``rev-parse`` reports for a working
    directory inside it; outside it (or with ``toplevel=None``) rev-parse fails as
    git does outside a repository. ``changed`` is what ``diff --name-only`` prints,
    one path per line, for a ref in ``refs``. ``clone`` writes a README and
    ``.git/HEAD`` into the target named in argv, which must be an existing empty
    directory, as git requires. ``rev_parse``, ``diff``, ``clone``, ``fetch`` and
    ``checkout`` replace the outcome of that subcommand (a clone given one writes
    nothing). Anything else is rejected.
    """

    DIFF = ArgvGrammar(
        bool_flags=frozenset({"--name-only", "-z"}),
        min_positionals=1,
        max_positionals=1,
    )
    CLONE = ArgvGrammar(value_flags=frozenset({"--depth"}), max_positionals=0)
    FETCH = ArgvGrammar(
        value_flags=frozenset({"--depth"}), min_positionals=2, max_positionals=2
    )
    CHECKOUT = ArgvGrammar(
        bool_flags=frozenset({"--detach"}), min_positionals=1, max_positionals=1
    )

    def __init__(
        self,
        *,
        toplevel: Optional[Path] = None,
        changed: Sequence[str] = (),
        refs: Sequence[str] = ("origin/main",),
        rev_parse: Optional[Outcome] = None,
        diff: Optional[Outcome] = None,
        clone: Optional[Outcome] = None,
        fetch: Optional[Outcome] = None,
        checkout: Optional[Outcome] = None,
    ) -> None:
        self.toplevel = toplevel
        self.changed = list(changed)
        self.refs = set(refs)
        self.outcomes: Dict[str, Optional[Outcome]] = {
            "rev-parse": rev_parse,
            "diff": diff,
            "clone": clone,
            "fetch": fetch,
            "checkout": checkout,
        }

    def run(self, call: ToolCall) -> Outcome:
        args = list(call.args)
        directory: Optional[str] = None
        # git reads its global options -C <path> and -c <name=value> in any order,
        # interleaved, before the subcommand (git_argv puts the -c settings first).
        # Repeated -C accumulates: each later one that is not absolute is taken
        # relative to the one before it, and an absolute one replaces it.
        while args[:1] in (["-C"], ["-c"]):
            option = args[0]
            if len(args) < 2:
                raise call.reject(
                    "-C needs a directory" if option == "-C" else "-c needs a setting"
                )
            value, args = args[1], args[2:]
            if option == "-C":
                directory = (
                    value if directory is None else posixpath.join(directory, value)
                )
                if not call.confined(directory).is_dir():
                    raise call.reject(f"-C {directory} is not a directory")
        if not args:
            raise call.reject("no subcommand")
        subcommand, rest = args[0], args[1:]
        handler = {
            "rev-parse": self._rev_parse,
            "diff": self._diff,
            "clone": self._clone,
            "fetch": self._fetch,
            "checkout": self._checkout,
        }.get(subcommand)
        if handler is None:
            raise call.reject(f"subcommand {subcommand!r} is not one ASH uses")
        return handler(call, directory, rest)

    def _override(self, subcommand: str) -> Optional[Outcome]:
        return self.outcomes[subcommand]

    def _rev_parse(self, call: ToolCall, directory, rest) -> Outcome:
        if directory is not None or rest != ["--show-toplevel"]:
            raise call.reject("only `rev-parse --show-toplevel` from a cwd")
        if call.cwd is None:
            raise call.reject("rev-parse without a working directory")
        override = self._override("rev-parse")
        if override is not None:
            return override
        cwd = Path(call.cwd)
        if self.toplevel is None or not (
            cwd == self.toplevel or cwd.is_relative_to(self.toplevel)
        ):
            return Exit(128, stderr=NOT_A_REPOSITORY)
        return Exit(0, stdout=f"{self.toplevel}\n")

    def _diff(self, call: ToolCall, directory, rest) -> Outcome:
        if directory is not None:
            raise call.reject("diff with -C")
        parsed = self.DIFF.parse(call, rest)
        if not parsed.has("--name-only"):
            raise call.reject("diff without --name-only")
        (revisions,) = parsed.positionals
        if not revisions.endswith("...HEAD"):
            raise call.reject(f"diff of {revisions!r}, not <ref>...HEAD")
        override = self._override("diff")
        if override is not None:
            return override
        base = revisions[: -len("...HEAD")]
        if base not in self.refs:
            return Exit(
                128,
                stderr=f"fatal: ambiguous argument '{revisions}': unknown revision "
                "or path not in the working tree.\n",
            )
        if parsed.has("-z"):
            # As git prints with -z: each name followed by NUL, none quoted.
            return Exit(0, stdout="".join(f"{line}\0" for line in self.changed))
        return Exit(0, stdout="".join(f"{line}\n" for line in self.changed))

    def _clone(self, call: ToolCall, directory, rest) -> Outcome:
        if directory is not None or "--" not in rest:
            raise call.reject("clone without the -- end-of-options marker")
        marker = rest.index("--")
        parsed = self.CLONE.parse(call, rest[:marker])
        depth = parsed.last("--depth")
        if depth is not None and not depth.isdigit():
            raise call.reject(f"--depth {depth!r} is not a number")
        operands = rest[marker + 1 :]
        if len(operands) != 2:
            raise call.reject(f"clone takes a url and a target, got {operands}")
        url, target = operands
        override = self._override("clone")
        if override is not None:
            return override
        target_path = Path(target)
        if target_path.exists() and (
            not target_path.is_dir() or any(target_path.iterdir())
        ):
            return Exit(
                128,
                stderr=f"fatal: destination path '{target}' already exists and is "
                "not an empty directory.\n",
            )
        # The README first: ToolCall.write refuses a target outside the test, so
        # nothing is created under a path that write would not accept.
        call.write(target_path / "README.md", CLONED_README)
        (target_path / ".git").mkdir()
        call.write(target_path / ".git" / "HEAD", CLONED_HEAD)
        return Exit(0, stderr=f"Cloning into '{target}'...\n")

    def _fetch(self, call: ToolCall, directory, rest) -> Outcome:
        if directory is None:
            raise call.reject("fetch without -C")
        parsed = self.FETCH.parse(call, rest)
        if parsed.positionals[0] != "origin":
            raise call.reject(f"fetch from {parsed.positionals[0]!r}, not origin")
        depth = parsed.last("--depth")
        if depth is not None and not depth.isdigit():
            raise call.reject(f"--depth {depth!r} is not a number")
        override = self._override("fetch")
        return override if override is not None else Exit(0)

    def _checkout(self, call: ToolCall, directory, rest) -> Outcome:
        if directory is None:
            raise call.reject("checkout without -C")
        parsed = self.CHECKOUT.parse(call, rest)
        if not parsed.has("--detach"):
            raise call.reject("checkout without --detach")
        override = self._override("checkout")
        if override is not None:
            return override
        return Exit(0, stderr="HEAD is now at 0000000 characterization\n")
