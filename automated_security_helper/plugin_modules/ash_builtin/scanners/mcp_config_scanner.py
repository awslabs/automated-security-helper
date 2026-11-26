# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP server config policy scanner, as a builtin scanner.

What it reads
-------------
The repo-local MCP server config files ``utils/mcp_config`` knows (``.mcp.json``,
``.cursor/mcp.json``, ``.vscode/mcp.json``, ``.gemini/settings.json``,
``claude_desktop_config.json``, ``.amazonq/mcp.json``, ``.roo/mcp.json``,
``.kiro/settings/mcp.json``, ``.devin/mcp_config.json``, ``.codex/config.toml``).
Each file is read into the normalized ``McpServerEntry`` model and every entry is
checked against the options below. The scanner runs in process: it starts no tool,
reaches no network, and never executes, resolves or fetches anything a config names.
Every finding's file, line and column come from the entry's own span table, so a
finding lands on the field it is about in the original file and needs no map-back.

The checks are exact-token and exact-flag matches, not substring searches, so a
clean repository stays quiet: ``sudo`` is a finding where it is the command or a
whole argument (or a whole word of a shell string handed to ``-c``), and ``pseudo``
is not.

Options, defaults and severities
--------------------------------
=============================  =======  ==========  =================================
option                         default  severity    what it flags
=============================  =======  ==========  =================================
``forbid_privilege_escalation``  true   HIGH        ``sudo``, ``doas``, ``su``,
                                                    ``pkexec`` as the command or as a
                                                    whole argument of any entry that
                                                    declares a command.
``forbid_auto_approval``         true   HIGH        a field that approves tool calls
                                                    without asking: gemini
                                                    ``trust: true``, kiro
                                                    ``autoApprove`` and roo
                                                    ``alwaysAllow`` that are not
                                                    empty, codex ``approval_mode`` of
                                                    ``auto`` or ``full-auto``.
``forbid_unpinned_runners``      true   MEDIUM      ``npx``, ``bunx``, ``pnpm dlx``,
                                                    ``pnpx`` and ``uvx`` started with a
                                                    package that carries no exact
                                                    version.
``require_local``                false  MEDIUM      a remote entry whose host is not
                                                    loopback (``localhost``,
                                                    ``127.0.0.0/8``, ``::1``).
``remote_url_prefixes``          []     MEDIUM      with a list: a remote URL that does
                                                    not start with a listed prefix,
                                                    and a non-loopback URL that is not
                                                    ``https``.
``allowed_command_prefixes``     []     MEDIUM      with a list: a declared command
                                                    that does not start with a listed
                                                    path prefix.
``flag_env_secrets``             true   LOW         a literal value in an ``env`` entry
                                                    whose name says key, token, secret
                                                    or password. A reference
                                                    (``${NAME}``, ``$NAME``) is fine.
                                                    The value is never put in a
                                                    finding.
=============================  =======  ==========  =================================

The three ``forbid_*`` checks are on by default because each names a hazard the MCP
specification and the vendors document themselves and fires only on a true match.
The prefix policies are site-specific, so they stay off until configured.

Prefix matching is on path or URL boundaries: ``/opt/mcp`` allows ``/opt/mcp/server``
and not ``/opt/mcp-evil/server``, and ``https://api.example.com`` allows
``https://api.example.com/v1`` and not ``https://api.example.com.evil.test``. A
command path is normalized (``/opt/mcp/../../bin/sh`` is ``/bin/sh``) before it is
compared.

Limits
------
* ``.claude/settings.json`` is not a target (a policy file; an ``mcpServers`` block
  there is not documented) and Zed ``context_servers`` project files are unverified.
* TOML spans are the key's first line only (``utils/mcp_config/toml_spans.py``).
* A file that does not parse, or is over the size limit, is reported in the scan's
  notes and skipped; it never produces a finding that quotes the file.
* The shell-string check looks at whole words after ``shlex`` splitting. A word built
  at run time (``"$CMD"``) is not seen.
"""

import logging
import ntpath
import posixpath
import re
import shlex
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    FrozenSet,
    List,
    Literal,
    NamedTuple,
    Optional,
    Tuple,
)
from urllib.parse import urlsplit

from pydantic import AnyUrl, Field

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.models.vocab import TargetType
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    Kind,
    Level,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.get_scan_set import honors_ignore_files, scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.mcp_config import (
    McpConfigParseError,
    McpServerEntry,
    Span,
    detect_format,
    parse_mcp_config_text,
)
from automated_security_helper.utils.mcp_config.readers import MAX_CONFIG_BYTES
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
    relative_display,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RULE_PRIVILEGE_ESCALATION = "MCP-PRIVILEGE-ESCALATION"
RULE_AUTO_APPROVAL = "MCP-AUTO-APPROVAL"
RULE_UNPINNED_RUNNER = "MCP-UNPINNED-RUNNER"
RULE_REMOTE_NOT_LOCAL = "MCP-REMOTE-NOT-LOCAL"
RULE_REMOTE_URL_PREFIX = "MCP-REMOTE-URL-PREFIX"
RULE_REMOTE_URL_INSECURE = "MCP-REMOTE-URL-INSECURE"
RULE_COMMAND_PREFIX = "MCP-COMMAND-PREFIX"
RULE_ENV_SECRET = "MCP-ENV-SECRET"  # pragma: allowlist secret

#: Severity of each rule, and the SARIF level it is written with.
RULE_SEVERITY: Dict[str, str] = {
    RULE_PRIVILEGE_ESCALATION: "HIGH",
    RULE_AUTO_APPROVAL: "HIGH",
    RULE_UNPINNED_RUNNER: "MEDIUM",
    RULE_REMOTE_NOT_LOCAL: "MEDIUM",
    RULE_REMOTE_URL_PREFIX: "MEDIUM",
    RULE_REMOTE_URL_INSECURE: "MEDIUM",
    RULE_COMMAND_PREFIX: "MEDIUM",
    RULE_ENV_SECRET: "LOW",
}
_LEVEL_BY_SEVERITY: Dict[str, Level] = {
    "HIGH": Level.error,
    "MEDIUM": Level.warning,
    "LOW": Level.note,
}

#: Programs that raise the privilege a command runs with.
PRIVILEGE_COMMANDS: FrozenSet[str] = frozenset({"sudo", "doas", "su", "pkexec"})

#: Launchers that fetch and run a package named on their command line.
_NPM_RUNNERS: FrozenSet[str] = frozenset({"npx", "bunx", "pnpx"})
#: Options of those launchers that take a value, so the value is not the package.
_NPM_VALUE_FLAGS: FrozenSet[str] = frozenset(
    {"-p", "--package", "-c", "--call", "--registry", "--cache", "--userconfig"}
)
_UVX_VALUE_FLAGS: FrozenSet[str] = frozenset(
    {
        "-p",
        "--python",
        "--with",
        "--with-requirements",
        "--with-editable",
        "-w",
        "--index",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--default-index",
        "-c",
        "--constraints",
        "--directory",
        "--project",
        "--config-file",
        "--env-file",
        "--refresh-package",
        "--reinstall-package",
        "--upgrade-package",
        "-P",
    }
)

#: An exact version: ``1``, ``1.2``, ``1.2.3``, ``v1.2.3``, ``1.2.3-rc.1``. A range
#: (``^1.2.3``, ``>=1``), a tag (``latest``, ``next``) and the empty string are not.
_EXACT_VERSION = re.compile(r"v?[0-9]+(?:\.[0-9]+){0,3}(?:[-+][0-9A-Za-z.\-+]+)?")

#: Name words that mark an env entry as holding a credential.
_SECRET_NAME_WORDS: FrozenSet[str] = frozenset(
    {"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY", "CREDENTIAL"}
)
#: Values that are settings, not credentials, whatever the name says.
_PLAIN_VALUES: FrozenSet[str] = frozenset(
    {"", "true", "false", "yes", "no", "on", "off", "none", "null", "0", "1"}
)


class PolicyFinding(NamedTuple):
    """One policy violation, located by a pointer inside the entry's file."""

    rule_id: str
    message: str
    #: Pointer, in the entry's source file, of the field the finding is about.
    pointer: str
    #: Whether the finding is about the field's key (a name) rather than its value.
    on_key: bool = False


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


class McpConfigScannerConfigOptions(ScannerOptionsBase):
    forbid_privilege_escalation: Annotated[
        bool,
        Field(
            description=(
                "Flag sudo, doas, su and pkexec used as the command, or as a whole "
                "argument, of a stdio MCP server entry (HIGH). The match is on the "
                "whole word, so a name that merely contains one is not flagged."
            ),
        ),
    ] = True
    forbid_unpinned_runners: Annotated[
        bool,
        Field(
            description=(
                "Flag npx, bunx, pnpm dlx, pnpx and uvx entries whose package has no "
                "exact version, such as `npx -y pkg` or `uvx pkg` (MEDIUM). "
                "`pkg@1.2.3` and `pkg==1.2.3` are pinned; `pkg@latest` and ranges "
                "are not."
            ),
        ),
    ] = True
    forbid_auto_approval: Annotated[
        bool,
        Field(
            description=(
                "Flag settings that approve MCP tool calls without asking (HIGH): "
                "gemini `trust: true`, a non-empty kiro `autoApprove` or roo "
                "`alwaysAllow`, and codex `approval_mode` of `auto` or `full-auto`."
            ),
        ),
    ] = True
    require_local: Annotated[
        bool,
        Field(
            description=(
                "Flag every remote (url, httpUrl, serverUrl) entry whose host is not "
                "loopback (MEDIUM). `localhost`, `127.0.0.0/8` and `::1` count as "
                "local, whichever way the IPv6 address is spelled."
            ),
        ),
    ] = False
    remote_url_prefixes: Annotated[
        List[str],
        Field(
            description=(
                "When not empty, every remote URL must start with one of these "
                "prefixes (MEDIUM), compared on URL boundaries with the scheme and "
                "host in lower case, and a remote URL that is not loopback must be "
                "https (MEDIUM). Empty turns the check off."
            ),
        ),
    ] = []
    allowed_command_prefixes: Annotated[
        List[str],
        Field(
            description=(
                "When not empty, every stdio command must be a path that starts "
                "with one of these prefixes (MEDIUM), compared on path boundaries "
                "after the command is normalized. A bare command name such as `npx` "
                "does not start with a path prefix and is flagged. Empty turns the "
                "check off."
            ),
        ),
    ] = []
    flag_env_secrets: Annotated[
        bool,
        Field(
            description=(
                "Flag an `env` entry whose name says key, token, secret or password "
                "and whose value is a literal rather than a reference such as "
                "`${NAME}` (LOW). The value is never written into the finding."
            ),
        ),
    ] = True


class McpConfigScannerConfig(ScannerPluginConfigBase):
    name: Literal["mcp-config"] = "mcp-config"
    enabled: bool = True
    options: Annotated[
        McpConfigScannerConfigOptions,
        Field(description="Configure the MCP server config policy scanner"),
    ] = McpConfigScannerConfigOptions()


# ---------------------------------------------------------------------------
# Checks (pure: an entry and the options in, findings out)
# ---------------------------------------------------------------------------


def _basename(command: str) -> str:
    """The program name of a command, from a POSIX or Windows path, lower case."""
    name = ntpath.basename(posixpath.basename(command.replace("\\", "/")))
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return name.lower()


def _words(text: str) -> List[str]:
    """The words of a shell string, or the string itself when it will not split."""
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def check_privilege_escalation(entry: McpServerEntry) -> List[PolicyFinding]:
    """``sudo``-class programs as the command or a whole argument."""
    found: List[PolicyFinding] = []
    if entry.command is not None and _basename(entry.command) in PRIVILEGE_COMMANDS:
        found.append(
            PolicyFinding(
                RULE_PRIVILEGE_ESCALATION,
                f"MCP server '{entry.server_name}' runs its command through "
                f"'{_basename(entry.command)}', which raises the privilege the "
                "server runs with.",
                f"{entry.pointer}/command",
            )
        )
    for index, arg in enumerate(entry.args):
        # A whole argument, or a whole word of a shell string given to `-c`.
        candidates = [arg] + (_words(arg) if re.search(r"\s", arg) else [])
        hit = next((c for c in candidates if _basename(c) in PRIVILEGE_COMMANDS), None)
        if hit is not None:
            found.append(
                PolicyFinding(
                    RULE_PRIVILEGE_ESCALATION,
                    f"MCP server '{entry.server_name}' passes "
                    f"'{_basename(hit)}' on its command line (argument "
                    f"{index + 1}), which raises the privilege the server runs "
                    "with.",
                    f"{entry.pointer}/args/{index}",
                )
            )
    return found


def _is_exact_version(version: str) -> bool:
    return _EXACT_VERSION.fullmatch(version) is not None


def _npm_spec_version(spec: str) -> Optional[str]:
    """The version of an npm package spec (``name@1.2.3``), or None when it has none."""
    body = spec.removeprefix("@")
    if "@" not in body:
        return None
    return body.rsplit("@", 1)[1]


def _uv_spec_version(spec: str) -> Optional[str]:
    """The exact version of a uv tool spec (``name==1.2.3`` or ``name@1.2.3``)."""
    if "==" in spec:
        return spec.split("==", 1)[1]
    if "@" in spec and not spec.startswith("@"):
        return spec.split("@", 1)[1]
    return None


def _first_package(
    args: List[str], start: int, value_flags: FrozenSet[str]
) -> Optional[Tuple[int, str]]:
    """The first argument at or after ``start`` that is a package, with its index."""
    index = start
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            continue
        if token.startswith("-"):
            # `--flag=value` carries its value; a bare value flag takes the next word.
            if "=" not in token and token in value_flags:
                index += 1
            index += 1
            continue
        return index, token
    return None


def _package_from_flags(
    args: List[str], flags: FrozenSet[str]
) -> Optional[Tuple[int, str]]:
    """The package named by ``--from``/``-p``-style flags, with the index of its value."""
    for index, token in enumerate(args):
        if token in flags and index + 1 < len(args):
            return index + 1, args[index + 1]
        for flag in flags:
            if flag.startswith("--") and token.startswith(flag + "="):
                return index, token.split("=", 1)[1]
    return None


def check_unpinned_runner(entry: McpServerEntry) -> List[PolicyFinding]:
    """Package launchers started with a package that has no exact version."""
    if entry.command is None:
        return []
    program = _basename(entry.command)
    args = entry.args
    found: Optional[Tuple[int, str, Optional[str]]] = None

    if program in _NPM_RUNNERS or (program == "pnpm" and args[:1] == ["dlx"]):
        start = 1 if program == "pnpm" else 0
        picked = _package_from_flags(args, frozenset({"--package", "-p"}))
        if picked is None:
            picked = _first_package(args, start, _NPM_VALUE_FLAGS)
        if picked is not None:
            index, spec = picked
            found = (index, spec, _npm_spec_version(spec))
    elif program == "uvx":
        picked = _package_from_flags(args, frozenset({"--from"}))
        if picked is None:
            picked = _first_package(args, 0, _UVX_VALUE_FLAGS)
        if picked is not None:
            index, spec = picked
            found = (index, spec, _uv_spec_version(spec))
    if found is None:
        return []
    index, spec, version = found
    if version is not None and _is_exact_version(version):
        return []
    shown = shown_on_one_line(spec)
    return [
        PolicyFinding(
            RULE_UNPINNED_RUNNER,
            f"MCP server '{entry.server_name}' starts '{shown}' through "
            f"'{program}' with no exact version, so each launch can run different "
            "code. Pin it, for example 'name@1.2.3'.",
            f"{entry.pointer}/args/{index}",
        )
    ]


def check_auto_approval(entry: McpServerEntry) -> List[PolicyFinding]:
    """Settings that approve tool calls without asking."""
    found: List[PolicyFinding] = []
    for field, value in entry.auto_approve.items():
        if field == "trust":
            hit = value is True or (
                isinstance(value, str) and value.strip().lower() == "true"
            )
        elif field in ("autoApprove", "alwaysAllow"):
            hit = isinstance(value, list) and len(value) > 0
        elif field == "approval_mode":
            hit = isinstance(value, str) and value.strip().lower() in (
                "auto",
                "full-auto",
            )
        else:
            hit = False
        if hit:
            found.append(
                PolicyFinding(
                    RULE_AUTO_APPROVAL,
                    f"MCP server '{entry.server_name}' sets '{field}', which lets "
                    "its tools run without asking for approval.",
                    f"{entry.pointer}/{field}",
                    on_key=True,
                )
            )
    return found


def host_is_loopback(host: Optional[str]) -> bool:
    """Whether a URL host is this machine: ``localhost`` or a loopback address."""
    if not host:
        return False
    name = host.strip().strip("[]").rstrip(".").lower()
    if name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        address = ip_address(name.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_loopback or bool(mapped is not None and mapped.is_loopback)


def _split_url(url: str) -> Optional[Tuple[str, Optional[str], str]]:
    """(scheme, hostname, normalized url) of an absolute URL, or None."""
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        # Read so that a malformed port raises ValueError here.
        _ = parts.port
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    netloc = parts.netloc.lower()
    rest = url.strip()[len(parts.scheme) + 3 + len(parts.netloc) :]
    return parts.scheme.lower(), host, f"{parts.scheme.lower()}://{netloc}{rest}"


def _prefix_matches(url: str, prefix: str) -> bool:
    """Whether ``url`` starts with ``prefix``, on a URL boundary."""
    if not url.startswith(prefix):
        return False
    if prefix.endswith(("/", "?", "#")) or len(url) == len(prefix):
        return True
    return url[len(prefix)] in "/?#"


def check_remote(
    entry: McpServerEntry,
    require_local: bool,
    prefixes: List[str],
) -> List[PolicyFinding]:
    """Entries that declare a URL: locality, URL prefix and scheme."""
    if entry.url is None:
        return []
    pointer = entry.url_pointer or entry.pointer
    parsed = _split_url(entry.url)
    scheme, host, normalized = parsed if parsed is not None else ("", None, entry.url)
    local = host_is_loopback(host)
    found: List[PolicyFinding] = []
    if require_local and not local:
        found.append(
            PolicyFinding(
                RULE_REMOTE_NOT_LOCAL,
                f"MCP server '{entry.server_name}' is a remote server and its "
                "host is not loopback, but remote servers are not allowed here.",
                pointer,
            )
        )
    if prefixes:
        allowed = [(_split_url(p) or ("", None, p))[2] for p in prefixes]
        if not any(_prefix_matches(normalized, p) for p in allowed):
            found.append(
                PolicyFinding(
                    RULE_REMOTE_URL_PREFIX,
                    f"MCP server '{entry.server_name}' uses a remote URL that does "
                    "not start with any allowed prefix.",
                    pointer,
                )
            )
        if not local and scheme != "https":
            found.append(
                PolicyFinding(
                    RULE_REMOTE_URL_INSECURE,
                    f"MCP server '{entry.server_name}' uses a remote URL that is "
                    "not https and is not loopback.",
                    pointer,
                )
            )
    return found


def _normalized_command_path(command: str) -> str:
    text = command.replace("\\", "/")
    return posixpath.normpath(text) if "/" in text else text


def _path_prefix_matches(path: str, prefix: str) -> bool:
    normalized_prefix = posixpath.normpath(prefix.replace("\\", "/"))
    if normalized_prefix == ".":
        return False
    if path == normalized_prefix:
        return True
    root = (
        normalized_prefix
        if normalized_prefix.endswith("/")
        else normalized_prefix + "/"
    )
    return path.startswith(root)


def check_command_prefix(
    entry: McpServerEntry, prefixes: List[str]
) -> List[PolicyFinding]:
    """Declared commands must live under an allowed path prefix."""
    if not prefixes or entry.command is None:
        return []
    path = _normalized_command_path(entry.command)
    if any(_path_prefix_matches(path, prefix) for prefix in prefixes):
        return []
    return [
        PolicyFinding(
            RULE_COMMAND_PREFIX,
            f"MCP server '{entry.server_name}' runs a command that is not under "
            "any allowed path prefix.",
            f"{entry.pointer}/command",
        )
    ]


def _name_words(name: str) -> List[str]:
    """The upper-case words of an env name: ``GITHUB_API_KEY`` and ``apiKey`` split."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.upper()) if w]


def _is_reference(value: str) -> bool:
    text = value.strip()
    return (
        "${" in text
        or text.startswith("$")
        or (text.startswith("%") and text.endswith("%") and len(text) > 2)
        or (text.startswith("<") and text.endswith(">"))
    )


def check_env_secrets(entry: McpServerEntry) -> List[PolicyFinding]:
    """Literal credentials in ``env``. Never quotes the value."""
    found: List[PolicyFinding] = []
    for key, value in entry.env.items():
        words = _name_words(key)
        compact = "".join(words)
        if not (set(words) & _SECRET_NAME_WORDS or "APIKEY" in compact):
            continue
        if value.strip().lower() in _PLAIN_VALUES or _is_reference(value):
            continue
        found.append(
            PolicyFinding(
                RULE_ENV_SECRET,
                f"MCP server '{entry.server_name}' sets '{shown_on_one_line(key)}' "
                "to a literal value in its env. Use a reference such as "
                "'${NAME}' instead.",
                f"{entry.pointer}/env/{_pointer_token(key)}",
                on_key=True,
            )
        )
    return found


def _pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def evaluate_entry(
    entry: McpServerEntry, options: McpConfigScannerConfigOptions
) -> List[PolicyFinding]:
    """Every policy finding for one entry under ``options``.

    The command checks run for every entry that declares a ``command`` and the
    URL checks for every entry that declares a URL, never by the entry's classed
    ``kind``: an entry spelling both a command and a url is classed remote (the
    url decides the kind), and gating on the kind would let one decoy ``url`` key
    hide a ``sudo`` command from every command check. Which field such a client
    acts on is the vendor's call, so both sides are checked.
    """
    found: List[PolicyFinding] = []
    if entry.command is not None:
        if options.forbid_privilege_escalation:
            found.extend(check_privilege_escalation(entry))
        if options.forbid_unpinned_runners:
            found.extend(check_unpinned_runner(entry))
        found.extend(check_command_prefix(entry, options.allowed_command_prefixes))
    if options.forbid_auto_approval:
        found.extend(check_auto_approval(entry))
    found.extend(
        check_remote(entry, options.require_local, options.remote_url_prefixes)
    )
    if options.flag_env_secrets:
        found.extend(check_env_secrets(entry))
    return found


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------


@ash_scanner_plugin
class McpConfigScanner(ScannerPluginBase[McpConfigScannerConfig]):
    """Policy checks over repo-local MCP server config files, in process."""

    display_name = "MCP config"
    docs_summary = "MCP server config policy"
    covers = ("MCP server config files",)

    #: Entirely in process, so a Python-only scan runs it.
    python_only: ClassVar[bool | None] = True
    #: There is no tool to look for on PATH.
    resolves_tool_off_path: ClassVar[bool] = True
    #: Nothing is fetched, ever.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    #: No network, no extra paths, no variables: the strict default.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). The scanner builds its own
    #: SARIF from the normalized ``McpServerEntry`` model, so the native fields name
    #: that model's attributes.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field="PolicyFinding.rule_id (MCP-PRIVILEGE-ESCALATION, "
            "MCP-AUTO-APPROVAL, MCP-UNPINNED-RUNNER, MCP-REMOTE-NOT-LOCAL, "
            "MCP-REMOTE-URL-PREFIX, MCP-REMOTE-URL-INSECURE, MCP-COMMAND-PREFIX, "
            "MCP-ENV-SECRET)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="RULE_SEVERITY[rule_id] (HIGH, MEDIUM, LOW), written as "
            "result level and properties issue_severity",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="McpServerEntry.source_file",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="McpServerEntry.spans[pointer] line / end_line",
        ),
        column=FacetDecl(
            state=FacetState.MAPPED,
            native_field="McpServerEntry.spans[pointer] col / end_col (JSON); "
            "a TOML key is located by its line only",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="PolicyFinding.message, built from McpServerEntry.server_name",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="the finding names a field of a config file; the server entry's "
            "JSON pointer rides in the result property mcp_server_pointer, and "
            "ash_resource_id is not written, so a suppression binds on file and line",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="an MCP server entry is not a deployable resource type",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="the finding names a launcher argument, not a package inventory row",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="the finding carries no package version",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="the finding carries no package path",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="policy findings carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the rules carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the scanner writes no partialFingerprints; identity is file and line",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="policy findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the remedy is the last sentence of the message; there is no "
            "separate remediation field",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the config text is never quoted into a finding, because an env "
            "value can be a credential",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the rules carry no reference URLs",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="adapter-written PropertyBag tags (mcp-config, security, "
            "tool_name, tool_type)",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties issue_severity, mcp_server_pointer and "
            "mcp_config_format written by the adapter",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="mcp-config",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source="mcp_config_scanner.py: no network call exists; the config "
                "text is read and never resolved or fetched",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SYNTHESIZED,),
                side_reports=(),
                non_finding_artifacts=(),
                consumed_by_deviation="no tool output exists; the SARIF is built "
                "in-process from the normalized entries",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="the scan set filtered to the ten MCP config paths of "
                "utils/mcp_config/readers.py FORMATS",
                covers_note="no target kind names tool configuration files; "
                "source_code is the nearest, and covers says what is read",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.IN_PROCESS,
                external_programs=(),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="the source target is read; the converted target "
                "holds the converter's scripts, which script scanners cover",
                python_only=True,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="first-party Python; no tool is provisioned",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="each rule has its own severity, HIGH, MEDIUM or LOW "
                "(RULE_SEVERITY)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="the scanner reads no ignore file, inline comment or "
                "baseline; ASH suppressions and ignore_paths are the only silencing",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="identity is file and line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="the seven options of McpConfigScannerConfigOptions",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="the base default {0, 1}; the scan is in-process, so "
                "there is no tool exit",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PYPI_PINNED_DEPENDENCY,
                selection_surfaces=(),
                upstream_license="not read",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no prerequisite; a repository with no MCP config files has "
                "nothing to scan",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = McpConfigScannerConfig()
        self.command = "ash-mcp-config-scanner"
        self.tool_type = ScannerToolType.SAST
        self.tool_version = None
        super().model_post_init(context)

    def _forced_binary_precluded_reason(self) -> Optional[str]:
        """mcp-config is entirely Python, so no forced binary satisfies it.

        There is no tool to check for and nothing a ``--binary-path`` record
        could resolve; the record is never consulted for this scanner and the
        docs name it as an exception. Validation passes on its own below either
        way, so the preclusion changes no verdict -- it keeps the debug log from
        claiming a forced binary satisfied a scanner that runs none.
        """
        return "mcp-config runs no external program; there is no binary to force"

    def validate_plugin_dependencies(self) -> bool:
        # Entirely Python: there is no tool to check for.
        return True

    def _options(self) -> McpConfigScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, McpConfigScannerConfigOptions):
            return options
        return McpConfigScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: TargetType,
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Abstract stub: this scanner overrides scan() directly; it is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # -- reading -----------------------------------------------------------------

    def _read_entries(
        self, path: str, display: str, notes: List[str]
    ) -> List[McpServerEntry]:
        """The entries of one config file; a file that cannot be read adds a note."""
        try:
            with open_in_scanned_tree(
                path, self._require_context().source_dir
            ) as handle:
                data = handle.read(MAX_CONFIG_BYTES + 1)
        except TreeInputRefused:
            notes.append(
                f"{display}: skipped, the path is not read under the scanned-tree rule"
            )
            return []
        except OSError:
            notes.append(f"{display}: skipped, the file could not be read")
            return []
        if len(data) > MAX_CONFIG_BYTES:
            notes.append(f"{display}: skipped, the file is too large")
            return []
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            notes.append(f"{display}: skipped, the file is not UTF-8")
            return []
        try:
            return parse_mcp_config_text(text, display)
        except McpConfigParseError as error:
            where = f" at line {error.line}, column {error.col}" if error.line else ""
            # The reason names a position and never quotes the file.
            notes.append(f"{display}: skipped, {error.reason}{where}")
            return []

    # -- results -----------------------------------------------------------------

    @staticmethod
    def _region(entry: McpServerEntry, finding: PolicyFinding) -> Optional[Region]:
        relative = finding.pointer[len(entry.pointer) :]
        span: Optional[Span] = (
            entry.key_span(relative) if finding.on_key else entry.span(relative)
        )
        if span is None:
            return None
        return Region(
            startLine=span.line,
            endLine=span.end_line,
            startColumn=span.col,
            endColumn=span.end_col,
        )

    def build_result(
        self, entry: McpServerEntry, finding: PolicyFinding, tool_type: str
    ) -> Result:
        """One SARIF result for one policy finding. Quotes no config value."""
        severity = RULE_SEVERITY[finding.rule_id]
        region = self._region(entry, finding)
        if region is None:
            region = Region(startLine=1, endLine=1)
        properties = PropertyBag(
            tags=[
                "mcp-config",
                "security",
                f"tool_name::{self._require_config().name}",
                f"tool_type::{tool_type}",
            ],
        )
        setattr(properties, "issue_severity", severity)  # noqa: B010
        setattr(properties, "mcp_server_pointer", entry.pointer)  # noqa: B010
        setattr(properties, "mcp_config_format", entry.format_id)  # noqa: B010
        return Result(
            ruleId=finding.rule_id,
            level=_LEVEL_BY_SEVERITY[severity],
            kind=Kind.fail,
            message=Message(root=Message1(text=finding.message)),
            properties=properties,
            locations=[
                Location(
                    id=1,
                    physicalLocation=PhysicalLocation(
                        root=PhysicalLocation2(
                            artifactLocation=ArtifactLocation(uri=entry.source_file),
                            region=region,
                        )
                    ),
                )
            ],
        )

    def evaluate_files(self, files: Dict[str, str], notes: List[str]) -> List[Result]:
        """Results for ``{display path: absolute path}``, sorted by file then place."""
        options = self._options()
        tool_type = str(getattr(self.tool_type, "value", self.tool_type))
        results: List[Result] = []
        for display in sorted(files):
            for entry in self._read_entries(files[display], display, notes):
                for finding in evaluate_entry(entry, options):
                    results.append(self.build_result(entry, finding, tool_type))
        return results

    def _empty_report(self, target: Path) -> SarifReport:
        return self._report(target, [], 0, [])

    def _report(
        self, target: Path, results: List[Result], errors_before: int, notes: List[str]
    ) -> SarifReport:
        tool = Tool(
            driver=ToolComponent(
                name="mcp-config",
                fullName="ASH MCP server config policy scanner",
                organization="awslabs",
                version=self.tool_version,
                informationUri=AnyUrl(
                    "https://github.com/awslabs/automated-security-helper"
                ),
                rules=[],
            )
        )
        invocation = Invocation(
            commandLine=self.command,
            arguments=["--target", get_shortest_name(input=target)],
            startTimeUtc=self.start_time,
            endTimeUtc=self.end_time,
            executionSuccessful=True,
            exitCode=self.exit_code,
            exitCodeDescription="\n".join([*self.errors[errors_before:], *notes]),
            workingDirectory=ArtifactLocation(uri=get_shortest_name(input=target)),
            properties=PropertyBag.model_validate({"tool": tool}),
        )
        return SarifReport(
            version="2.1.0",
            runs=[Run(tool=tool, invocations=[invocation], results=results)],
        )

    def scan(
        self,
        target: Path,
        target_type: TargetType,
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Read every MCP config file of the scan set and report policy violations.

        Only the source target holds config files. The converted target holds the
        converter's scripts, which the script scanners read, so it is reported empty.
        """
        self.exit_code = 0
        self.start_time = None
        self.end_time = None
        self.output = []
        self._reset_errors()
        errors_before = len(self.errors)

        if not Path(target).exists() or not any(Path(target).iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return self._empty_report(target)

        validated = self._pre_scan(
            target=target, target_type=target_type, config=config
        )
        if not validated or not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        results_file = self._require_results_dir().joinpath(
            target_type, "results_sarif.sarif"
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        notes: List[str] = []
        results: List[Result] = []
        if target_type == "source":
            context = self._require_context()
            candidates = scan_set(
                source=context.source_dir,
                output=context.output_dir,
                honor_ignore_files=honors_ignore_files(context.config),
                run_id=getattr(context, "run_id", None),
            )
            files: Dict[str, str] = {}
            for path in candidates:
                display = relative_display(path, context.source_dir)
                if detect_format(display) is not None:
                    files[display] = path
            results = self.evaluate_files(files, notes)
            for note in notes:
                ASH_LOGGER.warning(shown_on_one_line(note), extra=NO_MARKUP)

        self.end_time = datetime.now(timezone.utc)
        sarif_report = self._report(target, results, errors_before, notes)
        with open_for_write(results_file) as handle:
            handle.write(
                sarif_report.model_dump_json(exclude_none=True, exclude_unset=True)
            )
        self._post_scan(target=target, target_type=target_type)
        return sarif_report
