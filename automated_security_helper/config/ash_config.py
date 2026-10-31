import json
import errno
import os
import secrets
import stat
from datetime import date, datetime, timezone
from pathlib import Path
import re
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)
from typing import (
    Annotated,
    Any,
    Callable,
    List,
    Dict,
    FrozenSet,
    Iterable,
    Literal,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    get_args,
)

import yaml
from automated_security_helper.utils.redacted_model import (
    env_resolved_scalar,
    RedactedSection,
    carry_environment_values,
    environment_strings,
    first_env_scalar,
    without_env_scalars,
)
from automated_security_helper.base.converter_plugin import ConverterPluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    EXTRACTION_LIMIT_OPTIONS,
    ArchiveConverterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverterConfig,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_ENV_VAR_ALLOWLIST,
    ASH_CONFIG_ENV_VAR_PREFIX,
    ASH_DEFAULT_SEVERITY_LEVEL,
    is_readable_environment_name,
    is_refused_config_environment_name,
)
from automated_security_helper.config.plugin_section_names import (
    # The one spelling rule for a known plugin's section name, shared with the
    # document loader, which folds once, before references are recorded and
    # before `extends` merges.
    folded_section_name as _folded_section_name,
)
from automated_security_helper.core.exceptions import ASHConfigUnsetVariableError
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
    expiration_date_problem,
    refuse_an_expiration_that_is_not_text,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CSVReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.cyclonedx_reporter import (
    CycloneDXReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    GitLabCycloneDXReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HTMLReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
    JUnitXMLReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    OCSFReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.spdx_reporter import (
    SPDXReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.yaml_reporter import (
    YAMLReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    SARIFReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
    ActionlintScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    CfnGuardScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    GitleaksScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    ZizmorScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScannerConfig,
)
from automated_security_helper.utils.config_trust import ConfigProvenance
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.report_yaml import NoCommandLineDumper


def config_env_var_is_interpolatable(var_name: str) -> bool:
    """Whether a config file's ``!ENV`` reference to ``var_name`` may read it.

    The set and the reasoning behind it live on
    ``ASH_CONFIG_ENV_VAR_PREFIX`` / ``ASH_CONFIG_ENV_VAR_ALLOWLIST`` in
    ``core/constants.py``, and the rule over them is
    ``core.constants.is_readable_environment_name``, which this function calls and
    so does the container run's ``_readable_environment_values``, so the config
    loader and the container cannot drift apart. This function stays the name the
    config loader and its tests use.

    The comparison is against the name exactly as the config file wrote it, with
    no case folding.

    Case folding was tried and withdrawn. The argument for it was Windows, which
    ASH v3 supports directly in local mode and where ``os.environ`` upper-cases
    its keys, so ``os.environ.get("aws_secret_access_key")`` returns what
    ``AWS_SECRET_ACCESS_KEY`` holds. That is true of ``os.environ`` and changes
    nothing here, because the names this function admits are those beginning with
    a literal ``ASH_`` plus three exact upper-case entries, and on Windows each of
    those reads back the variable it names. No spelling passes the check and then
    reads something outside it, so folding admitted more spellings without
    excluding any.

    The consequence is worth naming rather than hiding: on Windows a config
    writing ``${aws_region:None}`` does not resolve, even though Windows itself
    would find that variable. The reference is left as a literal and a warning
    names it, the docs and ASH's own config write these names in upper case, and
    ``tests/unit/config/test_config_env_interpolation.py`` pins both directions so
    that reintroducing folding is a decision rather than a drift.

    A name ``config_env_var_is_secret_shaped`` matches is not admitted either;
    that check does fold case, since it only ever excludes.
    """
    if config_env_var_is_secret_shaped(var_name):
        return False
    return is_readable_environment_name(var_name)


def config_env_var_is_secret_shaped(var_name: str) -> bool:
    """Whether ``var_name`` is a credential's name, so a config may not read it.

    The one name rule, ``core.constants.is_refused_config_environment_name``: a
    listed name, a name ending in one of ``ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES``,
    and any name the masking rule classes as holding a secret
    (``is_secret_shaped_environment_name``: a qualified, glued or
    digit-suffixed form such as ``ASH_API_KEY_PROD``, ``ASH_API_KEY2`` or
    ``ASH_APIKEY``). This loader read the suffix tuple alone, so it admitted
    names the same module masked in the stream output; the config validator
    reads this function too, so the two cannot drift again.
    """
    return is_refused_config_environment_name(var_name)


# The recognizer: whether a scalar STARTS as a reference, for the YAML implicit
# resolver, the TOML walk and every "is this a reference" question. Group 2
# captures the colon itself, so that ``${VAR}`` and ``${VAR:}`` can be told
# apart. Group 3 runs to the first closing brace on the same line, which is
# enough to recognize a reference; the default's real extent (a default may
# hold a brace pair, ``${VAR:{}}``) is read by ``read_env_reference``, the one
# parser the resolvers use. A newline never belongs to a reference: a TOML
# multi-line string or a folded YAML scalar that starts like one is the file's
# own text (the greedy ``.*`` this pattern once used stopped at a newline too).
ENV_REFERENCE_PATTERN = re.compile(r"^\${(\w+)(:?)([^}\r\n]*)}")
_ENV_REFERENCE_HEAD = re.compile(r"^\${(\w+)(:?)")


class EnvReference(NamedTuple):
    """A ``${VAR}`` or ``${VAR:default}`` reference at the start of a scalar, as
    ``read_env_reference`` reads it: the variable, whether a colon was written,
    the default's text (empty for ``${VAR}`` and for ``${VAR:}``), the reference
    as written, and the text after it."""

    var_name: str
    colon: bool
    default_text: str
    text: str
    rest: str


def read_env_reference(value: str) -> Optional[EnvReference]:
    """The reference ``value`` starts with, or None when it starts with none.

    The default runs to the closing brace that pairs with the reference's
    opening one, so a default may hold brace pairs (``${VAR:{}}``; a regex
    default ``${VAR:\\d{3}}``). A brace left open (``${VAR:{a}``) closes no
    reference, and a newline inside one ends the reading too: neither is a
    reference, so the value is its own text. ``${VAR-x}`` (text before the
    brace with no colon) is read with that text as its default, which the
    resolvers refuse (``env_reference_left_as_written``).
    """
    head = _ENV_REFERENCE_HEAD.match(value)
    if head is None:
        return None
    depth = 0
    for index in range(head.end(), len(value)):
        character = value[index]
        if character in "\r\n":
            return None
        if character == "{":
            depth += 1
        elif character == "}":
            if depth == 0:
                return EnvReference(
                    var_name=head.group(1),
                    colon=bool(head.group(2)),
                    default_text=value[head.end() : index],
                    text=value[: index + 1],
                    rest=value[index + 1 :],
                )
            depth -= 1
    return None


def env_reference_left_as_written(reference: EnvReference) -> Optional[str]:
    """Why ``reference`` resolves nothing, or None when it resolves.

    The one rule for the loader (``resolve_env_references``) and for the
    record's quiet reading (config_validator._quietly_resolved), so the two
    cannot drift: ``"secret"`` for a credential-shaped name; ``"unlisted"`` for
    a name a configuration file may not read; ``"not-a-reference"`` for
    ``${VAR-x}``, ``${VAR x}``, ``${VAR.x}`` (text before the brace with no
    colon: the shell's other default spellings, or a name this pattern does not
    read); ``"composite"`` for a reference followed by another closing brace
    (``${A}/${B}``, ``${A:x}${B}``, ``${A}x}``). A value holds one reference,
    at its start, whether or not that reference wrote a default; one that goes
    on to another brace is the file's own text. Each is left exactly as
    written rather than replaced: a literal that still reads as a reference is
    visible in the artifact and refused by any typed field, whereas a value
    with a reference resolved in its middle is not.
    """
    if config_env_var_is_secret_shaped(reference.var_name):
        return "secret"
    if not config_env_var_is_interpolatable(reference.var_name):
        return "unlisted"
    if not reference.colon and reference.default_text:
        return "not-a-reference"
    if "}" in reference.rest:
        return "composite"
    return None


def env_reference_value(reference: EnvReference) -> Tuple[Optional[str], bool]:
    """What ``reference`` resolves to, and whether its default supplied it.

    ``(value, False)`` when the variable is set; ``(default, True)`` when it is
    unset and a colon was written (the default ``None`` and an empty default
    both read as ``""``); ``(None, False)`` when it is unset with no colon,
    which the loader reports as an error and the quiet reading as no value.
    """
    resolved = os.environ.get(reference.var_name, None)
    if resolved is not None:
        return resolved, False
    if not reference.colon:
        return None, False
    default = reference.default_text
    return ("" if default == "None" else default), True


def resolve_env_references(value: str) -> Optional[str]:
    """Resolve the ``${VAR}`` or ``${VAR:default}`` reference a config scalar starts with.

    This is the body of the YAML ``!ENV`` constructor, shared so that a TOML
    config source resolves references by exactly the same rule. Only names
    ``config_env_var_is_interpolatable`` admits are read; any other reference is
    left as written, and that check comes before the environment is consulted.
    The reference is read by ``read_env_reference`` and judged by
    ``env_reference_left_as_written`` and ``env_reference_value``, the three
    functions the record's quiet reading shares; what this function adds is the
    reporting (the warnings, the error for an unset variable) and the marking
    of the result as read from the environment.

    ``${VAR:default}`` falls back to ``default`` when ``VAR`` is unset (the
    default ``None`` and an empty default both resolve to ``None``). ``${VAR}``
    has no fallback, so an unset ``VAR`` raises ``ASHConfigUnsetVariableError``
    naming it: substituting nothing would read as the variable being set to
    nothing, and the literal ``${VAR}`` would reach a reporter as a bucket or
    region name.

    The bare form did not resolve before. The text to replace was rebuilt as
    ``":".join(groups)``, which appended a colon the bare form had not written,
    so the replacement never matched and ``${VAR}`` stayed as written whatever
    the environment held. The text replaced is now the text the reference spans.
    """
    reference = read_env_reference(value)
    if reference is None:
        return value
    var_name, colon, default_text = (
        reference.var_name,
        reference.colon,
        reference.default_text,
    )
    ASH_LOGGER.debug(f"Evaluating env var match: {reference.text}")
    reason = env_reference_left_as_written(reference)
    if reason == "secret":
        ASH_LOGGER.warning(
            f"Not reading environment variable {var_name} into the configuration: "
            "a configuration file may not read a variable whose name is a "
            "credential's. The reference is left as written."
        )
        return value.strip()
    if reason == "unlisted":
        # Left exactly as written rather than replaced with its default. A
        # literal that still reads as a reference is visible in the artifact
        # and refused by any typed field, whereas the default is
        # indistinguishable from the variable simply not being set. See
        # ASH_CONFIG_ENV_VAR_ALLOWLIST in core/constants.py for which names
        # resolve.
        ASH_LOGGER.warning(
            f"Not reading environment variable {var_name} "
            "into the configuration. A configuration file "
            "may reference names beginning with "
            f"{ASH_CONFIG_ENV_VAR_PREFIX} and these names: "
            f"{', '.join(ASH_CONFIG_ENV_VAR_ALLOWLIST)}. "
            "The reference is left as written."
        )
        return value.strip()
    if reason == "not-a-reference":
        # ``${VAR-x}``, ``${VAR x}``, ``${VAR.x}``: not a reference this
        # function resolves, so it is left as written, as it always was.
        return value.strip()
    if reason == "composite":
        # ``${A}/${B}``, ``${A:x}${B}``, ``${A}x}``: another closing brace after
        # the reference. The no-default form was always left as written; the
        # defaulted form once resolved the first reference and kept the second
        # as a literal in the middle of the value, where a typed field accepts
        # it, so the two forms now read alike and the value says why.
        ASH_LOGGER.warning(
            f"Not resolving the value starting with {reference.text}: it goes on "
            "to another closing brace, and a configuration value holds one "
            "${VAR} or ${VAR:default} reference, at its start. The value is "
            "left as written."
        )
        return value.strip()
    if colon and default_text.startswith("-"):
        # The shell's ``${VAR:-default}``. ASH reads everything after the colon
        # as the default, so this one starts with "-". Said whether or not the
        # variable is set: the default is wrong the day it is not. The default
        # is the file's text and is not quoted.
        ASH_LOGGER.warning(
            f"The reference to {var_name} writes its default after ':-', as a "
            "shell does. A configuration reads ${VAR:default}, everything after "
            "the colon, so this default starts with '-'. Write the default right "
            "after the colon to leave the '-' out."
        )
    resolved_var, used_default = env_reference_value(reference)
    if resolved_var is None:
        raise ASHConfigUnsetVariableError(
            f"Environment variable {var_name} is not set, and the "
            f"configuration references it as ${{{var_name}}}, which has no "
            f"default. Set {var_name}, or write ${{{var_name}:None}} (or "
            "another default after the colon) to allow it to be unset.",
            variable=var_name,
        )
    if used_default:
        default_val: Optional[str] = default_text
        if default_val == "None":
            default_val = None
        ASH_LOGGER.warning(
            f"Environment variable {var_name} not set, using default value of "
            f"{default_val}"
        )
    full_value = resolved_var + reference.rest
    if full_value.strip() == "":
        return None
    # Marked as env-resolved so a typed field reads the text as its own
    # type, a refusal can name the variable, and a shown surface can print
    # what the value stands for (the section base's before-validator; see
    # utils/redacted_model.EnvResolvedScalar). What it prints depends on the
    # branch taken: the reference without its default when the variable was
    # read (the default is not the level in effect), the value itself when the
    # default was used (the file's own text, and what is being graded).
    shown = (
        full_value.strip()
        if used_default
        else ("${" + var_name + "}" + reference.rest).strip()
    )
    return env_resolved_scalar(
        full_value.strip(), var_name, shown, from_environment=not used_default
    )


class _NoAliasSafeLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` that refuses YAML aliases; see ``load_config_yaml``."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            event = self.peek_event()
            raise yaml.composer.ComposerError(
                None,
                None,
                f"found the alias *{event.anchor}; ASH configuration does not "
                "accept YAML aliases, so write the value out where it is used",
                event.start_mark,
            )
        return super().compose_node(parent, index)


def _load_single_document(loader_class: type, stream: Any) -> Any:
    # What yaml.load does, with the loader class given: one document, then the
    # loader's resources released.
    loader = loader_class(stream)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def load_config_yaml(stream: Any) -> Any:
    """Parse YAML that configures ASH: safe tags only, and no aliases.

    Every reader of an ASH config file, workspace policy, MCP profile or
    client-supplied config fragment parses with this, or with
    ``load_yaml_config``, which adds ``!ENV`` on top of it.

    Why no aliases: an alias is a reference to an anchored node, and a few
    hundred bytes of nested aliases stand for gigabytes once the parsed config
    is walked or serialized. A scan writes its config into its results, and MCP
    ``get_config`` returns it, so such a file exhausted memory in the process
    reading it; an MCP server resolves a client's config in the process every
    session shares. Parsing does not expand aliases, so a read-size bound cannot
    stop this. None of the YAML files in ASH's repository uses an alias, and a
    config that repeats a value can write it out where it is used. Anchors with
    no alias referring to them are harmless and still parse.
    """
    return _load_single_document(_NoAliasSafeLoader, stream)


class EnvReferenceNotResolved(Exception):
    """``load_yaml_config(..., env="refuse")`` met an ``!ENV`` value.

    ``line`` is 1-based. ``config_sources.read_config_file`` turns this into the
    ``ASHConfigEnvNotResolvedError`` that names the file.
    """

    def __init__(self, line: int) -> None:
        super().__init__(f"!ENV at line {line}")
        self.line = line


#: What ``load_yaml_config(..., env="written")`` puts before a reference the file
#: tags explicitly, so the reference reads as the file wrote it.
EXPLICIT_ENV_TAG = "!ENV "


def load_yaml_config(
    stream: Any, env: Literal["resolve", "refuse", "keep", "written"] = "resolve"
) -> Any:
    """Parse an ASH YAML config, resolving ``!ENV`` references as it goes.

    With ``env="refuse"``, the first ``!ENV`` value, tagged or matched by the
    implicit resolver, raises ``EnvReferenceNotResolved`` before anything is read
    from the environment. With ``env="keep"``, each one is the reference as
    written, which is what a raw view of the file shows. ``env="written"`` is
    ``keep``, except that a value the file tags ``!ENV`` itself keeps the tag
    (``EXPLICIT_ENV_TAG``): the reference exactly as the file wrote it, which is
    what a record of the configuration holds (``config/environment_record.py``).

    Aliases are refused, as in ``load_config_yaml``.
    """

    # Use a local subclass to avoid mutating the global SafeLoader
    class _AshConfigLoader(_NoAliasSafeLoader):
        def compose_scalar_node(self, anchor):
            # The tag is known only from the event: a node the implicit resolver
            # tagged !ENV and one the file tagged look the same once composed.
            explicit = self.peek_event().tag == "!ENV"
            node = super().compose_scalar_node(anchor)
            node.ash_explicit_env = explicit
            return node

        def construct_mapping(self, node, deep=False):
            mapping = super().construct_mapping(node, deep=deep)
            if env == "written":
                # A key written more than once keeps its LAST value, at the
                # position of its FIRST writing: that is how a dict takes a
                # repeated key. The record of what a file read pairs the
                # written and the resolved readings by key and keeps, for a
                # name two entries come to (a plain key and a reference that
                # resolves to it), the entry written last; it reads that order
                # from this mapping. So each kept entry is moved to where its
                # last writing was: the mapping's order is the write order of
                # the entries the loader kept.
                for key_node, _ in node.value:
                    key = self.construct_object(key_node, deep=deep)
                    if key in mapping:
                        mapping[key] = mapping.pop(key)
            return mapping

    _AshConfigLoader.add_implicit_resolver("!ENV", ENV_REFERENCE_PATTERN, None)

    def constructor_env_variables(loader, node):
        if env == "refuse":
            raise EnvReferenceNotResolved(node.start_mark.line + 1)
        if env == "keep":
            return loader.construct_scalar(node)
        if env == "written":
            scalar = loader.construct_scalar(node)
            if getattr(node, "ash_explicit_env", False):
                return f"{EXPLICIT_ENV_TAG}{scalar}"
            return scalar
        return resolve_env_references(loader.construct_scalar(node))

    _AshConfigLoader.add_constructor("!ENV", constructor_env_variables)
    # !ENV is bounded to ASH_CONFIG_ENV_VAR_PREFIX/ASH_CONFIG_ENV_VAR_ALLOWLIST by
    # resolve_env_references above.
    return _load_single_document(_AshConfigLoader, stream)


class TaggedReference(str):
    """A reference ``AshConfig.save(as_written=True)`` writes tagged ``!ENV``, so
    the file reads it from the environment when it is loaded. Any other string
    that reads as a reference is still written quoted."""

    __slots__ = ()


def represent_tagged_reference(
    dumper: Any, value: "TaggedReference"
) -> yaml.ScalarNode:
    """``value`` as an ``!ENV`` scalar, the reference without a tag it wrote."""
    return dumper.represent_scalar("!ENV", str(value).removeprefix(EXPLICIT_ENV_TAG))


class _QuotedStr(str):
    """A string ``_rewrite_config_with_entry`` writes quoted, as ``_ConfigDumper``
    would, among existing values it writes as they were."""

    __slots__ = ()


class _EntryRewriteDumper(yaml.SafeDumper):
    pass


_EntryRewriteDumper.add_representer(
    _QuotedStr,
    lambda dumper, value: dumper.represent_scalar(
        "tag:yaml.org,2002:str", str(value), style="'"
    ),
)


def _quote_references(value: Any) -> Any:
    """``value`` with every string that reads as ``!ENV`` marked to be quoted."""
    if isinstance(value, dict):
        return {k: _quote_references(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_quote_references(v) for v in value]
    if isinstance(value, str) and ENV_REFERENCE_PATTERN.match(value):
        return _QuotedStr(value)
    return value


# Define BuildConfig class
class BuildConfig(RedactedSection):
    """Configuration model for build-time settings."""

    model_config = ConfigDict(extra="forbid")

    build_mode: Annotated[
        Literal["ONLINE", "OFFLINE"],
        Field(
            description=(
                "Not used: nothing reads this setting, so it changes neither the "
                "container image build nor the scan. To scan offline, pass "
                "--offline or set ASH_OFFLINE."
            )
        ),
    ] = "ONLINE"
    tool_install_scripts: Annotated[
        Dict[str, List[str]],
        Field(
            description=(
                "Not used: nothing reads this setting, so no script listed here "
                "runs. Map of tool names to their installation scripts."
            )
        ),
    ] = {}
    custom_scanners: Annotated[
        List[ScannerPluginBase],
        Field(
            max_length=0,
            description=(
                "Not supported: nothing reads these entries, so the list must "
                "stay empty. Configure scanners under their own sections."
            ),
        ),
    ] = []

    @field_validator("custom_scanners", mode="before")
    @classmethod
    def _refuse_custom_scanner_entries(cls, value):
        """A non-empty list is refused by name: nothing loads these entries.

        Nothing reads the field after validation, so an entry that validated
        became configuration that silently did nothing, and before this check
        a non-empty entry usually died inside the plugin base's own
        validation with an unnamed TypeError instead (pydantic does not wrap
        a TypeError). The empty default and an absent key keep validating,
        which is every config without the key. A scanner instance passed from
        Python is refused as well: no production code builds the field, and
        an instance in it would be just as dead. The length limit in the
        field's declaration says the same to the schema.

        Every non-empty list is refused here, one holding an environment
        reference included. This validator runs before the section base's
        reference walk, and the walk does not refuse an entry slot that holds
        a model: a list passed on to it went to the scanner model's own
        validation, whose error renders the resolved text as ``input_value``.

        Every non-empty value draws this one refusal, whatever slot a
        reference sits in. The reference walk's own refusal is not used here:
        its advice is to write the value in the file, and the field never
        accepts one, so following it would end in this refusal anyway. The
        message names the field, and the variable when a list item, a mapping
        value or a mapping key holds a reference (``first_env_scalar`` reads a
        mapping's keys before its values, so a reference used as a key names
        the key's variable). The check
        reads only ``.variable`` from the first scalar in document order (for
        a YAML ``!!set``, which keeps no order, the one with the smallest
        variable name) and never the scalar's text, never returns it and never raises with it,
        so no part of the resolved value reaches the message.
        """
        if value:
            message = (
                "build.custom_scanners is not supported: its entries are never "
                "loaded, so a non-empty list is refused rather than accepted "
                "as configuration that does nothing. Remove the entries, and "
                "configure scanners under their own sections."
            )
            reference = first_env_scalar(value)
            if reference is not None:
                message += (
                    f" The value holds an environment reference ({reference.variable})."
                )
            raise ValueError(message)
        return value


def _merge_config_values(base: Any, overlay: Any) -> Any:
    """Merge two raw config values, ``overlay`` winning key by key.

    Model instances are dumped first so that a value built in Python merges the
    same way as one read from YAML. An ``overlay`` instance is dumped with only
    the fields it was built with: dumped whole, each default it was never given
    replaced the value ``base`` set for that key. Anything that is not a mapping
    on both sides is replaced by ``overlay`` whole.
    """
    if isinstance(base, BaseModel):
        base = base.model_dump()
    if isinstance(overlay, BaseModel):
        overlay = overlay.model_dump(exclude_unset=True)
    if not (isinstance(base, dict) and isinstance(overlay, dict)):
        return overlay
    merged = dict(base)
    for key, value in overlay.items():
        merged[key] = (
            _merge_config_values(merged[key], value) if key in merged else value
        )
    return merged


def field_name_spellings(segment_cls: type[BaseModel]) -> Dict[str, str]:
    """Map each declared field name to its alias, where the two differ.

    Read from ``model_fields``, so a plugin field declared with an alias later is
    covered without being listed anywhere. The config linter reads this too, so
    its warning about the field-name spelling says what actually happens to it.
    """
    return {
        field_name: info.alias
        for field_name, info in segment_cls.model_fields.items()
        if info.alias and info.alias != field_name
    }


class _PluginConfigSegment(RedactedSection):
    """Base for the scanner, reporter and converter config segments.

    A plugin field declared with a hyphenated alias (``gitlab-sast``) differs from
    its Python field name (``gitlab_sast``), and these segments do not set
    ``populate_by_name``. Without the validator below, a key written with the
    field name landed in the ``extra="allow"`` bucket, unvalidated, while the
    declared field kept its defaults. ``get_plugin_config`` by the alias then
    returned the defaults, while the runtime lookup by class name could reach the
    extras copy -- for a scanner it did not, so ``cdk_nag: {enabled: false}``
    left cdk-nag enabled.

    ``populate_by_name`` is not the fix, because of the case where both keys are
    present. That happens on every ``--config-overrides`` run that touches an
    aliased plugin, not only in a hand-written config: ``apply_config_overrides``
    round-trips through ``model_dump()``, which is keyed by field name, so the
    file's settings come back under ``gitlab_sast`` while the override adds
    ``gitlab-sast`` holding only the overridden key. Pydantic would keep one of
    the two whole, silently reverting either the override or the rest of the
    file. They are merged key by key instead, the alias -- the documented
    spelling -- winning where both set the same key. A hand-written config with
    both is also flagged by ``ash config lint``.
    """

    @model_validator(mode="before")
    @classmethod
    def _read_field_name_spellings_as_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        # The spelling other than the declared one already read for each
        # declared key: the field-name spelling here, a variant below.
        seen_variant: Dict[str, str] = {}
        for field_name, alias in field_name_spellings(cls).items():
            if field_name not in data:
                continue
            seen_variant[alias] = field_name
            data = dict(data)
            field_name_value = data.pop(field_name)
            if alias in data:
                data[alias] = _merge_config_values(field_name_value, data[alias])
            else:
                data[alias] = field_name_value
        # Any other spelling of a declared plugin's name (case, "-"/"_",
        # separators dropped) is that plugin's section too. Left as written it
        # landed in the extra bucket, unvalidated, so a value the declared
        # spelling refuses loaded into an extras copy a lookup by class name
        # could reach, while the construction lookup by the declared key got
        # the defaults. The declared spelling wins where both set a key, as
        # for the field-name spelling above. Two non-declared spellings of one
        # plugin name no winner and are refused as ambiguous, the same rule the
        # document loader applies per file (plugin_section_names). The
        # field-name spelling is one of them: the loader does not take it for
        # the declared spelling, so a variant beside it is refused here too,
        # where it was merged in silently. A document load folds there and
        # never reaches this branch; it runs for a configuration built from a
        # dict directly.
        declared = {info.alias or name for name, info in cls.model_fields.items()}
        folded = {_folded_section_name(key): key for key in declared}
        for key in list(data):
            if not isinstance(key, str) or key in declared:
                continue
            target = folded.get(_folded_section_name(key))
            if target is None:
                continue
            earlier = seen_variant.get(target)
            if earlier is not None:
                raise ValueError(
                    f"{earlier} and {key} are two spellings of the {target} "
                    "section: ambiguous, keep one"
                )
            seen_variant[target] = key
            data = dict(data)
            variant_value = data.pop(key)
            if target in data:
                data[target] = _merge_config_values(variant_value, data[target])
            else:
                data[target] = variant_value
        return data


class ConverterConfigSegment(_PluginConfigSegment):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
        extra="allow",
    )

    __pydantic_extra__: Dict[str, Any | ConverterPluginConfigBase] = {}

    archive: Annotated[
        ArchiveConverterConfig,
        Field(description="Configure the options for the ArchiveConverter"),
    ] = ArchiveConverterConfig()
    jupyter: Annotated[
        JupyterConverterConfig,
        Field(description="Configure the options for the JupyterConverter"),
    ] = JupyterConverterConfig()


class ScannerConfigSegment(_PluginConfigSegment):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
        extra="allow",
    )

    __pydantic_extra__: Dict[str, Any | ScannerPluginConfigBase] = {}

    actionlint: Annotated[
        ActionlintScannerConfig,
        Field(description="Configure the options for actionlint"),
    ] = ActionlintScannerConfig()
    bandit: Annotated[
        BanditScannerConfig, Field(description="Configure the options for Bandit")
    ] = BanditScannerConfig()
    cdk_nag: Annotated[
        CdkNagScannerConfig,
        Field(description="Configure the options for CdkNag", alias="cdk-nag"),
    ] = CdkNagScannerConfig()
    cfn_guard: Annotated[
        CfnGuardScannerConfig,
        Field(description="Configure the options for cfn-guard", alias="cfn-guard"),
    ] = CfnGuardScannerConfig()
    cfn_lint: Annotated[
        CfnLintScannerConfig,
        Field(description="Configure the options for cfn-lint", alias="cfn-lint"),
    ] = CfnLintScannerConfig()
    cfn_nag: Annotated[
        CfnNagScannerConfig,
        Field(description="Configure the options for CfnNag", alias="cfn-nag"),
    ] = CfnNagScannerConfig()
    checkov: Annotated[
        CheckovScannerConfig, Field(description="Configure the options for Checkov")
    ] = CheckovScannerConfig()
    detect_secrets: Annotated[
        DetectSecretsScannerConfig,
        Field(
            description="Configure the options for DetectSecrets",
            alias="detect-secrets",
        ),
    ] = DetectSecretsScannerConfig()
    gitleaks: Annotated[
        GitleaksScannerConfig, Field(description="Configure the options for Gitleaks")
    ] = GitleaksScannerConfig()
    grype: Annotated[
        GrypeScannerConfig, Field(description="Configure the options for Grype")
    ] = GrypeScannerConfig()
    npm_audit: Annotated[
        NpmAuditScannerConfig,
        Field(description="Configure the options for NpmAudit", alias="npm-audit"),
    ] = NpmAuditScannerConfig()
    opengrep: Annotated[
        OpengrepScannerConfig, Field(description="Configure the options for Opengrep")
    ] = OpengrepScannerConfig()
    semgrep: Annotated[
        SemgrepScannerConfig, Field(description="Configure the options for Semgrep")
    ] = SemgrepScannerConfig()
    syft: Annotated[
        SyftScannerConfig, Field(description="Configure the options for Syft")
    ] = SyftScannerConfig()
    trivy: Annotated[
        TrivyScannerConfig,
        Field(description="Configure the options for Trivy (trivy fs)"),
    ] = TrivyScannerConfig()
    zizmor: Annotated[
        ZizmorScannerConfig, Field(description="Configure the options for zizmor")
    ] = ZizmorScannerConfig()


class ReporterConfigSegment(_PluginConfigSegment):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
        extra="allow",
    )

    __pydantic_extra__: Dict[str, Any | ReporterPluginConfigBase] = {}

    csv: Annotated[
        CSVReporterConfig,
        Field(description="Configure the options for the CSV reporter"),
    ] = CSVReporterConfig()
    cyclonedx: Annotated[
        CycloneDXReporterConfig,
        Field(description="Configure the options for the CycloneDX reporter"),
    ] = CycloneDXReporterConfig()
    gitlab_cyclonedx: Annotated[
        GitLabCycloneDXReporterConfig,
        Field(
            description="Configure the options for the GitLab CycloneDX dependency scanning reporter",
            alias="gitlab-cyclonedx",
        ),
    ] = GitLabCycloneDXReporterConfig()
    # Do the same for html, json, junitxml, ocsf, sarif, spdx, text, and yaml
    html: Annotated[
        HTMLReporterConfig,
        Field(description="Configure the options for the HTML reporter"),
    ] = HTMLReporterConfig()
    flat_json: Annotated[
        FlatJSONReporterConfig,
        Field(
            description="Configure the options for the Flat JSON reporter",
            alias="flat-json",
        ),
    ] = FlatJSONReporterConfig()
    gitlab_sast: Annotated[
        GitLabSASTReporterConfig,
        Field(
            description="Configure the options for the GitLab SAST reporter",
            alias="gitlab-sast",
        ),
    ] = GitLabSASTReporterConfig()
    github_ghas: Annotated[
        GHASReporterConfig,
        Field(
            description="Configure the options for the GitHub Advanced Security (GHAS) SARIF reporter",
            alias="github-ghas",
        ),
    ] = GHASReporterConfig()
    junitxml: Annotated[
        JUnitXMLReporterConfig,
        Field(description="Configure the options for the JUnit XML reporter"),
    ] = JUnitXMLReporterConfig()
    markdown: Annotated[
        MarkdownReporterConfig,
        Field(description="Configure the options for the Markdown reporter"),
    ] = MarkdownReporterConfig()
    ocsf: Annotated[
        OCSFReporterConfig,
        Field(description="Configure the options for the OCSF reporter"),
    ] = OCSFReporterConfig()
    sarif: Annotated[
        SARIFReporterConfig,
        Field(description="Configure the options for the SARIF reporter"),
    ] = SARIFReporterConfig()
    spdx: Annotated[
        SPDXReporterConfig,
        Field(description="Configure the options for the SPDX reporter"),
    ] = SPDXReporterConfig()
    text: Annotated[
        TextReporterConfig,
        Field(description="Configure the options for the Text reporter"),
    ] = TextReporterConfig()
    unused_suppressions: Annotated[
        UnusedSuppressionsReporterConfig,
        Field(
            description="Configure the options for the Unused Suppressions reporter",
            alias="unused-suppressions",
        ),
    ] = UnusedSuppressionsReporterConfig()
    yaml: Annotated[
        YAMLReporterConfig,
        Field(description="Configure the options for the YAML reporter"),
    ] = YAMLReporterConfig()


class MCPResourceManagementConfig(RedactedSection):
    """Configuration model for MCP resource management settings.

    The MCP server enforces two of these: ``max_concurrent_scans`` and
    ``scan_timeout_seconds``. It reads them from the operator's config (the file
    ``ASH_CONFIG`` names, else these defaults), never from the config of a scan,
    which can be the scanned repository's own or a client's. The other fields are
    accepted so that existing configs keep validating, and nothing reads them.
    Nothing ever read this section: the resource manager that had limits of the
    same names took them from its constructor's defaults, and was later removed
    as dead code.
    """

    model_config = ConfigDict(extra="forbid")

    # Concurrent operation limits
    max_concurrent_scans: Annotated[
        Optional[int],
        Field(
            description="Maximum number of scans the MCP server runs at once, across every session; a scan started beyond it is refused. A workspace scan counts as one scan, however many projects it has. 0 or null for no limit. Read from the operator's ASH_CONFIG only.",
            ge=0,
            le=100,
        ),
    ] = 3

    max_concurrent_scans_per_session: Annotated[
        int,
        Field(
            description=(
                "Maximum number of scans one session of a network transport "
                "(streamable-http, sse) may run at once; 0 for no per-session "
                "limit. A run_ash_workspace_scan counts once. Read from the "
                "operator's config (ASH_CONFIG) only, never from a scanned or "
                "delivered one. stdio's single session is not limited."
            ),
            ge=0,
            le=100,
        ),
    ] = 2

    max_concurrent_tasks: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Maximum number of concurrent async tasks allowed",
            ge=1,
            le=50,
        ),
    ] = 20

    # Thread pool configuration
    thread_pool_max_workers: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Maximum number of worker threads in the shared thread pool",
            ge=1,
            le=20,
        ),
    ] = 4

    # Timeout configuration (in seconds)
    scan_timeout_seconds: Annotated[
        Optional[int],
        Field(
            description="Longest a single MCP scan may run, in seconds, counted from when it starts running (after any wait for another scan of its session); a scan still running then is stopped and reported as failed. For a workspace scan it covers the whole workspace, and every project is stopped and reported as failed. 60 to 86400, or 0 or null for no limit. Read from the operator's ASH_CONFIG only.",
            ge=0,
            le=86400,  # 24 hours max
        ),
    ] = 1800  # 30 minutes default

    @field_validator("scan_timeout_seconds")
    @classmethod
    def _timeout_is_off_or_at_least_a_minute(
        cls, value: Optional[int]
    ) -> Optional[int]:
        # 0 turns the limit off; anything else keeps the floor it always had.
        if value is not None and 0 < value < 60:
            raise ValueError("scan_timeout_seconds must be 0 (no limit) or 60-86400")
        return value

    operation_timeout_seconds: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Default timeout for general operations in seconds",
            ge=30,
            le=600,  # 10 minutes max
        ),
    ] = 180  # 3 minutes default

    shutdown_timeout_seconds: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Maximum time to wait for graceful shutdown in seconds",
            ge=5,
            le=300,  # 5 minutes max
        ),
    ] = 30

    # Resource monitoring thresholds
    memory_warning_threshold_mb: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Memory usage threshold in MB that triggers warnings",
            ge=100,
            le=8192,  # 8GB max
        ),
    ] = 1024  # 1GB default

    memory_critical_threshold_mb: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Memory usage threshold in MB that triggers protective actions",
            ge=200,
            le=16384,  # 16GB max
        ),
    ] = 2048  # 2GB default

    task_count_warning_threshold: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Active task count that triggers warnings",
            ge=5,
            le=100,
        ),
    ] = 15

    # Message size limits
    max_message_size_bytes: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Maximum size of MCP messages in bytes",
            ge=1024,  # 1KB min
            le=100 * 1024 * 1024,  # 100MB max
        ),
    ] = 10 * 1024 * 1024  # 10MB default

    # Path validation limits
    max_path_length: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Maximum allowed path length for security validation",
            ge=256,
            le=8192,
        ),
    ] = 4096

    # Directory size limits
    max_directory_size_mb: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Maximum directory size in MB that can be scanned",
            ge=10,
            le=10240,  # 10GB max
        ),
    ] = 1000  # 1GB default

    # Health check configuration
    enable_health_checks: Annotated[
        bool,
        Field(
            description="Not enforced: nothing reads this setting. Enable periodic health checks and resource monitoring",
        ),
    ] = True

    health_check_interval_seconds: Annotated[
        int,
        Field(
            description="Not enforced: nothing reads this setting. Interval between health checks in seconds",
            ge=10,
            le=300,  # 5 minutes max
        ),
    ] = 60  # 1 minute default

    # Logging configuration
    enable_resource_logging: Annotated[
        bool,
        Field(
            description="Not enforced: nothing reads this setting. Enable detailed resource management logging",
        ),
    ] = True

    log_resource_operations: Annotated[
        bool,
        Field(
            description="Not enforced: nothing reads this setting. Log individual resource operations for debugging",
        ),
    ] = False


#: The archive converter's extraction limits as runtime-override pointers. They bound
#: what extracting an archive in the scanned tree may write, so no client may raise
#: them; they are part of ALWAYS_DENIED_PATHS. A write at an ancestor
#: (``/converters/archive``, ``/converters``) is refused too, as for any denied_paths
#: entry.
ARCHIVE_LIMIT_RUNTIME_PATHS: Tuple[str, ...] = tuple(
    f"/converters/archive/options/{name}" for name in EXTRACTION_LIMIT_OPTIONS
)

#: Runtime-override denials no profile can remove: RuntimeOverridesConfig adds any of
#: them its denied_paths leaves out. A client override that gets past the gate is
#: replayed as the operator's own setting (resolve_config, the session's profile), so
#: these are the settings that trust depends on. The scanner sandbox. Plugin modules,
#: imported into ASH's own process. The detect-secrets settings that turn on secret
#: verification (each candidate secret is sent to its issuer) or import a plugin or
#: filter from a file, and the baseline that can carry both. The archive extraction
#: limits. And every plugin that sends data off the host, each a whole section, so a
#: client can neither configure nor enable one through config overrides, nor change
#: what it sends or where, nor disable such a scanner (``**`` also matches the
#: section itself; a reporter's ``enabled: false`` is accepted and takes no effect,
#: see reporter_trust; a workspace scan's ``scanners`` and ``excluded_scanners``
#: arguments can still leave a scanner out of a run, never add one): the reporters
#: that send the results, and the scanners that send the source (snyk-code),
#: dependency lists (npm-audit), candidate secrets (detect-secrets), usage metrics
#: (semgrep, opengrep) or usage data (trivy, trivy-repo), or that call the GitHub
#: API with the token in ASH's environment (zizmor's online audits).
#: tests/unit/config/test_off_host_plugins_are_operator_only.py lists what each one
#: sends and classifies every plugin.
#:
#: A floor rather than the default alone: denied_paths was replaced whole by a
#: profile's own list, so adding one entry dropped every shipped one.
ALWAYS_DENIED_PATHS = (
    "/sandbox",
    "/sandbox/**",
    "/ash_plugin_modules",
    "/ash_plugin_modules/**",
    "/scanners/detect-secrets/options/scan_settings/filters_used",
    "/scanners/detect-secrets/options/scan_settings/filters_used/**",
    "/scanners/detect-secrets/options/scan_settings/plugins_used",
    "/scanners/detect-secrets/options/scan_settings/plugins_used/**",
    "/scanners/detect-secrets/options/baseline_file",
    *ARCHIVE_LIMIT_RUNTIME_PATHS,
    "/reporters/s3/**",
    "/reporters/aws-security-hub/**",
    "/reporters/cloudwatch-logs/**",
    "/reporters/bedrock-summary-reporter/**",
    "/scanners/detect-secrets/**",
    "/scanners/npm-audit/**",
    "/scanners/opengrep/**",
    "/scanners/semgrep/**",
    "/scanners/snyk-code/**",
    "/scanners/trivy-repo/**",
    "/scanners/trivy/**",
    "/scanners/zizmor/**",
)


class RuntimeOverridesConfig(RedactedSection):
    """Allowlist + denylist controlling which JSON-Patch ops the MCP server accepts.

    The MCP server's streamable-HTTP transport lets clients apply JSON-Patch ops
    to a profile-resolved config at session-bind time. This object is the security
    boundary: by default, runtime overrides are disabled. When enabled, only ops
    whose `path` matches `allowed_paths` AND does not match `denied_paths` are
    accepted. `denied_value_patterns` blocks values that match a regex on a
    per-path basis (e.g. shell metacharacters in extra_args).
    """

    model_config = ConfigDict(extra="forbid")

    enabled: Annotated[
        bool,
        Field(description="Master switch — runtime patches are rejected unless True."),
    ] = False

    allowed_paths: Annotated[
        List[str],
        Field(
            description=(
                "JSON-Pointer glob patterns the client may target. `*` matches one segment, "
                "`**` matches any subtree. Example: '/scanners/*/options/severity_threshold'."
            )
        ),
    ] = []

    denied_paths: Annotated[
        List[str],
        Field(
            description=(
                "JSON-Pointer glob patterns that are never allowed (denied wins over allowed). "
                "Each entry starts with '/'. The defaults block the fields that decide "
                "whether a scan fails, what it runs and reports, where findings are "
                "sent, the scanner sandbox, and this policy. A list equal to a default "
                "ASH has shipped counts as the current default list. Any other list "
                "is added to the current defaults, unless replace_default_denied_paths "
                "is true. When it is added, a list that holds some default entries and "
                "leaves others out still gets them, and a warning names the ones it "
                "leaves out. Whatever the list, and with replace_default_denied_paths "
                "too, the entries ASH always denies (the scanner sandbox, "
                "ash_plugin_modules, the detect-secrets verification, plugin and "
                "baseline settings, the archive converter's extraction limits, and the "
                "sections of the plugins that send data off the host: the s3, "
                "aws-security-hub, cloudwatch-logs and bedrock-summary-reporter "
                "reporters and the detect-secrets, npm-audit, opengrep, semgrep, "
                "snyk-code, trivy, trivy-repo and zizmor scanners) are added to it."
            )
        ),
    ] = [
        # Top-level safety: never let a runtime patch flip the failure semantics.
        "/fail_on_findings",
        # Same class of field, same reason: a client that could turn the
        # completeness gate off could make a scan where nothing ran report clean.
        "/fail_on_incomplete_scanners",
        # And the staleness policy: flipping it to warn would let a scan against an
        # out-of-date vulnerability database pass.
        "/content_db_staleness",
        "/content_db_staleness_overrides",
        # Turning the scanned repository's ignore files off or on changes which
        # files are scanned; it is the operator's choice.
        "/honor_ignore_files",
        # Turning it back on after the operator turned it off would relax trivy-db.
        "/content_db_staleness_offline_image_default",
        # The scanner sandbox: a client must not be able to switch it off, hand a
        # scanner a network, or widen what it can read.
        "/sandbox",
        "/sandbox/**",
        # Plugin modules are imported into ASH's own process, unsandboxed.
        "/ash_plugin_modules",
        "/ash_plugin_modules/**",
        # detect-secrets settings the trust checks count as the operator's: the
        # verification filter sends each candidate secret to the service that issued
        # it, plugins and filters named by file are imported, and a baseline file can
        # carry both.
        "/scanners/detect-secrets/options/scan_settings/filters_used",
        "/scanners/detect-secrets/options/scan_settings/filters_used/**",
        "/scanners/detect-secrets/options/scan_settings/plugins_used",
        "/scanners/detect-secrets/options/scan_settings/plugins_used/**",
        "/scanners/detect-secrets/options/baseline_file",
        # Suppressions and ignore paths can hide findings outright.
        "/global_settings/ignore_paths",
        "/global_settings/suppressions",
        # The runtime-override policy itself: a client that could rewrite it
        # through patch_ops could then lift every other entry here.
        "/global_settings/mcp",
        "/global_settings/mcp/**",
        # Scanner options that drop findings by rule ID, by a baseline, or by a
        # whole category (a framework, a severity, a rule set, a detector, a
        # confidence level, a cap on the number reported) rather than by path. A
        # delivered config's path exclusions are re-applied to the results as
        # marked suppressions (config/client_scanner_exclusions.py); these have
        # no file to scan instead, so a client may not change them. Options that
        # only tune output or performance, or whose default already reports the
        # least they can, are not listed. Of cdk-nag's packs only the one on by
        # default is listed: turning another on reports more. The detect-secrets
        # baseline, which can drop findings too, is listed above with its settings.
        "/scanners/opengrep/options/exclude_rule",
        "/scanners/semgrep/options/exclude_rule",
        "/scanners/bandit/options/confidence_level",
        "/scanners/checkov/options/frameworks",
        "/scanners/checkov/options/skip_frameworks",
        "/scanners/opengrep/options/config",
        "/scanners/opengrep/options/patterns",
        "/scanners/opengrep/options/severity",
        "/scanners/semgrep/options/config",
        "/scanners/semgrep/options/severity",
        "/scanners/detect-secrets/options/scan_settings",
        "/scanners/cdk-nag/options/nag_packs/AwsSolutionsChecks",
        "/scanners/ferret-scan/options/checks",
        "/scanners/ferret-scan/options/confidence_levels",
        "/scanners/ferret-scan/options/disable_ip_types",
        "/scanners/ferret-scan/options/enable_preprocessors",
        "/scanners/ferret-scan/options/finding_limit",
        "/scanners/ferret-scan/options/profile",
        "/scanners/ferret-scan/options/recursive",
        "/scanners/ferret-scan/options/respect_gitignore",
        "/scanners/ferret-scan/options/use_default_config",
        "/scanners/ferret-scan/options/validator_budget",
        "/scanners/trivy-repo/options/license_full",
        "/scanners/trivy-repo/options/scanners",
        # The same for the builtin scanners: cfn-guard's rule sets, the cfn-lint
        # rules it skips and the regions it validates for, a gitleaks baseline,
        # and trivy's scanners and ignore_unfixed (off by default; on, it
        # withholds every vulnerability that has no fixed version).
        "/scanners/cfn-guard/options/rule_sets",
        "/scanners/cfn-lint/options/ignore_checks",
        "/scanners/cfn-lint/options/regions",
        "/scanners/gitleaks/options/baseline_path",
        "/scanners/trivy/options/scanners",
        "/scanners/trivy/options/ignore_unfixed",
        # Options that can leave findings out without naming them. A scanner
        # set offline runs on whatever data is cached, and npm audit keeps no
        # advisory data: offline it skips the advisory request, reports none
        # and exits 0 (npm 10.9). max_live_bytes bounds how much extracted
        # content ferret-scan holds at once, and gitleaks skips every file
        # larger than max_target_megabytes.
        "/scanners/*/options/offline",
        "/scanners/ferret-scan/options/max_live_bytes",
        "/scanners/gitleaks/options/max_target_megabytes",
        # A scanner's own config file, and which version of its tool runs. From a
        # config file inside the scanned tree the config file comes only from the
        # operator (config/tool_config_trust.py), and so does every scanner's and
        # converter's tool_version. The version is a specifier set or release tag
        # from any source, installed only from the tool's own index or release
        # page; a repository's config may still choose opengrep's version. A
        # client's file may set none of them; refusing says so instead of
        # leaving them out with a log line.
        "/scanners/bandit/options/config_file",
        "/scanners/checkov/options/config_file",
        "/scanners/ferret-scan/options/config_file",
        "/scanners/grype/options/config_file",
        "/scanners/syft/options/config_file",
        "/scanners/trivy-repo/options/secret_config_file",
        # And the builtin scanners' own config files, trivy-repo's config file
        # and modules directory, cfn-guard's rules files, the programs actionlint
        # runs, and zizmor's online audits, which let the GitHub token in ASH's
        # environment reach zizmor. From a config inside the scanned tree each
        # is the operator's alone (utils/config_trust.py).
        "/scanners/trivy-repo/options/config_file",
        "/scanners/trivy-repo/options/module_dir",
        "/scanners/trivy/options/config_file",
        "/scanners/trivy/options/secret_config_file",
        "/scanners/actionlint/options/config_file",
        "/scanners/actionlint/options/shellcheck",
        "/scanners/actionlint/options/pyflakes",
        "/scanners/cfn-guard/options/rules_paths",
        "/scanners/cfn-lint/options/config_file",
        "/scanners/gitleaks/options/config_file",
        "/scanners/zizmor/options/config_file",
        "/scanners/zizmor/options/online_audits",
        # Whether snyk code test may apply the .snyk and .dcignore files in the
        # tree it tests, which leave files out of its analysis.
        "/scanners/snyk-code/options/honor_tree_exclusions",
        # Whether cfn-lint, gitleaks and zizmor honor the ignore comments and
        # template metadata in the files they scan, which drop findings before
        # ASH's suppressions see them.
        "/scanners/cfn-lint/options/honor_inline_ignores",
        "/scanners/gitleaks/options/honor_inline_ignores",
        "/scanners/zizmor/options/honor_inline_ignores",
        "/scanners/*/options/tool_version",
        "/converters/jupyter/options/tool_version",
        "/scanners/opengrep/options/version",
        "/scanners/opengrep/options/sha256",
        "/scanners/opengrep/options/metrics",
        "/scanners/semgrep/options/metrics",
        # AWS-credential-bearing reporter options (plugin-provided, hyphenated
        # names), and every other destination and credential option of the
        # built-in AWS reporters (config/reporter_trust.py). The whole section
        # of each reporter that sends findings off the host is denied, its
        # enabled with the rest: S3's, Security Hub's, CloudWatch Logs' and the
        # Bedrock reporter's. A client's enabled: false is not refused
        # (client_config_policy._writes_a_tightening), but takes no effect: the
        # operator's enabled applies (config/reporter_trust.py). A local
        # reporter's enabled is not denied.
        "/reporters/bedrock-summary-reporter/options/aws_*",
        # The reporters that send results off the host, whole: turning one on or
        # choosing its destination is the operator's call (also in
        # ALWAYS_DENIED_PATHS).
        "/reporters/cloudwatch-logs/**",
        "/reporters/aws-security-hub/**",
        "/reporters/bedrock-summary-reporter/options/model_id",
        "/reporters/bedrock-summary-reporter/options/output_file",
        "/reporters/bedrock-summary-reporter/options/output_executive_file",
        "/reporters/bedrock-summary-reporter/options/output_technical_file",
        "/reporters/s3/**",
        "/reporters/bedrock-summary-reporter/**",
        # The GitLab SAST report leaves suppressed findings out with this set, so
        # the findings a client's own suppressions are marked on would be gone
        # from it (off by default; GHAS's is on by default and off reports more).
        "/reporters/gitlab-sast/options/exclude_suppressed",
        # The scanners that send data off the host, whole, for the same reason: the
        # source (snyk-code), dependency lists (npm-audit), candidate secrets
        # (detect-secrets), usage metrics (semgrep, opengrep) or usage data (trivy,
        # trivy-repo), or the GitHub token (zizmor's online audits). Also in
        # ALWAYS_DENIED_PATHS.
        "/scanners/detect-secrets/**",
        "/scanners/npm-audit/**",
        "/scanners/opengrep/**",
        "/scanners/semgrep/**",
        "/scanners/snyk-code/**",
        "/scanners/trivy-repo/**",
        "/scanners/trivy/**",
        "/scanners/zizmor/**",
        # The archive converter's extraction limits bound what extracting an
        # archive in the scanned tree may write, so a client may not raise them.
        # A write at an ancestor (/converters/archive, /converters) is refused too.
        # Listed for the operator reading the default; a profile's own list keeps
        # them too (ALWAYS_DENIED_PATHS).
        *ARCHIVE_LIMIT_RUNTIME_PATHS,
    ]

    denied_value_patterns: Annotated[
        Dict[str, str],
        Field(
            description=(
                "Map of JSON-Pointer pattern to regex. add/replace ops are rejected when "
                "any string leaf reachable from the op's value matches the regex; lists "
                "and dicts are walked recursively so a forbidden token cannot be hidden "
                "inside a nested structure. The `test` op is exempt because it is "
                "read-only. Each key starts with '/'."
            )
        ),
    ] = {}

    #: Set by ``client_config_policy.effective_policy`` on the copy it returns:
    #: the operator's own list (None for a default one), and that this copy's
    #: ``denied_paths`` is already the list that applies.
    _listed_denied_paths: Optional[Tuple[str, ...]] = PrivateAttr(default=None)
    _effective: bool = PrivateAttr(default=False)
    #: ``denied_paths`` as the profile wrote it, before ``_keep_the_always_denied_paths``
    #: added the ALWAYS_DENIED_PATHS entries it left out; None when it set no list.
    #: Whether the list is a shipped default, and which fields the operator's own
    #: list names, are decided from what was written
    #: (``client_config_policy.policy_is_default`` and ``exempt_paths``).
    _written_denied_paths: Optional[Tuple[str, ...]] = PrivateAttr(default=None)

    replace_default_denied_paths: Annotated[
        bool,
        Field(
            description=(
                "When true, denied_paths is used as written instead of being added "
                "to ASH's default list, and each default entry it leaves out is "
                "named in a warning. When false (the default), the entries listed "
                "are denied as well as the defaults. Either way, an unset list, or "
                "one equal to a default ASH has shipped, gets the current default "
                "list."
            )
        ),
    ] = False

    @field_validator("denied_paths")
    @classmethod
    def _denied_paths_are_pointers(cls, value: List[str]) -> List[str]:
        # Named by position, not quoted: a value can be one read from the
        # environment, and the message goes wherever the error is shown.
        bad = [
            str(index)
            for index, entry in enumerate(value)
            if not str(entry).startswith("/")
        ]
        if bad:
            raise ValueError(
                "denied_paths entries are JSON pointers and start with '/'; "
                f"the entries at positions {', '.join(bad)} do not and would match "
                "nothing"
            )
        return value

    @field_validator("denied_value_patterns")
    @classmethod
    def _value_pattern_keys_are_pointers(cls, value: Dict[str, str]) -> Dict[str, str]:
        # Counted, not quoted, as for denied_paths.
        bad = sum(1 for key in value if not str(key).startswith("/"))
        if bad:
            raise ValueError(
                "denied_value_patterns keys are JSON pointers and start with '/'; "
                f"{bad} of them do not and would match nothing"
            )
        return value

    @model_validator(mode="after")
    def _keep_the_always_denied_paths(self) -> "RuntimeOverridesConfig":
        """Add each ALWAYS_DENIED_PATHS entry the list leaves out, at its end.

        Assigned only when one is missing, so a default policy (which holds them all)
        is the shipped list unchanged and keeps its serialized shape. The list as
        written is kept first (``_written_denied_paths``).
        """
        if "denied_paths" in self.model_fields_set:
            self._written_denied_paths = tuple(self.denied_paths)
        missing = [
            entry for entry in ALWAYS_DENIED_PATHS if entry not in self.denied_paths
        ]
        if missing:
            self.denied_paths = [*self.denied_paths, *missing]
        return self

    @field_serializer("denied_paths")
    def _denied_paths_as_written(self, value: List[str]) -> List[str]:
        """Serialize ``denied_paths`` as the profile wrote it.

        The validator above appends the ALWAYS_DENIED_PATHS entries a written
        list leaves out, on the field itself. Dumped as the field holds it, a
        rebuild of the config from its dump (``apply_config_overrides``, a
        saved and reloaded file) read the augmented list as the operator's
        written list: a list equal to an older shipped default stopped
        counting as a default (``client_config_policy.policy_is_default``)
        and ``exempt_paths`` shrank to what the appended entries name. A copy
        ``effective_policy`` returned already holds the list that applies and
        is dumped as it is.
        """
        written = self._written_denied_paths
        if self._effective or written is None:
            return value
        # The written list describes the field only while the field still
        # holds what the validator built from it: the written entries, then
        # the always-denied ones it appended. A ``model_copy(update=...)``
        # copies the private attribute and runs no validator, so its new list
        # would otherwise be replaced by the old written one in every dump.
        expected = [*written, *(e for e in ALWAYS_DENIED_PATHS if e not in written)]
        if list(value) != expected:
            return value
        return list(written)


def sandbox_mode_from_yaml(value: Any) -> Any:
    """The sandbox mode a YAML scalar stands for.

    YAML 1.1 reads an unquoted ``off`` (also ``no`` and ``false``) as the
    boolean False, so the most common spelling of the mode "off" reaches the
    loader as a bool. False is read as "off", the one mode that means no
    sandbox. True (an unquoted ``on``, ``yes`` or ``true``) names no mode and
    is refused with a hint to quote the value. Any other value is returned
    unchanged.

    The mapping applies where YAML documents are read
    (``sandbox_mode_in_document``, called by the config loader), not on the
    model: a boolean arriving by a JSON-Patch value or a ``--config-overrides``
    value is refused by the mode's own type.
    """
    if value is False:
        return "off"
    if value is True:
        modes = get_args(SandboxConfig.model_fields["mode"].annotation)
        raise ValueError(
            "the value was read as a YAML boolean; write the mode in quotes "
            f"(the modes are {', '.join(modes)})"
        )
    return value


def sandbox_mode_in_document(document: Any) -> Any:
    """*document* with a boolean ``sandbox.mode`` read as the mode it stands for.

    The config loader calls this on each file's parsed document, before the
    files are merged and before the model validates the result, so a hand-written
    unquoted ``mode: off`` loads as "off" and an unquoted ``mode: on`` is refused
    with the quoting hint (``sandbox_mode_from_yaml``). The document is changed
    in place and returned; anything that is not a mapping with a ``sandbox``
    mapping holding a ``mode`` is returned as it is.

    Raises:
        ValueError: ``sandbox.mode`` is True.
    """
    sandbox = document.get("sandbox") if isinstance(document, dict) else None
    if isinstance(sandbox, dict) and isinstance(sandbox.get("mode"), bool):
        sandbox["mode"] = sandbox_mode_from_yaml(sandbox["mode"])
    return document


class SandboxConfig(RedactedSection):
    """OS-level sandboxing of scanner subprocesses. Off by default.

    See docs/content/docs/scanner-sandbox.md for the policy each scanner gets.
    """

    # Validated on its own too; see AshConfig.
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    mode: Annotated[
        Literal["off", "auto", "bwrap", "firejail", "landlock", "sandbox-exec"],
        Field(
            description=(
                "How scanner subprocesses are confined. 'off' runs them as plain "
                "subprocesses. 'auto' uses the best sandbox available (Linux: bwrap, "
                "then firejail, then landlock; macOS: sandbox-exec). Any other value "
                "requires that backend. A scanner that cannot be sandboxed as requested "
                "is recorded MISSING with the reason; it is never run unsandboxed. "
                "A mode that --sandbox, ASH_CONFIG or the operator's config file sets "
                "is a floor: a config file inside a git checkout or the scanned "
                "directory cannot turn it off or switch backends. "
                "Not applied in container mode, where the container is the boundary; "
                "ASH logs a warning when it is set there."
            )
        ),
    ] = "off"

    network_scanners: Annotated[
        Optional[List[str]],
        Field(
            description=(
                "Scanners allowed a network when the scan is online. Null (the default) "
                "uses each scanner's declared need: semgrep, opengrep, grype, trivy, "
                "npm-audit and snyk-code fetch rules, databases or audit data. A list "
                "replaces those defaults. Under --offline no scanner gets a network. "
                "Honored only from --config-overrides or a config file outside every "
                "git checkout and the scanned directory; set by any other config file, "
                "a list can only remove network."
            )
        ),
    ] = None

    extra_read_paths: Annotated[
        List[str],
        Field(
            description=(
                "Additional host paths every sandboxed scanner may read, for example a "
                "corporate CA bundle or a shared rule directory. '~' and $VARS expand. "
                "Honored only from --config-overrides or a config file outside every "
                "git checkout and the scanned directory."
            )
        ),
    ] = []

    read_path_scanners: Annotated[
        List[str],
        Field(
            description=(
                "Scanners allowed the extra host paths their own options ask for "
                "(a rules file or baseline outside the source tree, for example). "
                "Under a sandbox, without this, a scanner whose read paths come from "
                "its options gets only the default policy, and ASH does not read a "
                "detect-secrets baseline_file outside the source tree. With it, a "
                "granted path, that baseline included, is used only when it resolves "
                "inside the source tree or an extra_read_paths entry. "
                "Honored only from --config-overrides or a config file outside every "
                "git checkout and the scanned directory."
            )
        ),
    ] = []

    env_scanners: Annotated[
        List[str],
        Field(
            description=(
                "Scanners allowed the environment variables their own options ask "
                "for (a token for an online check, for example). Without this, such "
                "variables are not passed. Honored only from --config-overrides or a "
                "config file outside every git checkout and the scanned directory."
            )
        ),
    ] = []

    environment: Annotated[
        List[str],
        Field(
            description=(
                "The environment variables every sandboxed scanner is passed besides "
                "its fixed baseline (PATH, locale and terminal settings, a few tool "
                "homes such as JAVA_HOME and VIRTUAL_ENV, and the ASH_, UV_, LC_ "
                "and PYTHON families), written as a docker-compose "
                "'environment' list: NAME passes the value ASH has, NAME=value sets "
                "one, and a name listed twice takes its last entry. The default "
                "list is the proxy variables (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, "
                "NO_PROXY and their lower-case spellings), which a scanner is passed "
                "only when it has a network, and the CA-bundle variables "
                "(SSL_CERT_FILE, SSL_CERT_DIR, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, "
                "NODE_EXTRA_CA_CERTS), whose files the sandbox also lets a scanner "
                "with a network read. A list here REPLACES the default, as a compose list replaces "
                "an image's: [MY_VAR] alone drops the proxy and CA variables, so "
                "list them too. A name that marks a credential (TOKEN, PASSWORD, "
                "SECRET and the like), TMPDIR, TEMP, TMP, HOME and ASH's own run id "
                "are refused with the name; a scanner that needs a credential is granted it with "
                "env_scanners. Honored only from --config-overrides or a config "
                "file outside every git checkout and the scanned directory."
            )
        ),
    ] = [
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_DIR",
    ]

    @field_validator("environment")
    @classmethod
    def _environment_entries_are_ones_the_sandbox_passes(
        cls, value: List[str]
    ) -> List[str]:
        # The sandbox's own validator, so the setting and the policy it builds
        # refuse the same entries. Imported here because the sandbox package
        # imports this module. Its message names a variable and never a value.
        from automated_security_helper.utils.sandbox.policy import parse_environment

        parse_environment(value)
        return value

    # Set by config/sandbox_grants.py from a network_scanners list that a config
    # file the scanned repository could have written. Private, so no config file
    # can set it.
    _network_limit: Optional[List[str]] = PrivateAttr(default=None)

    @property
    def network_limit(self) -> Optional[List[str]]:
        """Scanners a config file in the scanned tree allows a network, or None.

        Only ever narrows: a scanner outside this list gets no network whatever
        network_scanners says. See config/sandbox_grants.py.
        """
        return self._network_limit

    @network_limit.setter
    def network_limit(self, value: Optional[List[str]]) -> None:
        self._network_limit = value


class AshMcpConfig(RedactedSection):
    """MCP-server-specific config bundle (transport-agnostic)."""

    model_config = ConfigDict(extra="forbid")

    runtime_overrides: Annotated[
        RuntimeOverridesConfig,
        Field(description="Allowlist for runtime JSON-Patch overrides."),
    ] = RuntimeOverridesConfig()


class AshConfigGlobalSettingsSection(RedactedSection):
    # validate_default is here because `severity_threshold`'s default is derived
    # from an environment variable, and pydantic does not validate a default no
    # caller supplied. Without it an off-table `ASH_DEFAULT_SEVERITY_LEVEL` landed
    # in a Literal-typed field that forbids it, and the ladder in
    # utils.severity_ladder read the result as CRITICAL -- the strictest gate --
    # for an operator who had asked for the loosest. core.constants now normalizes
    # at the boundary, so this guards the other direction: a future default written
    # in this file that the Literal does not admit fails at construction instead of
    # travelling into the exit code.
    model_config = ConfigDict(
        extra="forbid",
        validate_default=True,
        # Validated on its own too; see AshConfig.
        hide_input_in_errors=True,
    )

    severity_threshold: Annotated[
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        Field(
            description="Global minimum severity level to consider findings as failures across all scanners"
        ),
    ] = ASH_DEFAULT_SEVERITY_LEVEL

    ignore_paths: Annotated[
        List[IgnorePathWithReason],
        Field(
            description="Global list of IgnorePaths. Each path requires a reason for ignoring, e.g. 'Folder contains test data only and is not committed'."
        ),
    ] = []

    suppressions: Annotated[
        List[AshSuppression],
        Field(
            description="Global list of suppression rules. Each rule specifies findings to suppress based on rule ID, file path, and optional line numbers."
        ),
    ] = []

    mcp: Annotated[
        AshMcpConfig,
        Field(
            description="MCP-server-specific configuration (runtime override allowlist, etc.)."
        ),
    ] = AshMcpConfig()


# Distinguishes "caller did not pass cpu_count" from "caller passed None", which
# is a real value here: os.cpu_count() returns None on hosts that cannot report it,
# and a test needs to be able to say so explicitly.
_UNSET_CPU_COUNT: Any = object()


class WorkspaceExecutionConfig(RedactedSection):
    """How many projects a workspace scan runs at once, and how long each may take.

    Why this is not read from the .code-workspace file
    --------------------------------------------------
    ``automated_security_helper.workspace.workspace_file`` deliberately ignores
    that file's ``settings`` block, because it belongs to another tool whose
    schema ASH does not control. So every ASH knob, including these two, lives in
    ASH's own config -- here, in the config resolved for the workspace root.

    Why these two land before the workspace policy block
    ----------------------------------------------------
    Neither can change any project's verdict. ``max_parallel_projects`` decides
    scheduling and ``project_timeout`` decides how long to wait; the findings a
    project reports and the threshold they are judged against are untouched. The
    workspace-level *policy* fields -- a severity ceiling, workspace-wide
    suppressions -- can change a verdict, and they arrive separately and visibly
    rather than riding in on an execution change.

    Wall clock is ``ceil(projects / bound)`` waves, and that is arithmetic
    -----------------------------------------------------------------------
    A workspace of N projects at a bound of B runs in ``ceil(N / B)`` waves, so
    its wall clock is roughly that multiple of one project's. Reproduce with
    ``scripts/measure_workspace_parallelism.py``; measured on a 192-CPU Linux
    host on 2026-08-25, five projects, bound 4, three timed runs per arm, the
    whole child process timed:

    * five equal projects -- one alone 21.3s median (19.4-22.7), the workspace
      43.4s median (41.5-45.8). Ratio of medians **2.036x**, range 1.823-2.365x.
    * one larger project plus four small -- one alone 20.7s median (20.7-26.3),
      the workspace 40.5s median (39.3-46.0). Ratio **1.958x**, range
      1.495-2.227x.

    Both sit on the ``ceil(5/4) = 2`` floor, so neither says much about the
    implementation: an operator who wants a workspace to finish in about the time
    of its slowest project has to set ``max_parallel_projects`` to at least the
    project count and accept the thread product below. The default stays at 4
    because that product is the thing worth defaulting conservatively.

    Two earlier figures for this were wrong and are withdrawn. A reported 0.88x at
    bound 5 -- a five-project workspace beating one project alone -- was an
    artefact of timing a cold single-project arm against a warm workspace arm,
    because ``uv_tool_runner`` caches tool probing across invocations. The
    measurement script now runs a discard pass first and alternates the arms, and
    nothing close to a sub-1.0 ratio reappears. A reported 2.35x at bound 4 was a
    single unrepeated run; it lands at the top of the range measured here rather
    than at its centre, which is why the figures above are medians with a spread.

    The second shape did not do what it was designed to do, and that is worth
    knowing before anyone repeats it. It gave one project five times the files, on
    the theory that "the slowest project alone" would then be a real baseline and
    the small projects could hide inside its wave. But 60 files scanned in 20.7s
    and 12 files in 21.3s -- indistinguishable. Scan wall clock here is dominated
    by per-scanner startup, not by file count, so the fixture produced no dominant
    project and its number is really the equal case again. Testing the RFC's 1.5x
    criterion properly needs a project large enough to be file-bound rather than
    startup-bound, which is thousands of files, not sixty.

    On this evidence the 1.5x criterion is not met at the default bound in either
    shape, and for five projects at bound 4 it cannot be: two waves is 2.0x before
    any implementation cost.

    Failure modes and known limitations
    -----------------------------------
    * ``project_timeout`` bounds the *verdict*, not the worker. Python cannot
      preempt a thread, so a timed-out project is recorded FAILED and the
      workspace continues, but the abandoned worker keeps running -- and keeps
      its pool slot. Once every slot is held by an abandoned project, nothing
      still queued can start, so those projects are cancelled and recorded
      FAILED rather than waited on. A workspace with more projects than
      ``max_parallel_projects`` can therefore report several failures from one
      slow project; raising either knob avoids it.
    * The process still does not exit until every abandoned worker finishes,
      because the interpreter joins them. Scanners run as subprocesses with
      their own timeouts, so the residual exposure is a genuinely wedged
      in-process scanner.
    * The outer bound multiplies with the inner scanner pool. That pool is
      ``min(32, cpu_count + 4)`` in ``ScanExecutionEngine.__init__``, not 4, and
      not the unrelated ``thread_pool_max_workers`` MCP setting, so the
      worst-case thread count is ``max_parallel_projects * min(32, cpu + 4)``.
      On the 192-CPU host above, the default bound of 4 already permits up to
      128 concurrent scanner threads.
    """

    model_config = ConfigDict(extra="forbid")

    max_parallel_projects: Annotated[
        Optional[int],
        Field(
            None,
            ge=1,
            le=64,
            description=(
                "Maximum number of projects scanned concurrently. Unset means "
                "min(4, cpu_count). This is an outer bound over each project's "
                "own scanner thread pool, not a replacement for it."
            ),
        ),
    ] = None

    project_timeout: Annotated[
        Optional[float],
        Field(
            None,
            gt=0,
            description=(
                "Seconds to allow a single project. Unset means no limit. On "
                "timeout that project is recorded as failed and the remaining "
                "projects still complete."
            ),
        ),
    ] = None

    def resolved_max_parallel_projects(
        self, cpu_count: Optional[int] = _UNSET_CPU_COUNT
    ) -> int:
        """The bound to use, deriving the default when none is configured.

        Stored as ``None`` and derived here rather than defaulted to 4 in the
        field, so that a one-CPU host gets one worker instead of four and a
        serialised config still shows the operator did not choose a number.

        Args:
            cpu_count: Override for the host CPU count, for tests. ``None`` and
                ``0`` are both treated as one CPU, because ``os.cpu_count()``
                can return ``None`` and a pool of zero workers never runs.
        """
        if self.max_parallel_projects is not None:
            return self.max_parallel_projects
        if cpu_count is _UNSET_CPU_COUNT:
            cpu_count = os.cpu_count()
        return max(1, min(4, cpu_count or 1))


class ContentDbStalenessOverride(RedactedSection):
    """One content database held to a different staleness policy, until a fixed date.

    ``content_db_staleness`` decides for every database at once. This narrows a
    relaxation to the one database that needs it -- typically one whose upstream
    publisher has stopped publishing for a while -- so every other database is still
    held to the scan-wide policy. ``expiration`` and ``reason`` are required, the
    same two fields a time-boxed suppression carries: an exception to a freshness
    gate that has no end date is a permanent one. On and after ``expiration``
    (00:00 UTC) the entry is ignored, with a warning in the log, and the database
    is held to the policy it has without the entry: ``content_db_staleness``, or,
    for trivy-db in an image built with ``OFFLINE=YES``, that image's ``warn``
    default unless ``content_db_staleness_offline_image_default`` is false.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    database: Annotated[
        str,
        Field(
            description=(
                "The content database's registry name, as listed in "
                "automated_security_helper/utils/content_databases.py: grype-db, "
                "trivy-db, semgrep-offline-rules or opengrep-offline-rules."
            )
        ),
    ]
    policy: Annotated[
        Literal["fail", "warn"],
        Field(
            description="The policy this database is held to while the entry is in effect."
        ),
    ]
    expiration: Annotated[
        str,
        Field(
            description=(
                "Required. The date (YYYY-MM-DD, UTC) from which the entry no longer "
                "applies: at 00:00 UTC that day the database returns to the policy it "
                "has without the entry, which is content_db_staleness, or, for "
                "trivy-db in an image built with OFFLINE=YES, that image's warn "
                "default unless content_db_staleness_offline_image_default is false."
            )
        ),
    ]
    reason: Annotated[
        str,
        Field(
            min_length=1, description="Required. Why this database is held differently."
        ),
    ]

    @field_validator("database")
    @classmethod
    def _database_must_be_declared(cls, v: str) -> str:
        from automated_security_helper.utils.content_databases import (
            CONTENT_DATABASES,
        )

        names = sorted(entry.name for entry in CONTENT_DATABASES)
        if v not in names:
            # The declared names, not the value: a value can be one read from the
            # environment, and the message goes wherever the error is shown.
            raise ValueError(
                f"unknown content database; declared databases: {', '.join(names)}"
            )
        return v

    @field_validator("expiration", mode="before")
    @classmethod
    def _expiration_is_text(cls, v: Any) -> Any:
        """The one wording for an ``expiration`` that is not text (models/core.py)."""
        return refuse_an_expiration_that_is_not_text(v)

    @field_validator("expiration")
    @classmethod
    def _expiration_must_be_a_date(cls, v: str) -> str:
        problem = expiration_date_problem(v)
        if problem is not None:
            raise ValueError(problem)
        return v

    @property
    def expires_at(self) -> datetime:
        """00:00 UTC on ``expiration``, the first instant the entry no longer applies.

        Read with the validator's own parser (``expiration_date_problem``'s
        ``strptime`` with ``%Y-%m-%d``), which admits an unpadded month or day.
        ``date.fromisoformat`` does not, so an entry that validated with
        ``2026-1-5`` raised here and was dropped at scan time, a stricter
        ``fail`` entry included.
        """
        day = datetime.strptime(self.expiration, "%Y-%m-%d").date()
        return datetime(day.year, day.month, day.day, tzinfo=timezone.utc)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """True on and after 00:00 UTC on ``expiration``."""
        return (now or datetime.now(timezone.utc)) >= self.expires_at


def _export_format_name(item: Any) -> Any:
    """One ``output_formats`` entry: a name becomes its ``ExportFormat``.

    Config files are validated with strict=True, which accepts only an
    ExportFormat instance for an ExportFormat field, so a name read from YAML
    would be refused; converting here keeps the enum type. Per entry, so that a
    refusal is located at the entry and its input is that name alone: ``ash
    config validate`` replaces every input value in a message with ``<value>``,
    and with the whole list as the input, a valid name the list also held was
    replaced in the list of valid formats too.
    """
    if isinstance(item, str) and not isinstance(item, ExportFormat):
        try:
            return ExportFormat(item.strip())
        except ValueError:
            valid = ", ".join(fmt.value for fmt in ExportFormat)
            # The valid formats, not the entry, which may have been read from
            # the environment; the error's location names the entry.
            raise ValueError(
                f"the value is not a valid format. Valid formats are: {valid}"
            ) from None
    return item


def _output_formats_schema(schema: Dict[str, Any]) -> None:
    """Publish the spellings ``output_formats`` accepts, not only the list.

    The before-validator also takes one name and null, so an editor checking a
    config against the published schema should not flag those. A comma list is
    accepted too but cannot be described as a string pattern without repeating
    every name, so the schema offers the list, one name, and null.
    """
    array = {key: schema.pop(key) for key in ("type", "items") if key in schema}
    schema["anyOf"] = [array, array.get("items", {}), {"type": "null"}]


#: The variables a builtin reporter's options read when the config leaves the
#: option unset: s3's bucket_name, cloudwatch-logs' log_group_name and
#: bedrock-summary-reporter's model_id. A value read this way never goes through
#: the config's ``${VAR}`` expansion, so the config records it when it is built
#: (``AshConfig._environment_values``), and the lines that name the option are
#: redacted with it. The standard AWS_* variables (AWS_REGION,
#: AWS_DEFAULT_REGION, AWS_PROFILE) are left as written.
REPORTER_DEFAULT_VARIABLES = (
    "ASH_S3_BUCKET_NAME",
    "ASH_CLOUDWATCH_LOG_GROUP_NAME",
    "ASH_BEDROCK_MODEL_ID",
)


def reporter_default_values() -> List[str]:
    """The values REPORTER_DEFAULT_VARIABLES hold now, each once, unset and blank skipped."""
    values = (os.environ.get(name, "") for name in REPORTER_DEFAULT_VARIABLES)
    return list(dict.fromkeys(value for value in values if value.strip()))


# Two configs never compare equal with ``==`` unless their private load state
# matches too: pydantic compares private attributes, and a loaded config's
# (``_loaded_from``, ``_environment_values`` and the rest) differ from a
# rebuild's. No product code compares two configs with ``==``; a test that
# wants field equality compares ``model_dump()``. A comment, not the class
# docstring: the docstring is the generated JSON schema's description, read by
# config authors, and Python equality semantics are for code readers.
class AshConfig(RedactedSection):
    """Main configuration model for Automated Security Helper."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="ignore",
        # A refused value can be a secret read from the environment, and an
        # error's text goes wherever the error is shown: the console, ash.log,
        # an MCP response. The input stays in errors().
        hide_input_in_errors=True,
        # Accept BOTH the alias (e.g., 'mcp-resource-management') and the
        # Python field name (e.g., 'mcp_resource_management') as input.
        # Pydantic v2 default is alias-only when an alias is declared,
        # which surfaced as an MCP-profile-loading error: the strict-extra
        # gate accepted both spellings but model_validate(strict=True)
        # accepted only the alias. Settled in an earlier review.
        populate_by_name=True,
    )

    # Internal field to track config resolution warnings (not serialized)
    _resolution_warnings: List[str] = PrivateAttr(default_factory=list)
    # The sections of one plugin name this config has already said a lookup
    # reads one of (get_plugin_config), so a lookup repeated for each use of a
    # section warns once.
    _warned_shared_names: Set[Tuple[str, str, Tuple[str, ...]]] = PrivateAttr(
        default_factory=set
    )
    # Whether the operator or the scanned tree supplied this config, recorded by the
    # orchestrator (utils/config_trust.py). None means unknown, which counts as the
    # scanned tree.
    _provenance: Optional[ConfigProvenance] = PrivateAttr(default=None)

    # The config file resolve_config read this configuration from, set once the file
    # has loaded. None for the default configuration, including one used because
    # the file could not be read. What a scan reports as the configuration in use.
    _loaded_from: Optional[Path] = PrivateAttr(default=None)

    # The tree a scan with this config covers, when it is wider than the source
    # directory: workspace mode sets the workspace root. config/path_trust.py
    # refuses tool config files inside it. None means the source directory's tree.
    _scanned_root: Optional[Path] = PrivateAttr(default=None)

    # Which tool paths in this config the operator named
    # (config/path_trust.OperatorPaths), recorded by resolve_config. None means
    # no option value counts as the operator's.
    _operator_paths: Optional[Any] = PrivateAttr(default=None)

    # What the detect-secrets settings of this config may turn on, when a file the
    # scanned repository or an MCP client wrote built it (an
    # UntrustedDetectSecretsSettings from config/secret_verification_trust.py), or
    # None when the operator's own sources built it. Private, so no config file can
    # set or clear it.
    _untrusted_detect_secrets_settings: Optional[Any] = PrivateAttr(default=None)

    # Scanner exclusions a config an MCP client delivered supplied, moved out of the
    # scanners' options and applied to their results as marked suppressions
    # instead (config/client_scanner_exclusions.py). Set by resolve_config.
    _client_scanner_exclusions: List[Any] = PrivateAttr(default_factory=list)

    # Set by resolve_config when a file of the config's chain is inside the scanned
    # tree or was delivered by an MCP client: those files, and the trusted base the
    # built-in reporters' destination options were taken from, with the reporter
    # overrides replayed. A reporter a plugin module adds is only known once the
    # scan imports the module, and its declared destination options are taken from
    # the same base then (config/reporter_trust.py). Empty, and None, when there
    # is no such file. Also the reporter section keys those files wrote, so a
    # warning quotes a section as they spelled it where the merge kept another
    # spelling of it.
    _in_tree_config_files: Tuple[Path, ...] = PrivateAttr(default=())
    _trusted_reporter_base: Optional["AshConfig"] = PrivateAttr(default=None)
    _in_tree_reporter_keys: Tuple[str, ...] = PrivateAttr(default=())
    # Set by confine_off_host_reporters_to_overrides, for the commands that read
    # stored results (``ash report``, ``ash merge``): an off-host reporter's
    # enabled flag and destinations come from the defaults and --config-overrides
    # alone, in the operator view ``_operator_reporters`` as well as in
    # ``reporters``, and a reporter with no declared destination options takes
    # its whole section from them (config/reporter_trust.py). A scan leaves it
    # False: its operator view holds the operator's own chain files on purpose.
    _reporters_from_overrides: bool = PrivateAttr(default=False)

    # Recorded with the three above, by every call of confine_reporter_destinations:
    # the UntrustedSource it gave the warnings of that call (for a file that is on
    # the line only because resolving its name stopped before the walk finished, the
    # sentence and the remedy for that, confinement_membership). The warning for a
    # reporter's declared destination options is issued later, with no source of its
    # own, and speaks the source of the record it confines by
    # (config/reporter_trust.py). None before any call.
    _untrusted_membership_source: Optional[Any] = PrivateAttr(default=None)

    # Set by resolve_config in the same case: the ash_plugin_modules entries of the
    # trusted base, with the overrides replayed. A plugin class defined in an
    # off-host package is selected only when one of them, or
    # --ash-plugin-modules, loads it (config/plugin_module_trust.py). None when
    # no file of the chain needs it; the config's own entries are trusted then.
    _trusted_plugin_modules: Optional[Tuple[str, ...]] = PrivateAttr(default=None)

    # The output and work directories of every plugin context that holds this
    # config, resolved and de-duplicated: locations whose files the scan derived
    # from the repository being scanned. PluginContext fills it through
    # path_trust.record_derived_roots; path_trust.honored_path refuses a value
    # that is not the operator's own under any of them. This list holds the
    # contexts built outside a scan run; those built inside one go to the next
    # attribute.
    _derived_roots: List[Path] = PrivateAttr(default_factory=list)

    # The same record for the contexts built inside a scan run
    # (path_trust.derived_roots_scope), by run. A path is judged against the
    # list above and every run's roots, so a scan that is still going refuses
    # paths under another running scan's output directory too. A run's entry
    # is removed when its scan ends
    # (path_trust.forget_derived_roots); the mapping is replaced, never
    # changed in place, as the list above is.
    _run_derived_roots: Dict[str, Tuple[Path, ...]] = PrivateAttr(default_factory=dict)

    # The reporters section keys this configuration held before any
    # --config-overrides were applied, stamped by apply_config_overrides on
    # its first application. The trusted replay's fold reads it to tell a
    # section the file spelled from one an override created
    # (resolve_config._folded_onto_trusted). None means no overrides were
    # ever applied.
    _reporters_before_overrides: Optional[Tuple[str, ...]] = PrivateAttr(default=None)

    # The same record for the ``scanners`` sections, read by the scanner
    # overrides' fold for the ownership views.
    _scanners_before_overrides: Optional[Tuple[str, ...]] = PrivateAttr(default=None)

    # Whether an application of --config-overrides REPLACED ``ash_plugin_modules``
    # (an override of the key without the trailing ``+``), stamped by
    # apply_config_overrides from the key paths its overrides landed on, never
    # from the override text. The load path (load_config_file_for_run) reads it
    # after attaching the file's references, to drop every reference of a list
    # the file no longer describes. Once set it stays set.
    _plugin_modules_replaced: bool = PrivateAttr(default=False)

    # The dotted field paths this configuration's operator supplied, stamped by
    # apply_config_overrides: the paths the input model was written with (its
    # model_fields_set, walked before the rebuild, which re-validates a full
    # dump and so marks every field written) plus every override key applied,
    # kept through later applications. recorded_config._sets answers from it
    # when present, so a recorded field the operator never supplied still
    # refuses under an unrelated override. None means no overrides were ever
    # applied, and model_fields_set itself is the answer.
    _written_before_overrides: Optional[FrozenSet[str]] = PrivateAttr(default=None)

    # Set by resolve_config when this config was built from a file the scanned
    # repository could write, or one an MCP client supplied: the configuration as
    # the operator set it (the trusted base with the operator's reporter
    # overrides), and those files. A reporter that sends findings off the host
    # takes its whole section from it (config/operator_only_options.py,
    # reporter_section). None means this config is the operator's own.
    _operator_reporters: Optional[Any] = PrivateAttr(default=None)
    # Set beside it by record_operator_reporters: the operator views a
    # scanner's configured path is judged against (operator_wrote_value), as a
    # LIST of two to three views of different types -- the trusted base with
    # the reporter overrides, that base with the operator's ``scanners``
    # overrides, and, when the operator's own chain files wrote scanner
    # sections, the merged file view. A value is the operator's when any view
    # holds it. None means no views were recorded.
    _operator_scanner_views: Optional[List[Any]] = PrivateAttr(default=None)
    _repository_config_files: List[Path] = PrivateAttr(default_factory=list)
    # Those of the files an extends entry chose with a value read from the
    # environment, and every base below each, which the warning names <value>.
    _repository_config_environment_paths: FrozenSet[Path] = PrivateAttr(
        default_factory=frozenset
    )
    # Why those files are not the operator's, in the sentence the other
    # confinement warnings give (sandbox_grants.confinement_membership), set with
    # them by record_operator_reporters. None for a caller that records none.
    _repository_config_membership: Optional[str] = PrivateAttr(default=None)
    _off_host_sections_warned: List[str] = PrivateAttr(default_factory=list)

    # The values and keys the file this config was loaded from, and the files
    # it extends, read from the environment, set with the next attribute by
    # resolve_config.load_config_file_for_run from the reads the load made
    # (config_validator.environment_record_read). A line built from the config
    # after it loads is redacted with them, as the load's own refusals are: a
    # loaded plugin's option refusal (config/plugin_option_check.py) and
    # get_plugin_config's debug line. Every config starts with the reporter
    # defaults read from the environment (REPORTER_DEFAULT_VARIABLES), however it
    # is built; the load keeps them beside the values its files read.
    _environment_values: List[str] = PrivateAttr(
        default_factory=reporter_default_values
    )
    # Each string an operator's ``--config-overrides`` value holds, set by
    # resolve_config.apply_config_overrides. An override's value is the
    # operator's, not the environment's, but it can be a credential, so what
    # prints a section of this config (get_plugin_config's debug line, a
    # section's repr) hides it as it hides a value the files read from the
    # environment. Redaction state only: nothing records or serializes it, and
    # the refusals built from _environment_values do not read it.
    _override_values: Tuple[str, ...] = PrivateAttr(default=())
    # How the files wrote each of those values and keys
    # (config_validator.EnvironmentRewrite). The record of this config, in a
    # results file and anything sent from it, keeps the reference as the file
    # wrote it, never the value (record_of_config).
    _written_references: List[Any] = PrivateAttr(default_factory=list)
    # Each mapping where those files write a key as a reference, set or not
    # (environment_record.mappings_with_written_reference_keys), set with the
    # attributes above. The rules for an MCP client's patch decide from these
    # (config/runtime_patch.py), so their answer does not depend on the value.
    _written_key_mappings: Tuple[Any, ...] = PrivateAttr(default=())
    # For a configuration read from a results file's record: each field the
    # record holds as an environment reference the field cannot hold (a
    # fixed-choice field such as severity_threshold), as (field, reference),
    # read with the field's default (AshAggregatedResults.validate_ash_config).
    # A command that acts on such a field takes it from its own configuration
    # (config/recorded_config.py).
    _unreadable_references: List[Any] = PrivateAttr(default_factory=list)

    # What the files this config was resolved from read from the environment
    # (config/environment_record.EnvironmentReference), set by resolve_config. A
    # record of the config, such as a results file's ash_config, holds each as the
    # file wrote it instead of its value. Every read is here, one an extends
    # overlay wrote a literal over included, so redaction masks a value the
    # chain read wherever it appears. In memory only, never serialized.
    _environment_references: Tuple[Any, ...] = PrivateAttr(default=())

    # The references of _environment_references the merged document still shows
    # at their places (config_sources, ResolvedConfigDocument
    # .displayed_environment_references), set by resolve_config: what a view of
    # the configuration writes back as the file wrote it (`ash config get`, the
    # MCP get_config tool). Every other consumer reads _environment_references.
    _displayed_environment_references: Tuple[Any, ...] = PrivateAttr(default=())

    # True when _environment_references are the base's followed through a
    # client's patch (config/runtime_patch.apply_runtime_patch): a reference an
    # op wrote over is gone from them, and one it moved is at its new entry. A
    # session copy written from such a config records them as they stand, not
    # as the registered profile had them (cli/mcp/profile_registry).
    _references_followed: bool = PrivateAttr(default=False)

    def _redaction_values(self) -> Tuple[str, ...]:
        """repr and str of this config are redacted with the values it read
        from the environment (utils/redacted_model.py).

        Reprs reach users through tracebacks with locals (show_debug_locals),
        DEBUG logs of objects and the text around a validation error, none of
        which can know which fields were env-read, so an env-read value shows
        ``<value>`` wherever it sits: in a top-level field, inside a nested
        section, and in the repr of a model, list or dict that holds the
        config. So does each section printed on its own, as a traceback local
        holding ``config.global_settings`` or one ignore-path entry prints it:
        every section carries these values, given to it when the config is
        built, whenever the values change, and when a section is put in the
        config. A plugin prints redacted with its context's config, and so
        does its own section, built from the config (base/plugin_base.py). A
        model built from a section's dump by other code carries none until it
        is put into a config, a section or a plugin.
        """
        return environment_strings((*self._environment_values, *self._override_values))

    def _carry_environment_values_into_sections(self) -> None:
        values = self._redaction_values()
        for name in type(self).model_fields:
            carry_environment_values(self.__dict__.get(name), values)

    def model_post_init(self, context: Any) -> None:
        super().model_post_init(context)
        self._carry_environment_values_into_sections()

    def __setattr__(self, name: str, value: Any) -> None:
        # A field: RedactedSection gives the new section this config's values.
        super().__setattr__(name, value)
        # The values themselves, or all the private attributes at once (a
        # config rebuilt from another keeps what that one's load recorded,
        # resolve_config.apply_config_overrides): every section takes them.
        if name in (
            "_environment_values",
            "_override_values",
            "__pydantic_private__",
        ):
            self._carry_environment_values_into_sections()

    def model_copy(self, *, update: Any = None, deep: bool = False) -> "AshConfig":
        copied = super().model_copy(update=update, deep=deep)
        # A section passed in ``update`` was never put in a config.
        copied._carry_environment_values_into_sections()
        return copied

    # Project information
    project_name: Annotated[
        str,
        Field(
            description="Name of the project being scanned",
        ),
    ] = os.environ.get("ASH_PROJECT_NAME", "ash-scan")

    global_settings: Annotated[
        AshConfigGlobalSettingsSection,
        Field(
            description="Global default settings for ASH shared across scanners. If the same setting exists at the scanner level and is set in both places, the scanner level settings take precedence."
        ),
    ] = AshConfigGlobalSettingsSection()

    fail_on_findings: Annotated[
        bool,
        Field(
            description="Whether to exit with non-zero code if findings are detected"
        ),
    ] = True

    fail_on_incomplete_scanners: Annotated[
        bool,
        Field(
            description=(
                "Whether to exit with a non-zero code when a selected scanner did "
                "not complete -- status ERROR (ran and failed) or MISSING "
                "(dependencies unavailable, never ran). A SKIPPED scanner, one not "
                "selected or one with nothing of its kind to scan, does not trip "
                "this by itself, but a run in which every scanner is SKIPPED, such "
                "as one where no selected scanner had a file to scan, exits 1 while "
                "this is on. Independent of fail_on_findings: "
                "one answers 'was anything found', this one answers 'did what I "
                "asked for actually run'. Selects on the scanner's status, so it "
                "covers only a failure that reached that status. Defaults to True, "
                "so a scanner recorded ERROR or MISSING does not report the exit "
                "code of a clean scan. Converters count too: one that crashed, one "
                "that could not convert some of its inputs, and one whose tool is "
                "missing while it had inputs make the scan exit non-zero the same "
                "way. Set it to False, or pass "
                "--no-fail-on-incomplete-scanners, to accept a partial scan's exit "
                "code; excluding the scanner whose tool is unavailable is usually "
                "better, because an excluded scanner is recorded SKIPPED and the "
                "report then says what was not measured. One ending overrides this "
                "setting: a run where ASH could not stop a scanner's tool exits 1 "
                "either way, because the tool may still be running and writing "
                "into the output directory."
            )
        ),
    ] = True

    honor_ignore_files: Annotated[
        bool,
        Field(
            description=(
                "Whether the .gitignore and .ignore files in the scanned tree decide "
                "which files are left out of ASH's scan set, the file list "
                "detect-secrets, cfn-nag, cdk-nag, cfn-lint, cfn-guard, actionlint, "
                "zizmor, npm-audit and the converters read. True (the default) leaves out every file they match. False "
                "scans those files too; ASH's own exclusions (.git, CDK assets, "
                "its own output directory) still apply. An operator setting: a config file inside the scanned "
                "tree, or one an MCP client supplied, cannot change it, and its "
                "value there is ignored with a warning. Set it in a config file "
                "outside the tree, with --config-overrides, or with "
                "--no-honor-ignore-files / --honor-ignore-files. Every scan records "
                "the outcome in metadata.ignore_file_exclusions."
            )
        ),
    ] = True

    sandbox: Annotated[
        SandboxConfig,
        Field(description="OS-level sandboxing of scanner subprocesses."),
    ] = SandboxConfig()

    content_db_staleness: Annotated[
        Literal["fail", "warn"],
        Field(
            description=(
                "What a scan does when a scanner's content database (grype's or "
                "trivy's vulnerability database, the offline semgrep/opengrep "
                "rulesets) was built longer ago than the bound declared for it in "
                "automated_security_helper/utils/content_databases.py. 'fail' (the "
                "default) keeps the scanner's findings and exits 1, naming the "
                "database, its build time, its age and the bound. 'warn' lets the scan "
                "pass and records the same warning in the log and in the reports "
                "(summary, SARIF invocation notifications, flat JSON). The CLI flag "
                "--allow-stale-content-db sets 'warn' for one scan and takes "
                "precedence over this value; --no-allow-stale-content-db sets 'fail'."
            )
        ),
    ] = "fail"

    content_db_staleness_overrides: Annotated[
        List[ContentDbStalenessOverride],
        Field(
            description=(
                "Per-database exceptions to content_db_staleness, each with a required "
                "expiration date and reason. An entry holds one named database to its "
                "own policy until 00:00 UTC on its expiration date, and every database "
                "not named keeps content_db_staleness. An expired entry is ignored with "
                "a warning. Empty by default. Either form of --allow-stale-content-db "
                "clears this list for that scan, so the flag still decides for every "
                "database."
            )
        ),
    ] = []

    content_db_staleness_offline_image_default: Annotated[
        bool,
        Field(
            description=(
                "Whether an image built with OFFLINE=YES holds trivy-db to 'warn' rather "
                "than to content_db_staleness: fail. Such an image carries the trivy "
                "database it was built with, and trivy's own bound would fail every scan "
                "in it from a day after the build; with this, those scans pass and every "
                "report records the stale database. Only trivy-db: grype-db and the "
                "offline rulesets keep content_db_staleness. ASH_OFFLINE_AT_BUILD_TIME=YES "
                "in ASH's environment, which the image sets from its OFFLINE build "
                "argument, turns it on; without that variable this does nothing, whatever "
                "it says. Set false to hold trivy-db to content_db_staleness in the image "
                "too. A content_db_staleness_overrides "
                "entry for trivy-db outranks it, and either form of "
                "--allow-stale-content-db sets this to false for that scan."
            )
        ),
    ] = True

    ash_plugin_modules: Annotated[
        List[str],
        Field(
            description="List of Python modules to import containing ASH plugins and/or event subscribers. These are loaded in addition to the default modules.",
        ),
    ] = []

    external_reports_to_include: Annotated[
        List[str],
        Field(
            description="List of external reports to include in the final report. These can be paths to SARIF or CycloneDX reports produced by other tools.",
        ),
    ] = []

    # Build configuration - use a default instance instead of calling the constructor
    build: Annotated[
        BuildConfig | None,
        Field(description="Build-time configuration settings"),
    ] = None

    converters: Annotated[
        ConverterConfigSegment,
        Field(description="Converter configurations by name."),
    ] = ConverterConfigSegment()

    scanners: Annotated[
        ScannerConfigSegment,
        Field(description="Scanner configurations by name."),
    ] = ScannerConfigSegment()

    reporters: Annotated[
        ReporterConfigSegment,
        Field(description="Reporter configurations by name."),
    ] = ReporterConfigSegment()

    # ReportPhase reads this when the command line names no formats; an explicit
    # --output-formats list replaces it. It was read there before it was declared
    # here, and because this model ignores unknown keys, the value in a config file
    # was dropped on load.
    output_formats: Annotated[
        List[Annotated[ExportFormat, BeforeValidator(_export_format_name)]],
        Field(
            description="Reports to write, by reporter name (for example sarif, markdown, github-ghas): a list, one name, or names separated by commas. Narrows the enabled reporters; it does not enable a disabled one. Empty or null writes every enabled reporter. A --output-formats list on the command line replaces this list.",
            json_schema_extra=_output_formats_schema,
        ),
    ] = []

    # MCP resource management configuration
    mcp_resource_management: Annotated[
        MCPResourceManagementConfig,
        Field(
            description="Configuration for MCP server resource management and limits",
            alias="mcp-resource-management",
        ),
    ] = MCPResourceManagementConfig()

    workspace: Annotated[
        WorkspaceExecutionConfig,
        Field(
            description=(
                "Workspace-mode execution settings. Read from the config "
                "resolved for the workspace root; a project's own copy of this "
                "block is ignored, because how many projects run at once is not "
                "a project's decision."
            ),
        ),
    ] = WorkspaceExecutionConfig()

    # `extends` and `patch` are read by the config loader (config/config_sources.py)
    # and removed before validation, so a loaded config always has both as None.
    # They are declared here so the JSON schema documents them, and excluded from
    # every dump so that saving a resolved config never writes them back.
    extends: Annotated[
        str | List[str] | None,
        Field(
            exclude=True,
            description=(
                "Base config file(s) this config extends: a path, or a list of "
                "paths applied in order, relative to this file. Mappings merge key "
                "by key; lists and scalars from this file replace the base's. Paths "
                "must stay inside the repository being scanned; URLs are refused."
            ),
        ),
    ] = None

    patch: Annotated[
        List[Dict[str, Any]] | None,
        Field(
            exclude=True,
            description=(
                "RFC 6902 JSON-Patch operations (add, remove, replace, test) applied "
                "after this file is merged over its bases. Use 'add' at "
                "'/global_settings/suppressions/-' to append to a base's list."
            ),
        ),
    ] = None

    @field_validator("output_formats", mode="before")
    @classmethod
    def _output_format_names(cls, v: Any) -> Any:
        # The spellings --output-formats takes are accepted too: one name, or names
        # separated by commas. null (or a key with no value) means not set. Each
        # entry is then converted, or refused with the list a reader can pick
        # from, by _export_format_name.
        if v is None:
            return []
        if isinstance(v, ExportFormat):
            return [v]
        if isinstance(v, str):
            return [part.strip() for part in v.split(",") if part.strip()]
        return v

    @field_serializer("output_formats")
    def _output_format_values(self, v: List[ExportFormat]) -> List[str]:
        # The names, not the members, in every dump mode. A Python-mode dump of the
        # members was written by yaml.dump (ash config get, update, wizard) as
        # !!python/object/apply tags that no later load could read, and refused by
        # yaml.safe_dump (save, the MCP session config). A file that failed to load
        # was then scanned with the default config.
        return [str(getattr(fmt, "value", fmt)) for fmt in v]

    @field_validator("content_db_staleness_overrides")
    @classmethod
    def _one_override_per_database(
        cls, v: List[ContentDbStalenessOverride]
    ) -> List[ContentDbStalenessOverride]:
        # Named by the entries' positions, not by the database: a refusal names the
        # field and the rule, never a value.
        seen: Dict[str, int] = {}
        for index, entry in enumerate(v):
            if entry.database in seen:
                raise ValueError(
                    f"content_db_staleness_overrides entries {seen[entry.database]} "
                    f"and {index} name the same content database; one named by more "
                    "than one entry would be ambiguous"
                )
            seen[entry.database] = index
        return v

    @model_validator(mode="after")
    def _extends_must_be_resolved(self) -> "AshConfig":
        # Reached only when a dict carrying these keys is validated directly,
        # bypassing the loader. Ignoring them would run with the child alone and
        # none of its bases' settings, so it fails instead.
        if self.extends is not None or self.patch is not None:
            raise ValueError(
                "'extends' and 'patch' are resolved when a config file is loaded; "
                "load the file with AshConfig.from_file or resolve_config instead of "
                "validating its contents directly"
            )
        return self

    @classmethod
    def from_file(
        cls,
        config_path: Path,
        confine_to: Optional[Path] = None,
        permit_base: Optional[Callable[[Path], bool]] = None,
        confine: Optional[Callable[[Path, Path, Any], Any]] = None,
        repository_file: Optional[Callable[[Path, Path], bool]] = None,
    ) -> "AshConfig":
        """Load configuration from a file, following any ``extends`` chain.

        ``config_path`` may be YAML, JSON, an ``ashrc.toml``-style TOML file, or a
        ``pyproject.toml`` (whose ``[tool.ash]`` table is read). ``extends`` and
        ``patch`` are resolved by ``config/config_sources.py``, which documents
        the merge rules and the confinement of base paths to ``confine_to`` and
        ``permit_base``. ``confine`` and ``repository_file`` are
        load_config_file's.

        The file is loaded by ``resolve_config.load_config_file``, the one
        function every config file goes through, so it is refused where a scan
        refuses it and in the scan's words: ConfigFileRefused (an
        ASHConfigValidationError) for a file the model refuses, described field
        by field without the values and keys the chain read from the
        environment. pydantic's own text quotes every input, and callers print
        it: the scan for the ASH_CONFIG file, the MCP server for a profile or a
        session config, a workspace scan in a warning.
        """
        # Imported here: resolve_config imports this module.
        from automated_security_helper.config.resolve_config import load_config_file

        _, config = load_config_file(
            Path(config_path),
            permit_base=permit_base,
            confine_to=Path(confine_to) if confine_to is not None else None,
            confine=confine,
            repository_file=repository_file,
        )
        return config

    def save(
        self,
        config_path: Path,
        exclude_unset: bool = False,
        as_written: bool = False,
        env_tags: bool = True,
    ):
        """Save configuration to a file, as ``ash config init`` writes one.

        Through ``config/config_writer.py``: no internal-only fields, and JSON
        for a ``.json`` path. It wrote every field, and YAML whatever the path.
        With ``as_written``, each value and key the configuration's files read
        from the environment is written as the reference they wrote
        (render_config_file_as_written), for a file a scan loads again.

        Two modes config_writer does not render take a direct YAML dump instead.
        ``exclude_unset`` writes only the fields the config was loaded or built
        with, so the file sets what the original set and nothing else; it still
        loads back as the same values. ``env_tags`` False writes each reference
        of ``_environment_references`` as quoted text instead of tagged
        ``!ENV``, which nothing resolves on its own: the copy of a profile a
        client patched, in a directory where ``!ENV`` is not resolved, which a
        scan fills from the operator's copy
        (``environment_record.fill_environment_references``). The MCP server
        saves a session's config with these (``profile_registry
        .materialize_session_config``). In that dump a reference is written as
        the reference only where the whole string is the value: a value the load
        changed after reading it (a relative path taken from the file's
        directory) is refused, naming the variable
        (``environment_record.EnvironmentValueInPath``), and any other string
        that reads as an ``!ENV`` reference is written quoted. A value read from
        the environment that the dump still holds as text where no reference
        was written is refused too, naming only the variable. Without
        ``as_written`` such a value is written as text, as render_config_file
        writes it.

        The direct dump is a JSON document for a ``.json`` path, as
        render_config_file writes one; a JSON path whose dump has to write
        references is refused. The whole text is built before the file is
        opened, so a dump that fails leaves an existing file as it was.
        """
        from automated_security_helper.config.config_sources import is_json_file
        from automated_security_helper.config.config_writer import (
            SCHEMA_COMMENT,
            render_config_file,
            render_config_file_as_written,
        )

        config_path = Path(config_path)
        if exclude_unset or (as_written and not env_tags):
            writes_references = as_written and bool(self._environment_references)
            if is_json_file(config_path):
                if writes_references:
                    raise ValueError(
                        "the configuration was not written: with exclude_unset or "
                        "env_tags=False, the references its files read from the "
                        "environment are written to YAML only; save it to a YAML "
                        "path"
                    )
                text = (
                    json.dumps(
                        self.model_dump(
                            mode="json", by_alias=True, exclude_unset=exclude_unset
                        ),
                        indent=2,
                    )
                    + "\n"
                )
            else:
                data = self.model_dump(by_alias=True, exclude_unset=exclude_unset)
                if writes_references:
                    from automated_security_helper.config.environment_record import (
                        record_environment_references,
                        written_without_tag,
                    )

                    data = record_environment_references(
                        data,
                        self._environment_references,
                        mark=TaggedReference if env_tags else written_without_tag,
                        whole_only=True,
                    )
                    left = first_env_scalar(data)
                    if left is not None:
                        # By the variable's name alone: the text is the value.
                        raise RuntimeError(
                            "the configuration was not written: it would hold a "
                            f"value read from environment variable {left.variable} "
                            "as text, where its file wrote a reference to the "
                            "variable"
                        )
                else:
                    # A section kept without validation (an external plugin's)
                    # holds such values as a str subclass, which the dumper
                    # cannot write.
                    data = without_env_scalars(data)
                text = yaml.dump(data, Dumper=_ConfigDumper, indent=2)
            with open(config_path, mode="w", encoding="utf-8") as f:
                f.write(text)
            return
        render = render_config_file_as_written if as_written else render_config_file
        config_path.write_text(
            render(config_path, self, [SCHEMA_COMMENT]),
            encoding="utf-8",
        )

    def __repr_args__(self):
        """The fields as pydantic's repr shows them, except that a config whose
        files read values from the environment shows each as the file wrote it.

        A debug line that formats the config, or an object holding it (the
        plugin context), would otherwise print the values. Those fields are
        shown as the record holds them (config/environment_record.py), as plain
        data rather than nested models.
        """
        if not self._environment_references:
            yield from super().__repr_args__()
            return
        from automated_security_helper.config.environment_record import (
            record_environment_references,
        )

        recorded = record_environment_references(
            self.model_dump(by_alias=True), self._environment_references
        )
        yield from recorded.items()

    def get_plugin_config(
        self,
        plugin_type: Literal["converter", "scanner", "reporter"],
        plugin_name: str,
    ):
        match plugin_type:
            case "scanner":
                item_dict = self.scanners.model_dump(by_alias=True)
            case "reporter":
                item_dict = self.reporters.model_dump(by_alias=True)
            case "converter":
                item_dict = self.converters.model_dump(by_alias=True)
            case _:
                item_dict = {}
        return plugin_section_lookup(
            item_dict,
            plugin_type,
            plugin_name,
            self._redaction_values(),
            on_shared_name=lambda read, ignored: self._warn_of_a_shared_name(
                plugin_type, read, ignored
            ),
        )

    def _warn_of_a_shared_name(
        self, plugin_type: str, read: str, ignored: List[str]
    ) -> None:
        """Say, once, which section a lookup reads when several share a name.

        Two sections of one plugin name (``snyk.code`` beside ``Snyk_Code``)
        leave the lookup one to read, and the others never take effect. The one
        read is the key spelled as the reduced name if there is one, else the
        first key written whose name, without punctuation, is the plugin's, else
        the first whose name without its Converter, Scanner or Reporter word is
        (``plugin_section_claims`` states the order, ``plugin_section_key``
        applies it). A scan that runs with that section's settings, or without
        the scanner when that section is off, gives no other sign of it. The
        text names the keys, which can hold what the file read from the
        environment, so it is redacted with this config's values.
        """
        shared = (plugin_type, read, tuple(ignored))
        if shared in self._warned_shared_names:
            return
        self._warned_shared_names.add(shared)
        # Imported here: utils.error_text defers imports of the config package.
        from automated_security_helper.utils.error_text import (
            config_environment_values,
            text_without_values,
        )
        from automated_security_helper.utils.log import NO_MARKUP

        segment = f"{plugin_type}s"
        keys = [f"{segment}.{key}" for key in (read, *ignored)]
        ASH_LOGGER.warning(
            text_without_values(
                f"{', '.join(keys[:-1])} and {keys[-1]} name the same {plugin_type}. "
                f"Only {segment}.{read} is read. Keep one section for the "
                f"{plugin_type}.",
                config_environment_values(self),
            ),
            extra=NO_MARKUP,
        )


def plugin_section_claims(keys: Iterable[str]) -> Dict[str, List[str]]:
    """Each spelling a section key is indexed under, mapped to the keys that
    claim it, in the order they claimed it.

    ``plugin_section_lookup`` reads the first claimant of a spelling, so the first
    key of a list is the section a lookup under that spelling reads and the rest
    are sections of the same plugin that it never reads. *keys* are in the order
    of ``model_dump(by_alias=True)``, which lists a segment's declared fields
    before its extras. A reader that must agree with the lookup about which
    section is read (the workspace plan's scanner list) takes it from here and
    does not repeat the rule.

    Two passes over the keys, the second making its claims after every claim of
    the first, so a key's type-word-stripped spelling never outranks another
    key's exact or punctuation-stripped one:

    Exact and punctuation-stripped spellings of each key, in that order of
    preference. The stripped spelling is _lookup_spelling, the one
    plugin_key_lookup_names lists, so a key the lookup reads as a plugin's
    section is one the checks see as that plugin's (ascii_lower in
    plugin_section_names states the rule). An empty spelling (a key with no ASCII
    letter, digit or "+") is left out, as an empty reduced name is in the
    lookup: a plugin whose reduced name is empty would otherwise read that
    section, and the denials skip an empty name.

    The same suffix removal that is applied to the plugin name in the lookup,
    applied to the keys. Without it the two forms can never meet: a query for
    BedrockSummaryReporter reduces to "bedrocksummary", while the key
    "bedrock-summary-reporter" reduces only to "bedrocksummaryreporter", so any
    plugin whose config key contains the plugin-type word was unreachable and
    silently fell back to its defaults. `csv` matched only because its key does
    not contain "reporter", which is why this looked like an external-plugin
    problem.

    The first key to claim a spelling keeps it, in both passes. A declared
    scanner keeps the spelling it shares with a respelled extra beside it
    ("detect-secrets" and "detect.secrets" both reduce to "detectsecrets"): with
    the extra taking it, a lookup by the class name or the Python field name read
    the extra's section while the exact name read the declared one. A stripped
    spelling never shadows a real key: with both "bedrock-summary" and
    "bedrock-summary-reporter" present, the second one's stripped form collides
    with the first, and adding a plugin should not repoint another plugin's
    config. Among extras alone the first key in the file keeps the spelling.
    """
    claims: Dict[str, List[str]] = {}

    def claim(spelling: str, key: str) -> None:
        if not spelling:
            return
        claimants = claims.setdefault(spelling, [])
        if key not in claimants:
            claimants.append(key)

    names = list(keys)
    for key in names:
        for possible in sorted({key, _lookup_spelling(key)}):
            claim(possible, key)
    for key in names:
        claim(reduced_plugin_name(key), key)
    return claims


def plugin_section_key(
    keys: Iterable[str],
    reduced: str,
    claims: Optional[Dict[str, List[str]]] = None,
) -> Optional[str]:
    """The key ``plugin_section_lookup`` reads for the reduced plugin name *reduced*
    when the caller's own spelling is not a key, or ``None`` when no key is read.

    Two steps, in the lookup's order: a key spelled as the reduced name itself,
    then the first key to claim it (``plugin_section_claims``). A key spelled as
    the reduced name is read even when another key claimed the name before it:
    ``snykcode`` written after ``Snyk_Code`` is the section read. The step the
    lookup takes before either, the caller's own spelling when it is a key, is the
    one input this cannot know. A reader that must agree with the lookup, the
    workspace plan's scanner list, asks this function and does not repeat the rule.
    *claims* is ``plugin_section_claims(keys)`` when the caller has it already.
    """
    names = list(keys)
    if reduced and reduced in names:
        return reduced
    if claims is None:
        claims = plugin_section_claims(names)
    claimants = claims.get(reduced)
    return claimants[0] if claimants else None


def plugin_section_lookup(
    item_dict: dict,
    plugin_type: str,
    plugin_name: str,
    environment_values,
    on_shared_name: Optional[Callable[[str, List[str]], None]] = None,
):
    """The section of *item_dict* read as *plugin_name*'s, exactly as
    ``AshConfig.get_plugin_config`` reads its own segment's dump.

    A module function, because two readers answer this lookup: the resolved
    configuration, and the operator chain-files view ``resolve_config`` builds
    from a merged dump that is deliberately not validated into a model. One
    function keeps the two readers one, and the view never borrows an
    AshConfig method over a stand-in ``self``, which would break on any
    attribute that method grows to read. *environment_values* redacts the
    found-section debug line, as the configuration's own values do.

    *on_shared_name* is called with the key read and the keys it ignores, when
    there are any: those sections are never read. For a caller that named the key
    read exactly they are its peers (``plugin_section_peers``); for one that named
    no key they are every other key that claims the plugin's reduced name. The
    configuration passes one that warns; the chain-files view passes none.
    """
    found = None
    read_key: Optional[str] = None
    # Reduce the provided plugin_name in case the class name was passed in,
    # as the config itself uses kebab-case keys while the classes use PascalCase
    # for class names.
    #
    # Punctuation is stripped as well as the type word. Stripping only the type
    # word left a caller who passed the *config-key* spelling with a dangling
    # separator -- "bedrock-summary-reporter" reduced to "bedrock-summary-",
    # which matches no key and no candidate -- so the lookup missed even though
    # the key was spelled exactly right. cli/report.py passes
    # plugin_name=report_format straight from --output-format, and
    # scanner_statistics_calculator passes the registered scanner name, so this
    # is the spelling real callers use, not a hypothetical one.
    og_plugin_name = plugin_name
    plugin_name = reduced_plugin_name(plugin_name)
    # Each spelling of each config key maps to the first key that claims it
    # (plugin_section_claims states the rule and why).
    claims = plugin_section_claims(item_dict)
    # The caller's spelling, before any reduction, wins. This is checked
    # against og_plugin_name rather than plugin_name: by this point plugin_name
    # has had its type word and punctuation removed, so an exactly-correct
    # config key such as "bedrock-summary-reporter" no longer resembles itself
    # and could never match item_dict here.
    if og_plugin_name in item_dict:
        ASH_LOGGER.debug(
            f"Found {plugin_type} plugin {og_plugin_name} with direct match"
        )
        read_key = og_plugin_name
    else:
        # Then the reduced form: a key spelled as it, else the first key to claim
        # it (plugin_section_key). An empty reduced name is no plugin's, so it
        # matches no key, as it is left out of the index above.
        read_key = plugin_section_key(item_dict, plugin_name, claims)
        if read_key == plugin_name:
            ASH_LOGGER.debug(
                f"Found {plugin_type} plugin {og_plugin_name} with direct match"
            )
        elif read_key is not None:
            ASH_LOGGER.debug(
                f"Found {plugin_type} plugin {og_plugin_name} under config key {read_key}"
            )

    if read_key is not None:
        found = item_dict[read_key]
        if read_key == og_plugin_name:
            # The caller named this key, so the keys of the other rank are other
            # plugins that read their own sections by their own names.
            shared = plugin_section_peers(claims, read_key, plugin_name)
        else:
            # The caller named no key, so every other claimant may be the plugin
            # meant, and the section read is a choice among them.
            shared = [key for key in claims.get(plugin_name, []) if key != read_key]
        if shared and on_shared_name is not None:
            on_shared_name(read_key, shared)

    if found is not None:
        from automated_security_helper.config.config_validator import (
            redact_values,
        )
        from automated_security_helper.utils.log import NO_MARKUP

        # The section whole, without the values and keys the config file
        # read from the environment. NO_MARKUP: the section is data.
        ASH_LOGGER.debug(
            redact_values(
                f"Found config for {plugin_type} plugin {og_plugin_name}: {found}",
                environment_values,
            ),
            extra=NO_MARKUP,
        )

    return found


def plugin_section_peers(
    claims: Dict[str, List[str]], read_key: str, reduced: str
) -> List[str]:
    """The keys other than *read_key* that claimed *reduced* the way it did.

    A key claims a spelling in the first pass of ``plugin_section_claims`` when the
    spelling is the key as written or with punctuation removed, and only in the
    second when it is the key with its Converter, Scanner or Reporter word removed
    as well. The keys of one rank are one plugin's spellings of its section; the
    keys of the other rank are other plugins, each read by its own exact name:
    ``bedrock-summary`` and ``bedrock-summary-reporter`` are two plugins, and a
    warning to "keep one section" would send the operator to delete one plugin's
    configuration.

    A lookup that names a key exactly takes its peers from here. A lookup that
    names none (a class name, which reduces to *reduced*) cannot tell which plugin
    is meant and treats every other claimant as ignored. The workspace plan groups
    its extra scanner sections with this split, but returns its twins by reduced
    name, the keys of every rank together, because the registered name of the
    plugin, which it does not know, decides which rank a scan reads.
    """

    def first_pass(key: str) -> bool:
        return reduced in (key, _lookup_spelling(key))

    rank = first_pass(read_key)
    return [
        key
        for key in claims.get(reduced, [])
        if key != read_key and first_pass(key) == rank
    ]


_PLUGIN_TYPE_WORD = re.compile(r"(Converter|Scanner|Reporter)(Config)?", re.IGNORECASE)
_PLUGIN_NAME_PUNCTUATION = re.compile(r"[^a-z0-9+]+", re.IGNORECASE)


def _lookup_spelling(key: str) -> str:
    """``key`` with what ``_PLUGIN_NAME_PUNCTUATION`` drops removed and ASCII case lowered.

    That pattern drops what is outside ``[a-z0-9+]``, but under IGNORECASE it
    keeps the ASCII capitals and four non-ASCII letters it treats as equal to
    ASCII ones. This is the spelling, besides the key as written and
    ``reduced_plugin_name(key)``, under which ``plugin_section_lookup`` indexes a
    section and under which ``plugin_key_lookup_names`` lists it: one function for
    both, so the names a section is read under and the names the checks cover
    cannot differ. Lowered with ``ascii_lower``, which states why.
    """
    return _folded_section_name(_PLUGIN_NAME_PUNCTUATION.sub("", key))


def reduced_plugin_name(name: str) -> str:
    """``name`` as ``AshConfig.get_plugin_config`` compares it.

    The Converter/Scanner/Reporter word (and a following "Config") and every
    character outside ``[a-z0-9+]`` are removed, then the rest is lowered with
    ``ascii_lower``, so ``BedrockSummaryReporter`` and ``bedrock-summary-reporter``
    both become ``bedrocksummary``, and a non-ASCII look-alike stays distinct.

    This reads MORE spellings as one name than the fold does: the fold drops
    only ``-`` and ``_``, while this drops every character outside
    ``[a-z0-9+]`` (``detect.secrets``), and the IGNORECASE class keeps some
    non-ASCII case look-alikes the fold leaves distinct. That is the safe
    direction for both readers: a denial covers at least every spelling the
    fold reads as the plugin, and ``get_plugin_config``'s by-name lookup indexes
    a key under only the spellings ``plugin_key_lookup_names`` lists
    (``_lookup_spelling`` and this function), so a key it finds for a plugin's
    own name is one a denial on that plugin covers.
    """
    return _folded_section_name(
        _PLUGIN_NAME_PUNCTUATION.sub("", _PLUGIN_TYPE_WORD.sub("", name))
    )


def section_fold_key(name: str) -> tuple[str, str]:
    """The identity a section spelling folds under, shared by BOTH patch walks.

    The folded section name (ASCII case and the separators dropped) paired
    with the reduced plugin name. The document pointer walk folds a typed
    segment onto an existing key, and the owned view's settle respells a
    file's key onto a registered spelling, only when both parts agree: a
    spelling whose type word a separator splits ("bedrock-summary-repo_rter")
    folds by name alone but names no plugin the config lookup reads, and
    folding it on one side only would show a patched value the reporter never
    runs. With one key function the two walks cannot disagree on what folds.
    """
    return (_folded_section_name(name), reduced_plugin_name(name))


def plugin_key_lookup_names(key: str) -> set[str]:
    """Every reduced plugin name under which ``get_plugin_config`` finds section ``key``.

    The key as written, the key with punctuation removed and lowercased
    (``_lookup_spelling``, the spelling ``plugin_section_lookup`` indexes it
    under), and the key reduced the way a plugin name is. A plugin whose
    ``reduced_plugin_name`` is in this set reads ``key`` as its config when no
    section uses its exact name. ``runtime_patch`` uses the same set so a denial
    on a plugin's section holds for each of these spellings.
    """
    names = {key, _lookup_spelling(key)}
    reduced = reduced_plugin_name(key)
    if reduced:
        names.add(reduced)
    return names


def _same_suppression(existing: Any, suppression: AshSuppression) -> bool:
    """Whether a config entry is ``suppression``, field for field.

    The entry is read as a suppression first, so a field it leaves at its
    default and a YAML date (an unquoted 2099-01-31) compare equal to the
    values ``suppression`` holds. An entry that is not a valid suppression is
    never the same one.
    """
    if not isinstance(existing, dict):
        return False
    if isinstance(existing.get("expiration"), date):
        existing = {**existing, "expiration": existing["expiration"].isoformat()}
    try:
        existing_suppression = AshSuppression.model_validate(existing)
    except ValidationError:
        return False
    return existing_suppression.model_dump(
        mode="json", exclude_none=True
    ) == suppression.model_dump(mode="json", exclude_none=True)


class _KeepsEnvReferences(_NoAliasSafeLoader):
    """SafeLoader, with an ``!ENV`` scalar kept as its own text.

    For loads whose result only locates where to edit the file as text (the
    suppression writer): the reference is left in the file as written, so this
    parse must not read the environment, where ``_AshConfigLoader`` resolves
    the reference to its value. Every alias is refused while the document is
    composed, as ``load_config_yaml`` refuses it for every other reader of a
    config: the save edited a file with an alias the scan then could not
    load, and the save's write-check walks the loaded document, so an alias
    that fans out (or one that contains itself) cost that walk the document's
    expansion rather than its size.
    """


def _env_reference_text(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> str:
    """The ``!ENV`` scalar's own text, with nothing read from the environment."""
    return loader.construct_scalar(node)


_KeepsEnvReferences.add_constructor("!ENV", _env_reference_text)

#: YAML's line breaks besides CR and LF: NEL (U+0085), and the line and
#: paragraph separators (U+2028/U+2029). str.splitlines splits the file at
#: each and PyYAML ends a line at each, so the line readers take them as a
#: line's ending too. Spelled with chr(), so this file holds no invisible
#: characters.
_OTHER_YAML_BREAKS = (chr(0x85), chr(0x2028), chr(0x2029))

#: ``suppressions: []`` (as ``ash config init`` writes it) or a spelled null,
#: with an optional trailing comment: no entry is there, and a block item
#: under the flow-style or null value would not parse. The line ends in CR,
#: LF or both, in one of YAML's other breaks, or with the file - and the
#: ending is the text's LAST character (``\Z``, not ``$``, which also matches
#: before a string-final LF and so took "break then newline" as a line). The
#: comment stops at every line break: ``.`` crosses CR, NEL and the line and
#: paragraph separators, so ``#.*`` swallowed a next line into the comment.
#: Both shapes are unreachable through the save, whose one caller passes
#: elements of str.splitlines, but the pattern says what the caller means.
_ALL_LINE_BREAKS = "\r\n" + "".join(_OTHER_YAML_BREAKS)


def _key_pattern(key: str) -> str:
    """A pattern for ``key:`` as a YAML block mapping can write it: plain,
    single-quoted or double-quoted, with spaces or tabs before the colon
    (_key_on_line reads the same spellings)."""
    return rf"(?:{key}|\"{key}\"|'{key}')[ \t]*:"


_EMPTY_SUPPRESSIONS_LINE = re.compile(
    r"^(?P<indent>[ \t]+)(?P<key>"
    + _key_pattern("suppressions")
    + r")[ \t]*(?:\[[ \t]*\]|~|null|Null|NULL)[ \t]*"
    r"(?P<comment>#[^" + _ALL_LINE_BREAKS + r"]*)?"
    r"(?P<end>\r?\n?|[" + "".join(_OTHER_YAML_BREAKS) + r"])\Z"
)


#: A top-level ``global_settings: {}`` (as a flow mapping) or a spelled null,
#: with an optional trailing comment: the block holds nothing yet, and the
#: suppressions key is inserted under it once the value is dropped
#: (_blocked_empty_global_settings).
_EMPTY_GLOBAL_SETTINGS_LINE = re.compile(
    r"^(?P<key>"
    + _key_pattern("global_settings")
    + r")[ \t]*(?:\{[ \t]*\}|~|null|Null|NULL)[ \t]*"
    r"(?P<comment>#[^" + _ALL_LINE_BREAKS + r"]*)?"
    r"(?P<end>\r?\n?|[" + "".join(_OTHER_YAML_BREAKS) + r"])\Z"
)


def _blocked_empty_global_settings(lines: list) -> None:
    """Rewrite a top-level ``global_settings: {}`` (or spelled-null) line to
    take block children.

    In place, as ``_blocked_empty_suppressions`` does for the list: the ``{}``,
    ``~`` or ``null`` goes, a trailing comment and the line's own ending stay,
    and the ``suppressions:`` key is then inserted under it as the block's
    first child. Before this the line read as an inline mapping, which sent the
    save to the whole rewrite, dropping every comment the file held for a block
    that holds nothing.
    """
    for idx, line in enumerate(lines):
        found = _EMPTY_GLOBAL_SETTINGS_LINE.match(line)
        if found is not None:
            comment = found.group("comment")
            kept = f" {comment}" if comment else ""
            lines[idx] = f"{found.group('key')}{kept}{found.group('end')}"
            return


#: What may follow a mapping key's colon in block style: nothing, whitespace,
#: or a line break, YAML's other breaks (_OTHER_YAML_BREAKS) included.
_AFTER_A_KEY_COLON = ("", " ", "\t", "\r", "\n", *_OTHER_YAML_BREAKS)


def _key_on_line(stripped: str, key: str) -> Optional[int]:
    """The length of the ``key:`` that *stripped*, a line with its indent
    stripped, starts with, or None when it starts with no such key.

    The key as a YAML block mapping can write it (_key_pattern): plain,
    single-quoted or double-quoted, with spaces or tabs before the colon, and
    the colon followed by whitespace, a line break or nothing. Reading only
    the plain ``key:`` spelling took a quoted key, or one with a space before
    its colon, for no key at all: the save then added a second key of that
    name, and refused the file it had made.
    """
    for spelled in (key, f'"{key}"', f"'{key}'"):
        if not stripped.startswith(spelled):
            continue
        after = stripped[len(spelled) :]
        colon = len(after) - len(after.lstrip(" \t"))
        if after[colon : colon + 1] == ":" and (
            after[colon + 1 : colon + 2] in _AFTER_A_KEY_COLON
        ):
            return len(spelled) + colon + 1
    return None


def _suppressions_key_line(lines: list) -> tuple:
    """``(index, indent)`` of global_settings' own ``suppressions:`` line.

    Its own: a child of the top-level ``global_settings:`` block at the indent
    of that block's first child, so a key of the same name nested under
    another global_settings key is not taken for the list. ``(None, None)``
    when the block or the key is absent.
    """
    in_global = False
    child_indent: Optional[int] = None
    for idx, line in enumerate(lines):
        stripped = line.lstrip(" \t")
        indent = len(line) - len(stripped)
        if not stripped.strip() or stripped.startswith("#"):
            continue
        if indent == 0:
            if in_global:
                return (None, None)
            in_global = _key_on_line(stripped, "global_settings") is not None
            continue
        if not in_global:
            continue
        if child_indent is None:
            child_indent = indent
        if (
            indent == child_indent
            and _key_on_line(stripped, "suppressions") is not None
        ):
            return (idx, indent)
    return (None, None)


def _holds_a_value_on_its_line(key_line: str) -> bool:
    """Whether a ``suppressions:`` line carries its value after the colon (a
    flow list, a scalar), where a block item cannot follow it. An anchor or
    tag alone (``&shared``, ``!!seq``) names or types the node below the key,
    which can be the block list, so it is read past; one followed by a value
    counts as that value."""
    stripped = key_line.lstrip(" \t")
    rest = stripped[_key_on_line(stripped, "suppressions") or 0 :].strip()
    while rest.startswith(("&", "!")):
        parts = rest.split(None, 1)
        rest = parts[1].strip() if len(parts) > 1 else ""
    return bool(rest) and not rest.startswith("#")


#: What may follow a block-sequence ``-`` indicator: nothing, whitespace, or a
#: line break, YAML's other breaks (_OTHER_YAML_BREAKS) included.
_AFTER_THE_DASH = ("", " ", "\t", "\r", "\n", *_OTHER_YAML_BREAKS)


def _a_block_item(text: str) -> bool:
    """Whether *text*, a line with its indent stripped, is a block-sequence
    item: a ``-`` indicator alone or followed by whitespace or a line break.
    The one answer for every reader of the suppressions list
    (_value_line_under_key, _find_suppressions_append_point), so no shape is
    an item to one and a value to the other. YAML's other line breaks count:
    ``str.splitlines`` splits the file at them, so a ``-`` one follows ends
    its own line and its value starts on the next - an item, not a value
    under the key. The tab arm is unreachable through the save today -
    PyYAML refuses a tab where a token starts, so a ``-<TAB>item`` file
    never parses and is refused as unparseable first - and is kept so the
    two readers stay one definition apart from the parser's."""
    return text.startswith("-") and text[1:2] in _AFTER_THE_DASH


def _value_line_under_key(lines: list, key_idx: int) -> bool:
    """Whether the ``suppressions:`` key's value starts on the line under it
    in a form a block item cannot follow: a flow list, a flow map or a
    scalar.

    YAML lets a mapping value begin on the line after its key, indented past
    it, so ``suppressions:`` followed by ``[{...}]`` on its own line is the
    same shape _holds_a_value_on_its_line refuses on the key's line. The
    first content line indented past the key that is not a ``- `` block item
    is that value. An anchor or tag alone names or types the node below it
    and is read past, as on the key's line; a line at or left of the key's
    indent is a sibling or a parent, so the key holds no value below it.
    """
    key_line = lines[key_idx]
    key_indent = len(key_line) - len(key_line.lstrip(" \t"))
    for line in lines[key_idx + 1 :]:
        stripped = line.lstrip(" \t")
        if not stripped.strip() or stripped.startswith("#"):
            continue
        if len(line) - len(stripped) <= key_indent:
            return False
        rest = stripped
        while rest.startswith(("&", "!")):
            parts = rest.split(None, 1)
            rest = parts[1] if len(parts) > 1 else ""
        if not rest.strip() or rest.startswith("#"):
            continue
        return not _a_block_item(rest)
    return False


def _blocked_empty_suppressions(lines: list) -> None:
    """Rewrite global_settings' ``suppressions: []`` (or spelled-null) line to
    take block items.

    In place: the ``[]``, ``~`` or ``null`` goes, a trailing comment and the
    line's own ending stay, and the entry is then inserted under the key as
    the list's first block item.
    """
    key_idx, _ = _suppressions_key_line(lines)
    if key_idx is None:
        return
    found = _EMPTY_SUPPRESSIONS_LINE.match(lines[key_idx])
    if found is not None:
        comment = found.group("comment")
        kept = f" {comment}" if comment else ""
        lines[key_idx] = (
            f"{found.group('indent')}{found.group('key')}{kept}{found.group('end')}"
        )


def _line_ending(earlier: Optional[bytes]) -> str:
    """The ending for the lines a save adds: the file's own, CRLF when it has
    any, else LF (a new file's)."""
    return "\r\n" if earlier is not None and b"\r\n" in earlier else "\n"


def _ending_with(lines: list, eol: str) -> list:
    """*lines*, each LF ending written as *eol*. A line already ending CRLF,
    or with no ending, is left as it is."""
    if eol == "\n":
        return list(lines)
    return [
        f"{line[:-1]}{eol}"
        if line.endswith("\n") and not line.endswith("\r\n")
        else line
        for line in lines
    ]


def _insert_lines(lines: list, at: int, added: list, eol: str) -> None:
    """Insert *added* into *lines* at *at*, ending the line before first: a
    file's last line with no newline would otherwise take the first added
    line onto it."""
    if at > 0 and not lines[at - 1].endswith("\n"):
        lines[at - 1] = f"{lines[at - 1]}{eol}"
    lines[at:at] = _ending_with(added, eol)


class _KeyPairs(dict):
    """A JSON object as parsed, with its key/value pairs kept in order,
    repeats included: a dict keeps only the last of two equal keys."""

    def __init__(self, pairs: list) -> None:
        super().__init__(pairs)
        self.pairs = list(pairs)


def _pairs_of(node: Any, is_json: bool) -> Optional[list]:
    """The (key, value) pairs of a parsed JSON object or a composed YAML
    mapping, repeats included, or None for anything else."""
    if is_json:
        return node.pairs if isinstance(node, _KeyPairs) else None
    if isinstance(node, yaml.MappingNode):
        return [
            (key.value if isinstance(key, yaml.ScalarNode) else None, value)
            for key, value in node.value
        ]
    return None


def _any_repeated_json_key(node: Any) -> Optional[str]:
    """A key any object in a parsed JSON document (its pairs kept) writes
    more than once, or None."""
    if isinstance(node, _KeyPairs):
        keys = [key for key, _ in node.pairs]
        for key in keys:
            if keys.count(key) > 1:
                return key
        for _, value in node.pairs:
            found = _any_repeated_json_key(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = _any_repeated_json_key(value)
            if found is not None:
                return found
    return None


def _any_repeated_yaml_key(node: Any, seen: Optional[set] = None) -> Optional[str]:
    """A key any mapping in a composed YAML document writes more than once,
    or None. The whole-rewrite save writes the parsed document back whole,
    which keeps only the last of two equal keys wherever they sit, as the
    JSON save does (_any_repeated_json_key). An alias is the node it names,
    so a node can be reached twice, and a recursive alias reaches itself."""
    if seen is None:
        seen = set()
    if id(node) in seen:
        return None
    seen.add(id(node))
    if isinstance(node, yaml.MappingNode):
        keys = [
            key.value if isinstance(key, yaml.ScalarNode) else None
            for key, _ in node.value
        ]
        for key in keys:
            if key is not None and keys.count(key) > 1:
                return key
        for _, value in node.value:
            found = _any_repeated_yaml_key(value, seen)
            if found is not None:
                return found
    elif isinstance(node, yaml.SequenceNode):
        for value in node.value:
            found = _any_repeated_yaml_key(value, seen)
            if found is not None:
                return found
    return None


def _repeated_key(text: str, is_json: bool, any_depth: bool = False) -> Optional[str]:
    """The key of ASH's that a save edits -- global_settings at the top, or
    suppressions inside it -- that *text* writes more than once, or None.
    For JSON, any repeated key anywhere: the JSON save writes the parsed
    document back whole, which keeps only the last of two equal keys
    wherever they sit, where a YAML save edits only the lines it adds. A
    YAML save that writes the document back whole too (the full-rewrite
    Case D) passes ``any_depth`` and gets the JSON rule.

    YAML and JSON both keep only the last of two equal keys, so a repeat
    decides which of the two lists or blocks the scan reads. Read from the
    document's structure (composed YAML, JSON with its pairs kept), so a
    quoted key or one after a byte order mark counts as the same key, as it
    does when the file is loaded."""
    try:
        root = (
            json.loads(text.removeprefix(chr(0xFEFF)), object_pairs_hook=_KeyPairs)
            if is_json
            else yaml.compose(text, Loader=_KeepsEnvReferences)  # nosec B506 - a SafeLoader, composed only
        )
    except (yaml.YAMLError, ValueError):
        return None
    if is_json:
        return _any_repeated_json_key(root)
    if any_depth:
        return _any_repeated_yaml_key(root)
    top = _pairs_of(root, is_json)
    if top is None:
        return None
    if [key for key, _ in top].count("global_settings") > 1:
        return "global_settings"
    for key, value in top:
        inner = _pairs_of(value, is_json) if key == "global_settings" else None
        if inner is not None and [k for k, _ in inner].count("suppressions") > 1:
            return "suppressions"
    return None


def _apart_from_the_entry(document: Any, suppression: Optional[AshSuppression]) -> Any:
    """*document*, a parsed config, with the last suppression equal to
    *suppression* taken out, and a missing or null global_settings or
    suppressions read as an empty one: two documents that differ by that one
    entry alone compare equal."""
    if document is None:
        document = {}
    if not isinstance(document, dict):
        return document
    document = dict(document)
    settings = document.get("global_settings")
    if settings is None:
        settings = {}
    if isinstance(settings, dict):
        settings = dict(settings)
        entries = settings.get("suppressions")
        if entries is None:
            entries = []
        if isinstance(entries, list):
            entries = list(entries)
            if suppression is not None:
                for index in range(len(entries) - 1, -1, -1):
                    entry = entries[index]
                    if isinstance(entry, dict) and _same_suppression(
                        entry, suppression
                    ):
                        del entries[index]
                        break
        settings["suppressions"] = entries
        document["global_settings"] = settings
    return document


def _parsed_config(text: str, is_json: bool) -> Any:
    """*text* parsed as the file is read: YAML with ``!ENV`` kept as text, or
    JSON as JSON, past a leading byte order mark as the loader reads it
    (utf-8-sig)."""
    if is_json:
        return json.loads(text.removeprefix(chr(0xFEFF)))
    return yaml.load(text, Loader=_KeepsEnvReferences)  # nosec B506 - a SafeLoader


def _why_it_would_not_load(
    new: bytes,
    suppression: AshSuppression,
    held: list,
    is_json: bool,
    earlier: Optional[bytes] = None,
    whole_rewrite: bool = False,
) -> Optional[str]:
    """Why *new*, the bytes a save is about to write over *earlier* (None for a
    new file), is not the file's config with the one entry added, or None.

    Parsed as the file is read, *new* must parse and must not repeat a key
    the save edits (the scan would read only the last of two); it must hold
    *suppression* and every entry of *held*, the list the file had; and with
    the new entry taken out, it must equal the document *earlier* held. That
    last comparison covers the whole document, so a save the text edit
    misjudged -- a global_settings key the line scan did not take for the
    key, which would get a second block YAML then keeps -- cannot drop or
    change another setting while the suppressions check out. A file that
    already repeats one of those keys is refused too: a JSON save writes the
    document back whole and would drop the first of the two from the file.
    """
    try:
        text = new.decode("utf-8")
        data = _parsed_config(text, is_json)
    except (yaml.YAMLError, ValueError):
        return "does not parse"
    repeated = _repeated_key(text, is_json, any_depth=whole_rewrite)
    if repeated is not None:
        return f"repeats the key {repeated!r}, and only the last one is read"
    earlier_data: Any = None
    if earlier is not None:
        try:
            earlier_text = earlier.decode("utf-8")
            earlier_data = _parsed_config(earlier_text, is_json)
        except (yaml.YAMLError, ValueError):
            return "replaces a file that does not parse"
        repeated = _repeated_key(earlier_text, is_json, any_depth=whole_rewrite)
        if repeated is not None:
            return (
                f"drops one of the {repeated!r} keys the file repeats, of "
                "which only the last one is read"
            )
    settings = data.get("global_settings") if isinstance(data, dict) else None
    entries = settings.get("suppressions") if isinstance(settings, dict) else None
    if not isinstance(entries, list):
        entries = []
    if not any(
        isinstance(e, dict) and _same_suppression(e, suppression) for e in entries
    ):
        return "does not hold the saved suppression"
    if any(e not in entries for e in held):
        return "drops a suppression the file held"
    if _apart_from_the_entry(data, suppression) != _apart_from_the_entry(
        earlier_data, None
    ):
        return "drops or changes a setting the file held, or adds one"
    return None


def _staged_beside(target: Path, mode: int) -> Tuple[int, Path]:
    """A new file beside *target*, created exclusively with *mode*, and its
    descriptor. The kernel applies the process's umask to *mode*; nothing here
    changes the umask, which is process-wide, so another thread's file
    created meanwhile keeps its own mode.

    Deliberately not utils/atomic_write.py, whose staging shape this follows.
    That helper serves re-creatable results files: it stages with the plain
    umask mode (a host user must be able to read results a container wrote),
    retries the replace on Windows sharing violations so a progress poll's
    open does not fail a scan, and never syncs, because a results file lost
    to a power cut is re-made by the next run. A user's config is the
    opposite on each point: an existing file's copy starts private (0o600)
    and then takes the earlier owner, group and mode; the file and its
    directory are fsynced, because the config is the user's own work and a
    power loss must not leave it empty; and the staged bytes are read back
    and compared before the replace. Folding those behind options would give
    the shared helper five switches with one caller each; the two writers
    share the staging NAME shape (so a crash's leftover says what it is) and
    nothing else of their contracts."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for _ in range(100):
        # The shape utils/atomic_write.py stages with: a copy a crash leaves
        # behind (a kill between the stage and the replace) then says what it
        # is, where a bare `.<name>.<hex>` said nothing.
        staged = (
            target.parent / f".{target.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
        )
        try:
            return os.open(staged, flags, mode), staged
        except FileExistsError:
            continue
    raise FileExistsError(
        f"no unused name beside {target} to stage the saved config in"
    )


def _give_earlier_owner_and_mode(descriptor: int, earlier: os.stat_result) -> int:
    """Give the staged file the earlier file's owner, group and mode, and
    return the mode applied.

    The owner and group as far as the process may set them: a save by root (a
    `sudo ash`, a root container) would otherwise leave a user's config owned
    by root, and a process that may set only the group keeps that. A refusal
    is logged at debug and the save goes on, owned by the process, which is
    what a plain write by it would give a new file; the staged file then
    keeps the saver's group, so the earlier mode's group bits (and setgid)
    would open the file to a group its owner did not give them to, and they
    are dropped from the mode. The mode is set after the owner, as a change
    of owner can clear setuid and setgid bits."""
    mode = stat.S_IMODE(earlier.st_mode)
    if hasattr(os, "fchown"):
        try:
            os.fchown(descriptor, earlier.st_uid, earlier.st_gid)
        except OSError as owner_refused:
            try:
                os.fchown(descriptor, -1, earlier.st_gid)
            except OSError:
                ASH_LOGGER.debug(
                    "the saved config could not be given the earlier file's "
                    f"owner and group: {owner_refused.strerror}"
                )
                mode &= ~(stat.S_IRWXG | stat.S_ISGID)
    if hasattr(os, "fchmod"):
        os.fchmod(descriptor, mode)
    return mode


def _sync_directory(directory: Path) -> None:
    """Flush *directory*'s entries to the disk, so a replace made in it
    survives a power loss. Best effort: on Windows a directory cannot be
    opened to sync, and a filesystem that refuses the sync still holds the
    replace, which has already happened, so a failure here is not the save's."""
    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _left_unchanged(reason: str, config_path: Path) -> ValueError:
    """The save's refusal for *reason*, ending as every refusal of it does:
    with the path, and that it is unchanged. The one home of that wording,
    so a caller reads the same promise whichever check refused."""
    return ValueError(f"{reason}; {config_path} is unchanged")


def _resolved_for_save(path: Path, config_path: Path) -> Path:
    """``path`` with every link followed, for the save's containment check.

    A symlink loop is refused here, in the save's own words, before anything
    is staged. ``Path.resolve`` met one differently by version: 3.10 to 3.12
    raised RuntimeError from the resolve itself, and 3.13 onward returned the
    path with the loop unresolved, so the save failed at its stat with the
    system's ELOOP. Neither was the save's refusal. ``os.path.realpath`` in
    strict mode raises OSError(ELOOP) for a loop on every supported version; a
    path that does not exist yet (a new config, or a dangling link's target,
    which the containment check then judges) is resolved as far as it goes.
    """
    try:
        return Path(os.path.realpath(path, strict=True))
    except FileNotFoundError:
        return Path(os.path.realpath(path))
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise _left_unchanged(
                "the config path is a symlink loop, which the suppression save "
                "does not write through",
                config_path,
            ) from None
        raise


def _sticky_refusal_applies(
    earlier_status: Optional[os.stat_result], parent_status: os.stat_result
) -> bool:
    """Whether the directory's sticky bit can be what refused the replace.

    The restricted-deletion flag blocks a rename over an existing entry only
    when the effective uid owns neither that entry nor the directory and is
    not privileged (rename(2); the kernel's privilege check is CAP_FOWNER,
    which this predicate approximates as euid 0). A new config has no entry
    for the bit to protect, and a process that owns the config or the
    directory, or runs as root (approximating CAP_FOWNER), is not
    constrained by it, so naming "a sticky directory" in those cases sent an
    operator auditing a mode that was never the problem.
    os.geteuid does not exist on Windows, where no directory is sticky, so
    there the answer is False and the neutral wording carries the system's
    own reason.
    """
    if earlier_status is None or not parent_status.st_mode & stat.S_ISVTX:
        return False
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    euid = geteuid()
    return euid not in (0, earlier_status.st_uid, parent_status.st_uid)


def _write_checked(
    config_path: Path,
    new: bytes,
    suppression: AshSuppression,
    held: list,
    is_json: bool = False,
    earlier: Optional[bytes] = None,
    whole_rewrite: bool = False,
) -> None:
    """Write *new* over *config_path*, whose bytes were *earlier* (None for a
    new file), once it is known to be that config with the one entry added.

    The bytes are checked in memory first (_why_it_would_not_load), and a
    result the scan could not load, or one that would change anything but
    the entry, is refused with nothing written: a text edit composed against
    a shape this writer misjudged never reaches the file. They then go to a staged file in the target's own directory, are
    synced to the disk, read back and compared (a read served from the page
    cache: it checks the staged file holds exactly the bytes handed to
    write(), not what the platters would answer after a crash), and replace
    the resolved target
    in one os.replace, after which the directory is synced too. Right before
    the replace the config is read again, and one whose bytes are no longer
    *earlier* (written meanwhile, or created or removed) is refused, so a
    change made since the save read the file is not lost. So a failure
    at any step leaves the config as it was: a write cut short on the live
    file (a full disk, a kill) would have truncated it and lost the
    suppressions it held, and without the syncs a power loss could leave the
    replaced file empty on a filesystem that does not order data before a
    rename. Replacing the resolved target keeps a symlinked config a symlink,
    with the new bytes in its target. The staged file takes the earlier
    file's owner and group (as far as the process may set them) and its mode;
    a new config gets the mode a plain create gives it. Hard links to the
    config are not kept, and neither are ACLs or extended attributes: the
    replaced file is a new one. An existing config this process may not
    write is refused before anything is staged: the replace needs only the
    directory, so the save would otherwise bypass the file's own mode. A
    directory the staged file cannot be made in, and a directory that
    refuses the replace, are refused in the save's own words - the latter
    naming a sticky directory only when the sticky bit can be the cause:
    the directory's mode carries the bit, the config existed, and the
    process owns neither the config nor the directory and is not root
    (_sticky_refusal_applies). Any other write failure fails with the
    system's own error, with the config untouched.
    """
    problem = _why_it_would_not_load(
        new, suppression, held, is_json, earlier, whole_rewrite=whole_rewrite
    )
    if problem is not None:
        raise _left_unchanged(
            f"saving the suppression would write a config that {problem}",
            config_path,
        )
    target = _resolved_for_save(config_path, config_path)
    # The file the save writes stays inside the directory the config's own
    # chain is confined to, the root resolve_config_document uses for a root
    # config with no source directory given: the config's directory, or the
    # directory holding ``.ash/`` for a config in it. The root is taken from
    # the config path AS SPELLED, where a link sits, never from its resolution:
    # the resolved path is the link's target itself, so a root taken from it
    # would hold the target wherever the link led and confine nothing
    # (default_confinement_root resolves first, so it is not used here). A
    # symlinked config is written through to its target (so the link stays a
    # link), but only to a target inside that root, as resolved. A link placed
    # in a repository that pointed outside it (dangling or not) made the save
    # create or edit a file wherever the link led, with no confinement; the
    # documented ``.ash/.ash.yaml`` linked to a config beside ``.ash/`` stays
    # inside the root and saves through.
    anchor = config_path.parent
    if anchor.name == ".ash":
        anchor = anchor.parent
    inside = _resolved_for_save(anchor, config_path)
    if inside not in target.parents:
        raise _left_unchanged(
            "the config is a link to a file outside its own directory (for a "
            "config in .ash/, the directory holding .ash/), which the suppression "
            "save does not write through",
            config_path,
        )
    try:
        earlier_status: Optional[os.stat_result] = target.stat()
    except FileNotFoundError:
        earlier_status = None
    # An existing config this process may not write is refused before
    # anything is staged: the replace of a staged file needs only the
    # directory, so the save would otherwise succeed on a file its owner
    # made read-only and bypass the file's own mode.
    if earlier_status is not None and not os.access(target, os.W_OK):
        raise _left_unchanged(
            "the config is not writable, so the suppression is not saved",
            config_path,
        )
    # A new config is created as a plain create would make it; an existing
    # one's copy starts private and takes the earlier mode below. A directory
    # this process may not write refuses the staging, and the replace below
    # needs the same directory, so that is the deployment's shape: refused in
    # the save's own words (raised outside the handler, so no reader of the
    # refusal reaches the raw PermissionError naming the random staging file).
    staging: Optional[tuple] = None
    try:
        staging = _staged_beside(target, 0o666 if earlier_status is None else 0o600)
    except PermissionError:
        pass
    if staging is None:
        raise _left_unchanged(
            "the config's directory is not writable, so the suppression is not saved",
            config_path,
        )
    descriptor, staged = staging
    kept_mode: Optional[int] = None
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if earlier_status is not None:
                kept_mode = _give_earlier_owner_and_mode(
                    handle.fileno(), earlier_status
                )
            handle.write(new)
            handle.flush()
            os.fsync(handle.fileno())
        written = staged.read_bytes()
        if written != new:
            raise _left_unchanged(
                "the saved config did not read back as written", config_path
            )
        if kept_mode is not None and not hasattr(os, "fchmod"):
            os.chmod(staged, kept_mode)
        # The config as it is now, against the bytes the save was built from:
        # a change written to it since that read (an editor's save, a second
        # suppression save) would otherwise be replaced by bytes that never
        # held it. The window left is the one between this read and the
        # replace below. Read as every other config read is: opened without
        # waiting for a writer and held to a regular file, so a name swapped
        # for a FIFO since the first read cannot stall the save. A file that
        # can no longer be read that way is not the bytes the save was built
        # from either.
        from automated_security_helper.config.config_sources import read_config_bytes
        from automated_security_helper.core.exceptions import ASHConfigSourceError

        current: Any
        try:
            current = read_config_bytes(target)
        except FileNotFoundError:
            current = None
        except (OSError, ASHConfigSourceError):
            current = object()
        if current != earlier:
            raise _left_unchanged(
                "the config changed while the suppression was being saved, so "
                "it is not saved; save it again",
                config_path,
            )
        replace_refusal: Optional[str] = None
        try:
            os.replace(staged, target)
        except PermissionError as denied:
            # A directory this process may write can still refuse the
            # replace. The deployment's shape, not a write failure, so it is
            # refused in the save's own words. A sticky directory (a shared,
            # /tmp-like one, which lets only the file's owner replace a file)
            # is named only when the bit can be what refused this process
            # (_sticky_refusal_applies): it is one cause among several (an
            # open handle on Windows, where no directory is sticky; an
            # immutable attribute; an LSM denial), and naming it whenever the
            # mode carried the bit sent an operator auditing modes that could
            # not have been the problem - a config this process owns, or a
            # brand-new one, is never what the bit protects. Otherwise the
            # refusal blames nothing (the cause can be the file itself, not
            # the directory) and the system's own reason rides along -
            # strerror alone, never the exception's filename, which is the
            # random staging file. The stat is a fresh read of a directory
            # that can change under us, so its own failure means only that
            # the cause stays unnamed.
            try:
                parent_status: Optional[os.stat_result] = target.parent.stat()
            except OSError:
                parent_status = None
            if parent_status is not None and _sticky_refusal_applies(
                earlier_status, parent_status
            ):
                replace_refusal = (
                    "the config's directory does not let this process replace "
                    "the file (a sticky directory), so the suppression is not "
                    "saved"
                )
            else:
                named = f" ({denied.strerror})" if denied.strerror else ""
                replace_refusal = (
                    f"the system refused to replace the file{named}, "
                    "so the suppression is not saved"
                )
        except OSError as error:
            if error.errno != errno.EBUSY:
                raise
            # rename(2) cannot replace a mount point, so a config mounted as
            # one file (a container's single-file volume) answers EBUSY. That
            # is the deployment's shape, not a write failure, so it is refused
            # in the save's own words rather than a raw OSError naming the
            # staging file. An in-place write here would open the truncation
            # window this staged write exists to close, exactly where the
            # atomic replace is impossible. Every other OSError stays raw: the
            # staged path in those messages is the path the OS refused.
            replace_refusal = (
                "the config is mounted as a single file (its directory entry "
                "cannot be replaced), so the suppression is not saved; mount "
                "the directory instead, or add the entry by hand"
            )
        if replace_refusal is not None:
            # Raised outside the handlers, as unparsed_config_reason's
            # docstring asks, so the refusal carries no chained error.
            raise _left_unchanged(replace_refusal, config_path)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    _sync_directory(target.parent)


def add_suppression_to_config(config_path: Path, suppression: AshSuppression) -> bool:
    """Add a suppression to the suppressions list in an .ash.yaml config file.

    Returns True when the entry was written, and False when the file already
    has an identical one, in which case the file is left as it was. Another
    suppression for the same rule and path (a second line range, a new reason
    or expiration) is a different entry and is written.

    Comment- and formatting-preserving by construction: the new entry is
    serialized with PyYAML (so quoting and escaping are correct) and inserted as
    text. A full ``yaml.safe_dump`` rewrite -- which drops every comment in the
    file -- is a last resort, reached only for a brand-new file or a structure
    that cannot be edited as text (an inline ``global_settings: {...}`` mapping),
    i.e. a file with no comments to preserve or a shape that essentially never
    occurs in practice.

    The save builds the file's new bytes, the lines it adds in the file's own
    line endings, and checks them in memory before anything is written
    (_write_checked): a result that would not load, would not hold the entry,
    would drop an entry the file held, or would change anything else in the
    document is refused with the file untouched.
    The write then goes through a staged file that replaces the config in one
    step, so no failure leaves the file holding part of the new bytes.
    """
    from automated_security_helper.config.config_sources import (
        is_json_file,
        is_toml_file,
        refuse_unless_a_file,
        unparsed_config_reason,
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    # Without client_supplied: ASH sets it, and a value written in a config file
    # is ignored (IgnorePathWithReason.client_supplied).
    entry = suppression.model_dump(exclude_none=True, exclude={"client_supplied"})
    if is_toml_file(config_path):
        raise _left_unchanged(
            f"Suppressions are saved by editing YAML; {config_path} is TOML. Add "
            "the suppression to its global_settings.suppressions by hand",
            config_path,
        )
    # Before any open: a FIFO's open waits for a writer, and a device is not a
    # config. A path that does not exist yet passes, and is created below.
    # The shared check's words, with the save's closing promise; raised
    # outside the handler so the check's error is not its context.
    not_a_file: Optional[str] = None
    try:
        refuse_unless_a_file(config_path)
    except ASHConfigSourceError as e:
        not_a_file = str(e)
    if not_a_file is not None:
        raise _left_unchanged(not_a_file, config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    # The file's bytes as they are: what a failed write puts back, and where
    # its own line ending is read from.
    earlier: Optional[bytes] = (
        config_path.read_bytes() if config_path.exists() else None
    )
    eol = _line_ending(earlier)
    if is_json_file(config_path):
        json_text: Optional[str] = None
        undecoded: Optional[str] = None
        if earlier is not None:
            try:
                # The decode sits inside a guard: a file that is not UTF-8
                # raises UnicodeDecodeError, whose message prints the byte's
                # value. Refused here, before any write, in the words
                # the writer's own guard uses.
                json_text = earlier.decode("utf-8")
            except UnicodeDecodeError as e:
                undecoded = unparsed_config_reason(config_path, e)
        if undecoded is not None:
            # Outside the handler, so the decoder's error is not its context.
            raise _left_unchanged(undecoded, config_path)
        # A leading byte order mark, which the loader reads past (utf-8-sig)
        # and json.loads refuses: held apart and put back, as for YAML below.
        json_mark = ""
        if json_text is not None and json_text.startswith(chr(0xFEFF)):
            json_mark, json_text = json_text[0], json_text[1:]
        new_json, held_json = _json_config_with_entry(
            config_path, json_text, suppression
        )
        if new_json is None:
            return False
        _write_checked(
            config_path,
            (
                json_mark
                + "".join(_ending_with(new_json.splitlines(keepends=True), eol))
            ).encode("utf-8"),
            suppression,
            held_json,
            is_json=True,
            earlier=earlier,
        )
        return True

    # A brand-new file has no comments to lose, so a fresh dump is fine.
    if earlier is None:
        _write_checked(
            config_path,
            _config_dump_with_entry({}, entry).encode("utf-8"),
            suppression,
            [],
        )
        return True

    text = ""
    unparsed: Optional[str] = None
    try:
        # The decode sits inside the guard: a file that is not UTF-8 raises
        # UnicodeDecodeError, a ValueError, whose message prints the byte's
        # value. _KeepsEnvReferences, because a config carrying the
        # documented !ENV tag is valid here: the entry goes in as text, with
        # the reference as written, and this load reads nothing from the
        # environment. Decoded from the bytes as they are, so each line keeps
        # its own ending.
        text = earlier.decode("utf-8")
        data = (
            yaml.load(text, Loader=_KeepsEnvReferences)  # nosec B506 - a SafeLoader
            or {}
        )
    except (yaml.YAMLError, ValueError) as e:
        # The parser's message for a load from a str quotes a snippet of the
        # malformed line, its own words can quote a token of it either way, and
        # a constructor's ValueError (!!int) quotes the value
        # (unparsed_config_reason). A file that does not parse cannot be edited
        # as text here anyway: where the list is to be inserted is unknown.
        unparsed = unparsed_config_reason(config_path, e)
    if unparsed is not None:
        # Outside the handler, so the parser's error is not its context.
        raise _left_unchanged(unparsed, config_path)

    # The file's own leading byte order mark (some Windows editors write one):
    # YAML reads past it, while the line scan reads the first key from column
    # 0, so the mark is held apart from the scanned text and put back on the
    # written bytes.
    mark = ""
    if text.startswith(chr(0xFEFF)):
        mark, text = text[0], text[1:]

    # A shape the list cannot live in is refused by name, before any check
    # that would read keys off it or report the appended text's failure as
    # the file's.
    if isinstance(data, dict):
        settings_value = data.get("global_settings")
        if settings_value is not None and not isinstance(settings_value, dict):
            raise _left_unchanged(
                f"global_settings in {config_path} is not a mapping, so there "
                "is no block to add the suppression to",
                config_path,
            )
        if isinstance(settings_value, dict):
            entries_value = settings_value.get("suppressions")
            if entries_value is not None and not isinstance(entries_value, list):
                raise _left_unchanged(
                    f"global_settings.suppressions in {config_path} is not a "
                    "list the entry can be appended to",
                    config_path,
                )

    # A file that extends a base and has no suppressions list of its own gets
    # its suppressions from the base. Writing a list here would replace that
    # list (lists from the extending file win; see config/config_sources.py) and
    # silently drop the base's suppressions.
    if (
        isinstance(data, dict)
        and "extends" in data
        and not isinstance(
            (data.get("global_settings") or {}).get("suppressions"), list
        )
    ):
        raise _left_unchanged(
            f"{config_path} extends another config and has no suppressions list "
            "of its own, so writing one would replace the base's suppressions. "
            "Add it as a patch instead: patch: [{op: add, path: "
            "/global_settings/suppressions/-, value: {...}}]",
            config_path,
        )
    if _patch_op_over_the_list(data):
        raise _left_unchanged(_PATCH_OVER_THE_LIST.format(config_path), config_path)

    # An identical entry is not written twice. Matching on rule_id and path
    # alone dropped a second line range of the same file while the caller
    # reported it saved.
    held: list = []
    if isinstance(data, dict):
        existing = (data.get("global_settings") or {}).get("suppressions") or []
        if any(_same_suppression(e, suppression) for e in existing):
            return False
        if isinstance(existing, list):
            held = list(existing)

    lines = text.splitlines(keepends=True)

    if isinstance(data, dict) and (data.get("global_settings") or {}).get(
        "suppressions"
    ) in ([], None):
        # config init writes `suppressions: []`, and a null (`~`, `null`)
        # holds no entry either; the line drops the value so the entry below
        # goes under the key as the list's first block item. With no
        # suppressions key at all there is no line to rewrite, and the
        # helper leaves the lines alone.
        _blocked_empty_suppressions(lines)

    key_idx, _ = _suppressions_key_line(lines)
    if key_idx is not None and _holds_a_value_on_its_line(lines[key_idx]):
        # A flow list (other than the empty one rewritten above) or a scalar
        # on the key's line: a block item cannot follow it.
        raise _left_unchanged(
            f"global_settings.suppressions in {config_path} is written on its "
            "key's line (a flow list or a value), where a block item cannot "
            "follow it; write it as a block list, one '- ' item per entry, or "
            "add the suppression by hand",
            config_path,
        )
    if key_idx is not None and _value_line_under_key(lines, key_idx):
        # The same shapes with the value starting on the line under the key:
        # still nothing a block item can follow, and without this refusal the
        # rewrite below would double the key and fail in the loader's words,
        # which name nothing the operator can act on.
        raise _left_unchanged(
            f"global_settings.suppressions in {config_path} holds its value "
            "on the line under its key (a flow list or a value), where a "
            "block item cannot follow it; write it as a block list, one "
            "'- ' item per entry, or add the suppression by hand",
            config_path,
        )

    # A top-level mapping in flow style takes none of the text edits below:
    # each inserts block lines, which a flow mapping cannot hold, so it goes
    # to the full rewrite (Case D).
    flow_root = _flow_style_root(lines)

    # Case A: a suppressions list already exists -> insert the item at its end.
    insert_idx, list_indent = _find_suppressions_append_point(lines)
    if insert_idx is not None and not flow_root:
        _insert_lines(
            lines, insert_idx, _serialize_entry_lines(entry, list_indent), eol
        )
        _write_checked(
            config_path,
            f"{mark}{''.join(lines)}".encode("utf-8"),
            suppression,
            held,
            earlier=earlier,
        )
        return True

    # Case B: a block-style global_settings exists but has no suppressions key ->
    # insert the key plus the item at the end of that block. This is the common
    # first-suppression case, and the one the old full-rewrite fallback silently
    # stripped every comment from. A `global_settings: {}` or a spelled null
    # holds nothing either; its line drops the value first, so the key goes
    # under it as a block child instead of through the whole rewrite.
    _blocked_empty_global_settings(lines)
    gs_insert_idx, gs_child_indent = _find_global_settings_insert_point(lines)
    if gs_insert_idx is not None and not flow_root:
        block = [f"{gs_child_indent}suppressions:\n"]
        block += _serialize_entry_lines(entry, gs_child_indent + "  ")
        _insert_lines(lines, gs_insert_idx, block, eol)
        _write_checked(
            config_path,
            f"{mark}{''.join(lines)}".encode("utf-8"),
            suppression,
            held,
            earlier=earlier,
        )
        return True

    # Case C: content, but no global_settings key at all -> append a fresh block
    # at EOF, leaving every existing line (and comment) untouched.
    if not flow_root and not _has_top_level_key(lines, "global_settings"):
        block = ["global_settings:\n", "  suppressions:\n"]
        block += _serialize_entry_lines(entry, "    ")
        _insert_lines(lines, len(lines), block, eol)
        _write_checked(
            config_path,
            f"{mark}{''.join(lines)}".encode("utf-8"),
            suppression,
            held,
            earlier=earlier,
        )
        return True

    # Case D (last resort): a shape we cannot safely edit as text, e.g. an inline
    # `global_settings: {...}` mapping or a flow-style top-level mapping. Fall
    # back to a full rewrite. This loses comments, but only for a structure that
    # essentially never occurs.
    from automated_security_helper.config.config_sources import (
        text_reads_the_environment,
    )

    # Read from the text this save edits, not from the file again: a second
    # read that failed (or found other bytes) answered that nothing was read
    # from the environment, and the rewrite then dropped the !ENV tags.
    if text_reads_the_environment(config_path, text):
        # A rewrite here dumps what _KeepsEnvReferences read: each reference's
        # own text with its !ENV tag dropped, so a tagged reference the
        # implicit ${VAR} form does not cover would stop being resolved. (The
        # config update and wizard refusal in cli/config.py reads with the
        # resolving loader, so a rewrite THERE would write values; this one
        # would not.)
        raise _left_unchanged(
            f"{config_path} reads values from the environment through "
            "environment references (${VAR} or !ENV), and its shape can only "
            "be saved by a full rewrite, which would drop the !ENV tags; "
            "add the suppression by hand",
            config_path,
        )
    dumped = _config_dump_with_entry(data if isinstance(data, dict) else {}, entry)
    _write_checked(
        config_path,
        f"{mark}{''.join(_ending_with(dumped.splitlines(keepends=True), eol))}".encode(
            "utf-8"
        ),
        suppression,
        held,
        earlier=earlier,
        # The dump writes the parsed document back whole, as the JSON save
        # does, so a repeated key anywhere would silently drop its first
        # block while both parsed documents agree: checked at any depth.
        whole_rewrite=True,
    )
    return True


class _ConfigDumper(NoCommandLineDumper, yaml.SafeDumper):
    """``yaml.safe_dump``, with no line a CI workflow command
    (utils/report_yaml.py)."""


def _reference_shaped_strings_quoted(
    dumper: "_ConfigDumper", value: str
) -> yaml.ScalarNode:
    """Every string ``_ConfigDumper`` writes, quoted when the loader's
    implicit ``!ENV`` resolver would otherwise read it from the environment
    on reload (ENV_REFERENCE_PATTERN; implicit resolvers apply to plain
    scalars only), and written as ``SafeDumper`` writes a string otherwise.

    The loader tags a PLAIN scalar matching the pattern as an implicit
    ``!ENV`` read, so a reason the operator typed starting ``${...}`` saved
    unquoted came back with the variable's value substituted - the literal
    text lost, and an environment value flowing wherever the reason prints -
    and a whole-document dump turned every deliberately quoted ``'${ASH_X}'``
    literal already in the file back into a resolving reference. Quoting is
    the loader's own documented way to write a value that only looks like a
    reference. This representer is the rule's one home: the text-edit save
    serializes its entry through this dumper too, so a second entry-level
    marking would be the same rule written twice, free to drift. Keys pass
    through here too, and the loader resolves a plain key the same way, so a
    reference-shaped key is quoted as a value is. The blind spot is
    _KeepsEnvReferences' own: an explicitly ``!ENV``-tagged reference is read
    as its bare text, which this quoting would freeze into a literal - such
    files never reach a full rewrite, because the save refuses any file whose
    text ``text_reads_the_environment`` answers True for.
    """
    style = "'" if ENV_REFERENCE_PATTERN.match(value) else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_ConfigDumper.add_representer(str, _reference_shaped_strings_quoted)
# AshConfig.save's direct-dump modes serialize through this dumper, so it needs
# the TaggedReference representer: a reference saved as written is tagged !ENV.
_ConfigDumper.add_representer(TaggedReference, represent_tagged_reference)


def _serialize_entry_lines(entry: dict, item_indent: str) -> list[str]:
    """Render one suppression entry as indented YAML lines.

    Serialized with ``_ConfigDumper`` so a reason (or any value) containing
    ``"``, ``\\``, ``:`` or ``#`` is quoted and escaped correctly, and one the
    loader's implicit ``!ENV`` resolver would read from the environment is
    quoted so it reloads as the text the operator wrote
    (_reference_shaped_strings_quoted, the dumper's own str representer).
    ``[entry]`` is emitted with the item at column 0 (``- key: value`` then
    ``  key: value``); each line is prefixed with ``item_indent``.
    """
    dumped = yaml.dump(
        [entry],
        Dumper=_ConfigDumper,
        default_flow_style=False,
        sort_keys=False,
    )
    return [f"{item_indent}{line}\n" for line in dumped.splitlines()]


#: global_settings' suppressions list as JSON-Pointer segments.
_SUPPRESSIONS_POINTER = ("global_settings", "suppressions")

#: The save's refusal for a file whose own patch decides the list
#: (_patch_op_over_the_list); formatted with the config path.
_PATCH_OVER_THE_LIST = (
    "{} has a patch operation of its own that replaces, moves, removes or "
    "tests global_settings.suppressions (or a node above it), and the file's "
    "patch applies after its list is read, so an entry written to the list "
    "would not be in the list a scan reads, or the file would stop loading. "
    "Add it as a patch instead: patch: [{{op: add, path: "
    "/global_settings/suppressions/-, value: {{...}}}}]"
)


def _patch_op_over_the_list(document: Any) -> bool:
    """Whether *document*, a parsed config file, has a ``patch`` operation that
    writes, removes or tests global_settings' suppressions list, or a node
    that holds it, or that moves one of them away.

    A file's own patch applies after the file's keys are read
    (config_sources), so such an operation decides the list a scan reads: a
    ``replace`` drops the entry the save adds, and a ``test`` of the list no
    longer holds once the list has one more entry, so the file stops loading.
    An ``add`` at ``/global_settings/suppressions/-`` or at an index, and every
    operation inside the list or elsewhere, leaves the entry in place. A
    segment is read with "-" and "_" as one, as the patch's pointer walk reads
    it, after the pointer's own escapes.
    """
    ops = document.get("patch") if isinstance(document, dict) else None
    if not isinstance(ops, list):
        return False
    for op in ops:
        if not isinstance(op, dict):
            continue
        pointers = [op.get("path")]
        if op.get("op") == "move":
            pointers.append(op.get("from"))
        for pointer in pointers:
            if not isinstance(pointer, str):
                continue
            segments = tuple(
                segment.replace("~1", "/").replace("~0", "~").replace("-", "_")
                for segment in pointer.split("/")[1:]
            )
            if _SUPPRESSIONS_POINTER[: len(segments)] == segments:
                return True
    return False


def _json_config_with_entry(
    config_path: Path, text: Optional[str], suppression: AshSuppression
) -> tuple:
    """add_suppression_to_config for a ``.json`` config file: ``(new_text,
    held)``, the file's new text and the suppressions it held, or ``(None,
    [])`` when it already has an identical entry.

    The text edits add_suppression_to_config makes insert YAML lines, which left
    a ``.json`` config that neither JSON nor ASH's loader could parse, so the
    next scan ran with the default configuration. JSON holds no comments to
    preserve, so the file's *text* (None, when there is no file) is parsed,
    changed and dumped whole.
    """
    from automated_security_helper.config.config_sources import unparsed_config_reason

    data: Any = {}
    if text is not None:
        unparsed: Optional[str] = None
        try:
            # json's own error can quote the line (unparsed_config_reason), as
            # the YAML path formats it. The caller decodes the bytes
            # inside its own guard.
            data = json.loads(text)
        except json.JSONDecodeError as e:
            unparsed = unparsed_config_reason(config_path, e)
        if unparsed is not None:
            # Outside the handler, so the parser's error is not its context.
            raise _left_unchanged(unparsed, config_path)
    if not isinstance(data, dict):
        raise _left_unchanged(f"{config_path} does not hold a JSON object", config_path)
    # One rule for both formats: null means empty, as the YAML save and the
    # in-memory compare (_apart_from_the_entry) read it. setdefault returns an
    # existing null, which was then refused as "is not an object"/"is not a
    # list" for the file's own explicit null.
    if data.get("global_settings") is None:
        data["global_settings"] = {}
    global_settings = data.setdefault("global_settings", {})
    if not isinstance(global_settings, dict):
        raise _left_unchanged(
            f"global_settings in {config_path} is not an object", config_path
        )
    if "extends" in data and not isinstance(global_settings.get("suppressions"), list):
        raise _left_unchanged(
            f"{config_path} extends another config and has no suppressions list "
            "of its own, so writing one would replace the base's suppressions. "
            "Add it as a patch instead",
            config_path,
        )
    if _patch_op_over_the_list(data):
        raise _left_unchanged(_PATCH_OVER_THE_LIST.format(config_path), config_path)
    if global_settings.get("suppressions") is None:
        global_settings["suppressions"] = []
    suppressions = global_settings.setdefault("suppressions", [])
    if not isinstance(suppressions, list):
        raise _left_unchanged(
            f"global_settings.suppressions in {config_path} is not a list",
            config_path,
        )
    if any(_same_suppression(e, suppression) for e in suppressions):
        return (None, [])
    held = list(suppressions)
    suppressions.append(
        suppression.model_dump(exclude_none=True, exclude={"client_supplied"})
    )
    return (json.dumps(data, indent=2) + "\n", held)


def _config_dump_with_entry(data: dict, entry: dict) -> str:
    """*data* with *entry* appended to its suppressions, as a full
    ``_ConfigDumper`` dump. Only for files with no comments to preserve."""
    if not isinstance(data, dict):
        data = {}
    global_settings = data.setdefault("global_settings", {})
    if not isinstance(global_settings, dict):
        global_settings = {}
        data["global_settings"] = global_settings
    suppressions_list = global_settings.setdefault("suppressions", [])
    if not isinstance(suppressions_list, list):
        suppressions_list = []
        global_settings["suppressions"] = suppressions_list
    suppressions_list.append(entry)
    return yaml.dump(
        data, Dumper=_ConfigDumper, default_flow_style=False, sort_keys=False
    )


def _has_top_level_key(lines: list, key: str) -> bool:
    return any(
        (len(line) - len(line.lstrip())) == 0 and _key_on_line(line, key) is not None
        for line in lines
    )


def _flow_style_root(lines: list) -> bool:
    """Whether the document's top-level mapping is written in flow style
    (``{project_name: demo}``): the first line holding anything but a
    comment, a directive, a ``---`` marker or the document's anchor and tag
    starts with ``{``.

    No text edit applies to such a file: each one inserts block lines, which
    cannot follow or sit inside a flow mapping, so the result never parsed
    and the save was refused instead of reaching the full rewrite.
    """
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("---"):
            stripped = stripped[len("---") :].strip()
        while stripped.startswith(("&", "!")):
            parts = stripped.split(None, 1)
            stripped = parts[1].strip() if len(parts) > 1 else ""
        if not stripped or stripped.startswith(("#", "%")):
            continue
        return stripped.startswith("{")
    return False


def _find_global_settings_insert_point(lines: list) -> tuple:
    """End-of-block index and child indent for a block-style global_settings.

    Returns ``(insert_index, child_indent)`` for a top-level ``global_settings:``
    that has block children, or ``(None, None)`` if it is absent or inline
    (``global_settings: {...}``). A block with no children to anchor indentation
    on (only comments or blank lines under the key, or nothing) gets two spaces,
    the indent ``_config_dump_with_entry`` writes: the whole rewrite that such
    a file used to take dropped every comment it held.
    """
    in_global = False
    block_end = None
    child_indent = None
    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        indent_len = len(line) - len(stripped)
        if not in_global:
            key_length = (
                _key_on_line(stripped, "global_settings") if indent_len == 0 else None
            )
            if key_length is not None:
                # An inline mapping value after the colon is not
                # text-insertable. A trailing comment is not a value, and an
                # anchor or tag alone names or types the block below (as
                # _holds_a_value_on_its_line reads them): taking either for a
                # value sent the save to the whole rewrite, which drops every
                # comment the file holds.
                rest = stripped[key_length:].strip()
                while rest.startswith(("&", "!")):
                    parts = rest.split(None, 1)
                    rest = parts[1].strip() if len(parts) > 1 else ""
                if rest and not rest.startswith("#"):
                    return (None, None)
                in_global = True
                block_end = idx + 1
            continue
        if stripped == "":
            continue  # inside the block, but not a child to anchor on
        if stripped.startswith("#"):
            # Indented, it can be a block scalar's content line, which the
            # block runs through: inserting before it put the new key inside
            # that scalar. A real comment there is kept in the block either
            # way. At column 0 it is a comment, never content.
            if indent_len > 0:
                block_end = idx + 1
            continue
        if indent_len == 0:
            break  # a following top-level key: the block has ended
        if child_indent is None:
            child_indent = line[:indent_len]
        block_end = idx + 1
    if not in_global:
        return (None, None)
    if child_indent is None:
        child_indent = "  "
    return (block_end, child_indent)


def _find_suppressions_append_point(lines: list) -> tuple:
    """Where a new item goes at the end of global_settings' suppressions list.

    Returns ``(insert_index, list_item_indent)``, or ``(None, None)`` when
    global_settings has no suppressions key of its own. The list runs from the
    key's line through the last line, past blank and comment lines, that is
    part of it: indented deeper than the key, or an item (``-``) at the key's
    own indent, where YAML lets a block sequence sit. The first other line at
    or below the key's indent, a sibling global_settings key or a top-level
    key, ends it. The item indent is the list's first item's, or two spaces
    deeper than the key when it has none.
    """
    key_idx, key_indent = _suppressions_key_line(lines)
    if key_idx is None:
        return (None, None)
    insert_idx = key_idx + 1
    item_indent: Optional[str] = None
    for idx in range(key_idx + 1, len(lines)):
        line = lines[idx]
        stripped = line.lstrip(" \t")
        indent = len(line) - len(stripped)
        if not stripped.strip():
            continue
        if stripped.startswith("#"):
            # Deeper than the key, it can be a line of an entry's block
            # scalar, which the list runs through: inserting before it put the
            # new item inside that scalar. A real comment there is kept in the
            # list either way. At or left of the key's indent no scalar's
            # content can sit, so it is a comment and ends nothing.
            if indent > key_indent:
                insert_idx = idx + 1
            continue
        is_item = _a_block_item(stripped)
        if indent < key_indent or (indent == key_indent and not is_item):
            break
        if is_item and item_indent is None:
            item_indent = line[:indent]
        insert_idx = idx + 1
    if item_indent is None:
        item_indent = lines[key_idx][:key_indent] + "  "
    return (insert_idx, item_indent)


BuildConfig.model_rebuild()
ConverterConfigSegment.model_rebuild()
ScannerConfigSegment.model_rebuild()
ReporterConfigSegment.model_rebuild()
PluginContext.model_rebuild()
# Load-bearing, and not obviously so: AshAggregatedResults.ash_config is annotated
# Optional["AshConfig"] as a string, and this is the line that resolves it for any
# process that imports this module -- AshConfig is in scope here, which is all
# model_rebuild() needs. models/asharp_model.py resolves it a second way, on first
# use, for the import orders that never reach this line. Either mechanism alone
# suffices, so this one looks like dead duplication; deleting it narrows the fix to
# one mechanism and puts model_json_schema() back at the mercy of import order.
AshAggregatedResults.model_rebuild()
