"""Module containing the Checkov security scanner implementation."""

import contextlib
import logging
import os
import platform
import re
from pathlib import Path
from typing import Annotated, ClassVar, Dict, List, Literal

from pydantic import Field, model_validator
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.constants import ASH_ASSETS_DIR
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolArgs,
    ToolExtraArg,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.cfn_template_model import (
    CloudFormationTemplateModelError,
    cloudformation_candidate_files,
    NO_CLOUDFORMATION_TEMPLATE,
    NO_PARSEABLE_CLOUDFORMATION_TEMPLATE,
    UNDECODABLE_DAMAGED,
    UNDECODABLE_NOT_A_TEMPLATE,
    cloudformation_nothing_to_scan_reason,
    describe_parse_error,
    get_model_from_template_text,
    holds_cloudformation_template,
    judge_undecodable_candidate,
    read_template_text,
    unevaluable_template_reason,
    unmarked_wide_template_reason,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.download_utils import (
    NO_BIN_DIRECTORY,
    current_bin_path,
    refusing_install_command,
)
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.output_excerpt import tool_output_excerpt
from automated_security_helper.utils.scanned_tree import TreeInputRefused
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import CFN_NAG_GEM_VERSION
from automated_security_helper.utils.undecodable_text import text_of_undecodable


#: The directory, inside each template's results directory, that holds the copy of
#: the template cfn_nag_scan reads. Removed once cfn_nag_scan has run.
_CFN_NAG_INPUT_DIR = ".ash-cfn-nag-input"

#: The copy's name, less its extension. Fixed, so the path cfn_nag_scan is given is
#: the same whatever the template is called, including on Windows, where
#: cfn_nag_scan is the RubyGems wrapper cfn_nag_scan.bat.
_CFN_NAG_INPUT_STEM = "template"

#: The extensions the scanner selects templates by. The copy keeps the template's
#: own, so cfn_nag sees a JSON template as JSON and a YAML one as YAML.
_CFN_NAG_INPUT_SUFFIXES = (".json", ".yaml", ".yml")


def _stage_cfn_nag_input(results_file_dir: Path, cfn_file: str, text: str) -> Path:
    """Write the template text ASH checked where cfn_nag_scan will read it.

    cfn_nag_scan opens its ``--input-path`` by name. Giving it the scanned-tree path
    would let a file replaced after ASH's check be read in its place; a copy of the
    checked text cannot be. The copy is named ``template`` plus the template's
    extension whatever the template is called (see ``_CFN_NAG_INPUT_STEM``), and is
    written without following a link (``open_for_write``) because the results
    directory is one a sandboxed scanner can write. Findings on it are pointed back
    at the template by :func:`_restore_cfn_nag_uris`.
    """
    suffix = Path(cfn_file).suffix.lower()
    if suffix not in _CFN_NAG_INPUT_SUFFIXES:
        suffix = ".yaml"
    staged = results_file_dir.joinpath(
        _CFN_NAG_INPUT_DIR, f"{_CFN_NAG_INPUT_STEM}{suffix}"
    )
    staged.parent.mkdir(parents=True, exist_ok=True)
    with open_for_write(staged) as handle:
        handle.write(text)
    return staged


def _as_cfn_nag_renders(path: str | Path, run_dir: str | Path) -> str:
    """The artifact URI cfn_nag writes for an input path, run in ``run_dir``.

    cfn_nag's SARIF view (``result_view/sarif_results.rb``, ``relative_path``) keeps a
    relative path as given and renders an absolute one relative to ``Pathname.pwd``,
    which is the working directory's real path.

    The template path comes from the scan set as given, not resolved, so it is
    made relative to ``run_dir`` as given first and to its real path only when
    that escapes: with a source directory reached through a symbolic link, the
    real path alone gave a ``../``-escaping URI for every finding.
    """
    if not Path(path).is_absolute():
        return Path(path).as_posix()
    relative = None
    for base in (os.path.abspath(run_dir), os.path.realpath(run_dir)):
        try:
            relative = os.path.relpath(path, base)
        except ValueError:  # another drive, on Windows
            return Path(path).as_posix()
        if not _escapes(relative):
            break
    return Path(relative).as_posix()


def _escapes(relative: str) -> bool:
    """Whether a relative path leaves the directory it is relative to."""
    return relative == ".." or relative.startswith(".." + os.sep)


def _cfn_nag_sarif_text(stdout: str) -> tuple[str, int]:
    """cfn_nag_scan's stdout from the line that opens its SARIF document.

    cfn_nag's SPCM rule prints a diagnostic line to stdout when it cannot read a
    policy, before the SARIF document, so the whole stream did not parse and every
    finding for the template was discarded. The lines before the first one that
    starts with ``{`` are dropped; the second value is how many.
    """
    lines = stdout.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.lstrip().startswith("{"):
            return "".join(lines[index:]), index
    return stdout, 0


#: What a rule that raised under --isolate-custom-rule-exceptions leaves on stderr:
#: cfn_nag rescues the rule's exception, prints it and goes on, so the template
#: exits 0 with no record of the rule that did not run. Ruby prints an exception
#: handed to ``puts`` as its MESSAGE, with no class name: "wrong number of
#: arguments (given 1, expected 2)" was the whole line the arity defect left
#: (tests/integration/scanners/test_cfn_nag_custom_rules.py measured it). A class
#: name appears in the inspect form (``#<ArgumentError: ...>``), the uncaught form
#: (``... (ArgumentError)``), or a custom rule's own message (``MyRuleError: no such
#: attribute``). All of these are read: a line that names an exception class
#: anywhere counts, unless it is a Ruby or gem ``warning:`` line (a deprecation
#: warning naming a class is not a raise). A custom rule that raises with a message
#: naming no class and matching none of the standard openings is still missed.
_RUBY_EXCEPTION_FORMS = re.compile(
    r"#<[A-Z][A-Za-z0-9:]*(?:Error|Exception)\b|\([A-Z][A-Za-z0-9:]*(?:Error|Exception)\)\s*$"
)
#: A Ruby exception class name anywhere in a line (the base's reading, kept for a
#: custom rule's raise; a ``warning:`` line is excluded before this is applied).
_RUBY_EXCEPTION_CLASS = re.compile(r"\b[A-Z][A-Za-z0-9]*(?:Error|Exception)\b")
#: How Ruby's standard exceptions begin their messages, lowercased.
_RUBY_EXCEPTION_MESSAGES = (
    "wrong number of arguments",
    "undefined method",
    "undefined local variable or method",
    "uninitialized constant",
    "no implicit conversion of",
    "can't convert",
    "comparison of ",
    "divided by 0",
    "stack level too deep",
    "invalid byte sequence",
    "key not found:",
    "can't be coerced",
    "wrong argument type",
    "unknown keyword",
    "missing keyword",
)


def _rule_exception_lines(stderr: str) -> List[str]:
    """The stderr lines that are a Ruby exception, which is a rule that raised."""
    raised: List[str] = []
    for line in stderr.splitlines():
        stripped = line.strip()
        if not stripped or "warning:" in stripped:
            continue
        lowered = stripped.lower()
        if (
            _RUBY_EXCEPTION_FORMS.search(stripped)
            or _RUBY_EXCEPTION_CLASS.search(stripped)
            or any(opening in lowered for opening in _RUBY_EXCEPTION_MESSAGES)
        ):
            raised.append(stripped)
    return raised


#: Where macOS keeps a real compiler: the Command Line Tools, Xcode, or the
#: developer directory ``xcode-select`` points at. Without one of these,
#: ``/usr/bin/cc``, ``gcc`` and ``clang`` are stubs that offer to install the
#: tools and build nothing.
_MACOS_DEVELOPER_DIRS = (
    "/Library/Developer/CommandLineTools",
    "/Applications/Xcode.app/Contents/Developer",
)


def _macos_developer_tools_present() -> bool:
    """Whether a real C compiler is installed on macOS, by its developer directory.

    A filesystem probe, not a process: ``xcode-select -p`` would say the same,
    and this runs while the scanner is constructed, which starts nothing.
    """
    candidates = [os.environ.get("DEVELOPER_DIR"), *_MACOS_DEVELOPER_DIRS]
    return any(
        Path(directory, "usr", "bin", "clang").exists()
        for directory in candidates
        if directory
    )


#: The most bytes a template's results directory name may take before the
#: ``-2``, ``-3`` suffix of ``_unique_name``. A file name holds 255 bytes, so this
#: leaves room for a suffix of up to fourteen digits.
_RESULTS_DIR_NAME_BYTES = 240


def _unique_name(name: str, used: Dict[str, int]) -> str:
    """``name``, or ``name-2``, ``name-3`` and so on when an earlier template of
    this scan took it.

    ``get_normalized_filename`` maps ``/`` and ``.`` alike to ``__``, so
    ``a/b.yaml`` and ``a__b.yaml`` named one results directory and the later
    template's stdout and stderr logs overwrote the earlier one's.
    """
    count = used.get(name, 0) + 1
    used[name] = count
    return name if count == 1 else f"{name}-{count}"


def _ruby_headers_present(system_include: Path = Path("/usr/include")) -> bool:
    """Whether ``ruby.h`` is installed beside the ``ruby`` on PATH, or cannot be told.

    Linux distributions split the headers into a development package, and psych's
    native extension needs them; ``gem`` and a C compiler alone pass the probe
    and the build then fails on the missing header. Looked for under the
    interpreter's prefix and the system include directory, in both layouts: Debian
    and Ubuntu put it at ``include/ruby-<version>/ruby.h``, Fedora, RHEL and Amazon
    Linux (``ruby-devel``) at ``include/ruby.h``.

    False only when the interpreter's own ``include`` directory exists and holds
    neither: that is a ruby whose headers are a package not installed. When that
    directory does not exist the probe cannot tell: a version manager's shim (rbenv,
    asdf, mise) is a script on PATH whose prefix has no include directory, while the
    headers sit under the version it selects. Then, and when no ``ruby`` is on PATH
    (the RubyGems probe reports that), the answer is True and the gem install
    reports a missing header itself.
    """
    ruby = find_executable("ruby")
    if ruby is None:
        return True
    own_include = Path(os.path.realpath(ruby)).parent.parent / "include"
    for include in (own_include, system_include):
        if (include / "ruby.h").is_file() or any(include.glob("ruby-*/ruby.h")):
            return True
    return not own_include.is_dir()


def _restore_cfn_nag_uris(
    report: SarifReport, staged: Path, cfn_file: str, run_dir: str | Path
) -> None:
    """Point findings on the staged copy back at the template they came from.

    Matched on the copy's directory and file name, which nothing else in a cfn_nag
    report carries. The replacement is the URI cfn_nag gives the template when it
    reads it in place, so the findings are what they were without the copy. It is
    assigned after the report was validated, so it is put in the record form here
    (utils/undecodable_text.py): a template name that is not UTF-8 would otherwise
    stop the report from being written.
    """
    staged_tail = f"{_CFN_NAG_INPUT_DIR}/{staged.name}"
    original = text_of_undecodable(_as_cfn_nag_renders(cfn_file, run_dir))
    for run in report.runs or []:
        for result in run.results or []:
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                uri = getattr(artifact, "uri", None)
                if artifact is not None and uri:
                    if uri.replace("\\", "/").endswith(staged_tail):
                        artifact.uri = original


class CfnNagScannerConfigOptions(ScannerOptionsBase):
    pass


class CfnNagScannerConfig(ScannerPluginConfigBase):
    name: Literal["cfn-nag"] = "cfn-nag"
    enabled: bool = True
    options: Annotated[
        CfnNagScannerConfigOptions,
        Field(description="Configure CFN Nag scanner"),
    ] = CfnNagScannerConfigOptions()


@ash_scanner_plugin
class CfnNagScanner(ScannerPluginBase[CfnNagScannerConfig]):
    """CfnNagScanner implements SECRET scanning using CFN Nag."""

    #: cfn_nag is a Ruby gem. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    # ~/.gem/ruby, not ~/.gem: the gems live under ~/.gem/ruby/<version>, and
    # ~/.gem itself also holds the RubyGems credentials file, which cfn_nag has
    # no reason to read.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        read_paths=("~/.local/share/gem", "~/.gem/ruby", "$GEM_HOME"),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        if self.config is None:
            self.config = CfnNagScannerConfig()
        self.command = "cfn_nag_scan"
        self.tool_type = ScannerToolType.IAC
        self.rule_directory = ASH_ASSETS_DIR.joinpath("appsec_cfn_rules")
        extra_args = [
            ToolExtraArg(
                key="--print-suppression",
                value=None,
            ),
            # --isolate-custom-rule-exceptions bounds the damage a defect in one of the
            # four rules under --rule-directory can do. cfn_nag's CustomRuleLoader wraps
            # each rule in `rescue ScriptError, StandardError` and then immediately
            # re-raises unless this flag is set; the exception matches none of the
            # rescue clauses in CfnNag#audit and the executor has none at all, so it
            # reaches the top of the process, which exits before rendering any output.
            # The cost is therefore not the broken rule's verdict but every rule's
            # verdict on that template. That is not hypothetical: two of the four rules
            # in this directory shipped a call that raised ArgumentError on every
            # invocation, and the measurements for it are in the docstrings of
            # tests/integration/scanners/test_cfn_nag_custom_rules.py, which is also
            # where the argv that reproduces both failure modes lives.
            #
            # This changes cfn_nag's failure mode for every rule it loads, not only for
            # the ones ASH ships, which is the intended trade: a rule that raises should
            # cost its own verdict and nothing else.
            ToolExtraArg(
                key="--isolate-custom-rule-exceptions",
                value=None,
            ),
            # --ignore-fatal is deliberately absent, and its absence is load-bearing.
            #
            # cfn-model raises when it cannot parse a template -- an unresolved Ref or
            # GetAtt to a logical id not declared in that file is the common case -- and
            # cfn_nag turns that into a violation with id FATAL. A FATAL violation
            # carries no logical resource ids, and the SARIF renderer emits one result
            # per id, so FATAL renders as nothing whether or not this flag is passed.
            # What the flag additionally does is prune FATAL before the failure count is
            # computed, which drops the process exit status to 0.
            #
            # That leaves a template no rule was ever evaluated against reporting a
            # complete SARIF document, a fully populated rule driver, zero results, zero
            # bytes of stderr, and exit 0 -- identical in every observable respect to a
            # compliant template. Measured against cfn-nag 0.8.10 and cfn-model 0.6.6 --
            # the versions assets/Gemfile.lock pins and CFN_NAG_GEM_VERSION installs --
            # over four template shapes with
            #
            #   cfn_nag_scan --print-suppression [--ignore-fatal] \
            #       --output-format sarif --input-path <template>
            #
            # an unresolved-Ref template and a clean template both give exit 0 with zero
            # results when the flag is passed, and the two SARIF documents are the same
            # size. Without the flag the unresolved-Ref template gives exit 1 with zero
            # results while the clean template gives exit 0, and a template with real
            # findings gives a non-zero exit with a non-empty result set. So the pair
            # (exit status, result count) separates all three, and _evaluated_no_rule
            # below reads it. A suppressed violation is removed before the count, so a
            # fully suppressed template still exits 0 and is not mistaken for a failure.
            ToolExtraArg(
                key="--rule-directory",
                value=self.rule_directory.as_posix(),
            ),
        ]
        # No flag follows ASH's own log level. cfn_nag_scan defines no --verbose
        # option (its debug switch is --debug), so passing one at DEBUG made every
        # invocation exit 255 with no stdout, and the whole cfn-nag scan then
        # failed as "no output". Its --debug is not passed either: that output
        # goes to stdout, which is parsed as the SARIF document.
        self.args = ToolArgs(
            format_arg="--output-format",
            format_arg_value="sarif",
            scan_path_arg="--input-path",
            extra_args=extra_args,
        )

        super().model_post_init(context)

    @staticmethod
    def _missing_gem_prerequisites() -> List[str]:
        """Prerequisites for installing cfn-nag that are absent from this machine.

        Two of them, and neither is speculative.

        RubyGems, because cfn-nag is a gem. And a C compiler, because its closure
        does not install without one: cfn-nag depends on cfn-model, which requires
        ``psych ~> 3``, and psych has a C extension over libyaml. No psych 3.x release
        publishes a precompiled gem for a modern Windows ABI -- checked against the
        RubyGems API, 3.1.0 is the newest 3.x carrying any Windows binary and it is
        tagged x64-mingw32 while Ruby 3.1+ needs x64-mingw-ucrt -- so it must build
        from source. ASH's own container installs build-essential purely to get
        through this step and then purges it.

        Measured, not assumed: on windows-latest the gem install reached
        "ERROR: Failed to build gem native extension" and returned 1, which failed
        `ash dependencies install` outright and took every other scanner's install
        down with it. Checking first turns that into cfn-nag reporting itself as
        unprovisionable on this platform -- named in the installer's output, next to
        npm-audit -- which is a constraint rather than a malfunction.

        The two platforms are probed differently because the requirement differs.
        On POSIX, `cc`/`gcc`/`clang` on PATH is the requirement, and the hosted Linux
        and macOS runners have it, which is why cfn-nag installs and runs there.

        Windows is probed on RI_DEVKIT instead, because on Windows a compiler being
        present does not predict the build succeeding. Measured on 18e5cba9: extconf
        found psych's vendored libyaml and wrote a Makefile ("checking for yaml.h...
        yes", "creating Makefile"), and make then failed with

            No rule to make target
            '/C/hostedtoolcache/windows/Ruby/3.3.12/x64/include/ruby-3.3.0/ruby.h'

        -- an MSYS-translated path handed to a make from a different tree. What the
        build needs is one coherent MSYS2 environment where sh, make and gcc all come
        from the same install, and RI_DEVKIT is the marker for that: `ridk enable`
        sets it (rubyinstaller2, lib/ruby_installer/build/msys2_installation.rb) as
        part of activating that environment. Probing for a compiler instead is worse
        than not probing, because it passes on a stray gcc and licenses the attempt.

        The CI leg supplies that environment with `ruby/setup-ruby`, whose default
        `windows-toolchain` unpacks the ucrt64 gcc bundle and runs `ridk enable`; see
        .github/actions/run-scan-test/action.yml. A Windows machine without it still
        reports cfn-nag as unprovisionable rather than failing every other scanner's
        install, which is the intended behavior and not a platform exclusion.
        """
        missing: List[str] = []
        if find_executable("gem") is None:
            missing.append("RubyGems (`gem`) is not on PATH")

        if platform.system() == "Windows":
            # Windows is checked on RI_DEVKIT rather than on a compiler being present,
            # and the difference is not pedantic. A first attempt probed for
            # cc/gcc/clang; windows-latest has a gcc on PATH (MinGW arrives with other
            # tooling in that image), so the probe passed, the gem install ran, and it
            # still died with "Failed to build gem native extension" -- because Ruby's
            # mkmf needs a toolchain matching its own ABI, x64-mingw-ucrt, not whatever
            # gcc happens to be reachable. RI_DEVKIT is the variable RubyInstaller's
            # devkit and ruby/setup-ruby both export, so it is the marker that actually
            # tracks buildability here.
            if not os.environ.get("RI_DEVKIT"):
                missing.append(
                    "no Ruby DevKit (RI_DEVKIT is unset), and cfn-nag's `psych` "
                    "dependency publishes no precompiled gem for this Ruby ABI, so it "
                    "has to build from source"
                )
        elif not any(find_executable(cc) for cc in ("cc", "gcc", "clang")):
            missing.append(
                "no C compiler (cc, gcc or clang) is on PATH, and cfn-nag's `psych` "
                "dependency has to build from source"
            )
        elif platform.system() == "Darwin" and not _macos_developer_tools_present():
            # macOS ships cc, gcc and clang as stubs that pass a PATH probe and
            # then offer to install the Command Line Tools instead of compiling,
            # so the gem install was declared, failed building psych, and took
            # every other scanner's install down with it.
            missing.append(
                "the Xcode Command Line Tools are not installed (the cc, gcc and "
                "clang on PATH are the stubs that offer to install them), and "
                "cfn-nag's `psych` dependency has to build from source"
            )
        elif platform.system() == "Linux" and not _ruby_headers_present():
            # Linux only: distributions ship the headers as a separate package
            # (ruby-dev, ruby-devel), and a host with ruby and gcc but no headers
            # passed the probe and then failed the whole dependency install on
            # psych's build. Elsewhere the headers come with the interpreter.
            missing.append(
                "Ruby's development headers (ruby.h) are not installed beside the "
                "ruby on PATH, and cfn-nag's `psych` dependency has to build "
                "against them"
            )
        return missing

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "CfnNagScanner":
        """Set up the installation command for cfn-nag.

        cfn-nag is a Ruby gem, not a release binary, so it does not go through the
        pinned-digest download path the way grype, syft and trivy do. Forcing it
        into that path would mean pinning a digest for every gem in its dependency
        closure, which is what a lockfile is for.

        What that costs, stated plainly: this command pins cfn-nag itself exactly
        and lets RubyGems resolve the closure within cfn-nag's own constraints.
        The committed ``assets/Gemfile.lock`` pins the whole closure and remains
        the stricter artifact -- it is what the container image builds against.
        ``bundle install --gemfile`` was tried instead and rejected: that lock's
        PLATFORMS section lists only ``ruby``, so on Windows and macOS bundler
        needs the platform added before it will resolve, and an installer that
        works on one platform and errors on two is worse than one that pins
        slightly less.

        A Ruby interpreter is a prerequisite, not something ASH installs, and the
        command is therefore declared only when `gem` is actually present.

        Declaring it unconditionally was wrong in a way worth recording. `gem`
        missing makes run_command return 1 on FileNotFoundError, which counts as a
        failed install command, which fails the whole run -- so on a machine without
        Ruby, `ash dependencies install` would exit non-zero for every plugin
        together, before any scan. That is a different and worse outcome than
        cfn-nag being unavailable, and it contradicts how the same condition is
        treated one plugin over: npm-audit needs a Node runtime ASH does not
        install, declares no command, and is reported as a constraint rather than a
        malfunction. Two identical situations should not diverge on the accident of
        whether one of them declares a command that cannot work.

        With the gate, a machine without Ruby reports cfn-nag under "no install path
        on this platform" -- by name, next to npm-audit -- and a machine with Ruby
        installs it.
        """
        missing = self._missing_gem_prerequisites()
        if missing:
            # At WARNING only where it matters: with cfn_nag_scan already on PATH
            # (the official image installs the gem and then purges its compiler)
            # nothing needs installing, and every scanner construction warned
            # about an install that was never going to run.
            installed = find_executable("cfn_nag_scan") is not None
            ASH_LOGGER.log(
                logging.DEBUG if installed else logging.WARNING,
                f"cfn-nag cannot be installed here: {', '.join(missing)}. "
                + (
                    "cfn_nag_scan is already on PATH, so nothing needs installing."
                    if installed
                    else "It will be reported as having no install path on this "
                    "machine rather than failing the install of every other scanner."
                ),
            )
            return self

        # --user-install and --bindir together, and both are load-bearing.
        #
        # --user-install because a plain `gem install` writes to the interpreter's
        # GEM_HOME, which on a stock Linux runner is root-owned; without it the
        # install needs sudo and fails without it.
        #
        # --bindir because the binstub otherwise lands in whichever bin directory
        # that Ruby installation happens to use, and ASH looks on PATH and in
        # ASH_BIN_PATH -- not in a user gem bin. Pointing it at ASH_BIN_PATH makes
        # cfn-nag findable without depending on how the host arranges its Ruby.
        # Verified that a relocated binstub still activates the gem from the user
        # directory, since Gem.path includes it by default. With no bin directory
        # there is no --bindir to give, and the command only says so.
        bin_dir = current_bin_path()
        command = (
            refusing_install_command(NO_BIN_DIRECTORY)
            if bin_dir is None
            else CustomCommand(
                args=[
                    "gem",
                    "install",
                    "cfn-nag",
                    "-v",
                    CFN_NAG_GEM_VERSION,
                    "--no-document",
                    "--user-install",
                    "--bindir",
                    str(bin_dir),
                ],
                shell=False,
            )
        )
        for target_platform in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                self.custom_install_commands.setdefault(target_platform, {})[arch] = [
                    command
                ]
        return self

    #: For a target scan() found no template in; see the base class.
    nothing_scanned_reason: ClassVar[str | None] = NO_CLOUDFORMATION_TEMPLATE

    def nothing_to_scan_reason(self) -> str | None:
        """None when either tree holds a CloudFormation template; see the base class."""
        return cloudformation_nothing_to_scan_reason(self.context)

    def _process_config_options(self):
        # Add any additional config option parsing here, if necessary
        # For Python-based scanners, this typically won't be needed as we will access
        # the configuration directly from the self.config object.
        return super()._process_config_options()

    @staticmethod
    def _evaluated_no_rule(file_sarif: SarifReport, returncode) -> bool:
        """Whether this per-file run failed without rendering a single result.

        cfn_nag's exit status is its count of failing violations, and every violation a
        rule produces carries at least one logical resource id -- ``BaseRule#audit``
        returns nil when the id list is empty, so a rule cannot report a violation
        against nothing. The SARIF renderer emits one result per id. Put together, a
        rule violation always renders at least one SARIF result.

        The one failing violation that renders nothing is FATAL, which cfn_nag
        manufactures when cfn-model raises during parsing and which has no ids at all.
        So a non-zero exit with an empty result set means the count came from something
        SARIF could not represent, and the only thing in that category is a template
        that was never evaluated. That is why this reads the exit status rather than
        re-running the template: with ``--ignore-fatal`` withheld the signal is already
        on the first invocation, so no second invocation is needed.

        Deliberately not gated on the rule driver being populated. An empty driver
        alongside a non-zero exit is a stronger reason to distrust the run, not a
        reason to exempt it.
        """
        if returncode is None:
            return False
        try:
            code = int(returncode)
        except (TypeError, ValueError):
            # An exit status ASH cannot read is not evidence that rules ran.
            return True
        if code == 0:
            return False
        return not any(run.results for run in (file_sarif.runs or []))

    def _sarif_exit_code_accepted(self) -> bool:
        """cfn_nag's exit status is its count of failing violations (the rule
        ``_evaluated_no_rule`` reads), so any non-negative count from a run
        whose targets were all evaluated is a completed execution; the base
        set ``{0, 1}`` graded a clean run with two violations unsuccessful.
        The non-zero exit that rendered nothing is already a
        failed target in the counters, which grade first. A signal death is
        no count. A tool that never started is read from the recorded spawn
        failure (``scan_spawn_failure``, set by ``_run_subprocess`` from the
        response's flag), not from the code: ASH's could-not-start marker,
        127, is also what cfn_nag returns for a template with 127 (mod 256)
        failing violations, and that complete run was graded unsuccessful."""
        if self.scan_spawn_failure is not None:
            return False
        return self.exit_code is not None and self.exit_code >= 0

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — CfnNag overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CfnNagScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute CFN Nag scan and return results.

        Args:
            target: Path to scan

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        # Top of the method, above all five early returns, for the reason the same pair
        # carries in cdk_nag_scanner: an initialization placed further down is inherited by
        # whichever return sits above it, and the executor then reads stale attributes from
        # the previous target. exit_code for the same reason, and None because no
        # cfn_nag has run for this target yet: a template the model rejects is failed
        # without starting it; the invocation below reports the largest code of
        # this target's cfn_nag_scan runs.
        self.targets_attempted = 0
        self.targets_failed = 0
        # self.errors too, as cdk_nag_scanner resets it: the executor runs this
        # instance over the source and then the converted target, and the error
        # lines of the first were reported again as the second's.
        self._reset_errors()
        self.exit_code = None
        self._nothing_scanned_reason = None
        self.clear_unevaluated_targets()

        tool_component = ToolComponent(
            name="cfn_nag",
            semanticVersion=self.tool_version,
            version=self.tool_version,
            informationUri="https://github.com/stelligent/cfn_nag",
        )
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine=self.command,
                            # Nothing attempted yet, so the rule reads True;
                            # this report is returned only on the
                            # nothing-to-scan paths above the template loop.
                            executionSuccessful=self._sarif_execution_successful(),
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return sarif_report

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        if not self.dependencies_satisfied:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        try:
            # Absolute: cfn_nag_scan runs in the source directory and opens its
            # --input-path by name, so a staged copy under a relative --output-dir
            # was looked for relative to the source directory and not found.
            target_results_dir = Path(
                os.path.abspath(self.results_dir.joinpath(target_type))
            )

            # Every JSON and YAML file in the tree; shared with cdk-nag and with
            # nothing_to_scan_reason, which answers from this same selection. The
            # selection drops the files the global ignore paths ignore and honors
            # the repository's ignore files as the scan set does.
            scannable = cloudformation_candidate_files(
                self.context, target_type, global_ignore_paths
            )
            joined_files = "\n- ".join(scannable)
            ASH_LOGGER.debug(
                f"Found {len(scannable)} JSON/YAML files:\n- {joined_files}"
            )

            if len(scannable) == 0:
                self._plugin_log(
                    f"No JSON/YAML files found in {target_type} directory to scan. Exiting.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                return sarif_report

            # Process each template file. The counters above replace a local failed_files
            # list that was appended to on both failure paths and never read, so a run that
            # failed on every template still produced an empty-but-successful report.
            sarif_tool = Tool(driver=tool_component)
            sarif_output_file = target_results_dir.joinpath("cfn_nag.sarif")
            sarif_output_file.parent.mkdir(exist_ok=True, parents=True)
            # Templates for which cfn_nag_scan wrote nothing at all. Collected rather
            # than raised on immediately so that every template is still attempted and
            # named, and the partial report still reaches disk; what happens below
            # depends on whether any template's document parsed.
            unrendered: List[str] = []
            # Templates whose stdout parsed as SARIF. Counts parsed documents, not
            # bytes written: a template whose stdout is a fatal line counts as a
            # failed target, not here.
            parsed_sarif = 0
            # The tree the candidates came from. A template is read under the
            # scanned-tree rule against it, so a symlink or a file outside it is
            # refused before ASH parses it or hands it to cfn_nag_scan.
            scan_root = (
                self.context.work_dir
                if target_type == "converted"
                else self.context.source_dir
            )
            # The results directory names already taken in this scan (_unique_name).
            results_dir_names: Dict[str, int] = {}
            for cfn_file in scannable:
                # Whether this template was already counted as a failed target, so
                # the except arm below does not count it a second time.
                failed_counted = False
                # This file's text once it is read, for the except arm below. Reset
                # each time, so a file that cannot be read is never judged by the
                # text of the file before it.
                text_read: str | None = None
                try:
                    self._plugin_log(
                        f"Checking if file is CloudFormation: {cfn_file}",
                        target_type=target_type,
                        level=logging.DEBUG,
                    )
                    # Read once, under the scanned-tree rule. The model is built from
                    # this text and cfn_nag_scan is given a copy of it, so both see
                    # the file that was checked.
                    template_text = read_template_text(cfn_file, scan_root)
                    text_read = template_text
                    cfn_model = get_model_from_template_text(
                        template_text, Path(cfn_file)
                    )
                    if cfn_model:
                        self._plugin_log(
                            f"File *is* CloudFormation: {cfn_file}",
                            target_type=target_type,
                            level=logging.DEBUG,
                        )
                    else:
                        self._plugin_log(
                            f"cfn_model is falsey, but no error was thrown: {cfn_file}",
                            target_type=target_type,
                            level=logging.DEBUG,
                        )
                except TreeInputRefused as refused:
                    # Not read, so not known to be CloudFormation: an expected skip like
                    # the not-CloudFormation case below, and counted the same way. It is
                    # a warning, and kept in the scanner's error stream, so the skip is
                    # in the results rather than only in a TRACE line.
                    self._plugin_log(
                        f"Skipped {refused.path}: {refused.reason}",
                        target_type=target_type,
                        level=logging.WARNING,
                        append_to_stream="stderr",
                    )
                    continue
                except CloudFormationTemplateModelError as e:
                    # A document carrying a Resources mapping is CloudFormation, so
                    # failing to model it is an ASH-side limitation rather than a
                    # property of the file. Counted as a failed target, which is the
                    # whole point of splitting this out of the skip below: the skip sits
                    # above `targets_attempted += 1`, so a scan set in which every
                    # template tripped the model ended at zero attempts and the
                    # container reported SKIPPED with exit code 0. Counting it also
                    # makes a single occurrence visible to
                    # --fail-on-incomplete-scanners, which reads targets_failed.
                    self.targets_attempted += 1
                    self.targets_failed += 1
                    self.record_unevaluated_target(cfn_file)
                    reason = (
                        "the template carries a Resources mapping but could not be "
                        f"modeled as CloudFormation: {type(e.error).__name__}"
                    )
                    # ERROR puts the line in self.errors too, so it is not appended.
                    self._plugin_log(
                        f"cfn_nag did not evaluate {cfn_file}: {reason}",
                        target_type=target_type,
                        level=logging.ERROR,
                    )
                    continue
                except (OSError, UnicodeDecodeError) as e:
                    # The file could not be opened or decoded, so it is not known
                    # to be CloudFormation, and not known not to be. The
                    # tool-absent check counts an unreadable candidate as a
                    # template (only MISSING cannot hide one), and cfn-lint and
                    # cfn-guard count it as a failed, unevaluated target, so it
                    # is counted here the same way: a template saved as UTF-16
                    # beside good ones graded the cfn_nag scan PASSED while the
                    # other two scanners reported ERROR. ERROR puts the line in
                    # self.errors too, so it is not appended.
                    #
                    # A file that is not UTF-8 is judged from its text first,
                    # decoded as well as it can be, as discover_templates and the
                    # tool-absent check judge it (judge_undecodable_candidate,
                    # which answers a failed second read as a template, so no
                    # except arm here): its STRUCTURE makes it a failed target,
                    # as on the UTF-8 route; a marker alone makes it a damaged
                    # template, named as unparseable and counted as nothing, as
                    # its UTF-8 twin is below; neither makes it a skip. One that
                    # is not CloudFormation (a UTF-16 appsettings.json, a Latin-1
                    # locale file) no longer fails every CloudFormation scanner,
                    # and a Jinja-templated stack reads the same in any encoding.
                    if isinstance(e, UnicodeDecodeError):
                        judged = judge_undecodable_candidate(cfn_file, scan_root)
                        if judged == UNDECODABLE_DAMAGED:
                            self._nothing_scanned_reason = (
                                NO_PARSEABLE_CLOUDFORMATION_TEMPLATE
                            )
                            self._plugin_log(
                                f"Skipped {cfn_file}: it could be a CloudFormation "
                                "template but could not be parsed: not UTF-8, and "
                                "its text carries a CloudFormation marker with no "
                                f"Resources mapping: {type(e).__name__}",
                                target_type=target_type,
                                level=logging.WARNING,
                                append_to_stream="stderr",
                            )
                            continue
                        if judged == UNDECODABLE_NOT_A_TEMPLATE:
                            self._plugin_log(
                                f"Skipped {cfn_file}: not UTF-8, and its text is "
                                "not a CloudFormation template: "
                                f"{type(e).__name__}",
                                target_type=target_type,
                                level=logging.WARNING,
                                append_to_stream="stderr",
                            )
                            continue
                    self.targets_attempted += 1
                    self.targets_failed += 1
                    self.record_unevaluated_target(cfn_file)
                    self._plugin_log(
                        f"cfn_nag did not evaluate {cfn_file}: the file could not "
                        f"be read: {type(e).__name__}",
                        target_type=target_type,
                        level=logging.ERROR,
                    )
                    continue
                except Exception as e:
                    # Everything else here comes out of the template parser: the file
                    # is not parseable as YAML or JSON, or a value in it could not be
                    # built, or it is nested deeper than ASH reads.
                    #
                    # The exception is named by type and line only. Its text quotes the
                    # file -- PyYAML prints the offending line -- and this is logged.
                    #
                    # A UTF-16 or UTF-32 template written without a byte-order mark
                    # decodes as UTF-8 without an error and reaches the parsers
                    # NUL-interleaved: a template ASH could not decode, counted as
                    # its marked twin is above, a failed target, where it was named
                    # as unparseable and counted as nothing.
                    unevaluated = (
                        unmarked_wide_template_reason(text_read)
                        if text_read is not None
                        else None
                    )
                    if unevaluated is None:
                        unevaluated = unevaluable_template_reason(
                            cfn_file, scan_root, text=text_read
                        )
                    if unevaluated is not None:
                        # A file whose structure is a template (a top-level Resources
                        # mapping) that ASH could not evaluate counts as an unevaluated
                        # target, like one the model rejects above. ERROR puts the line
                        # in self.errors too.
                        self.targets_attempted += 1
                        self.targets_failed += 1
                        self.record_unevaluated_target(cfn_file)
                        self._plugin_log(
                            f"cfn_nag did not evaluate {cfn_file}: {unevaluated}",
                            target_type=target_type,
                            level=logging.ERROR,
                        )
                        continue
                    # A SKIPPED target says a template could not be parsed only when
                    # this file could be one: the tool-absent check counts it, so the
                    # same tree without the tool is MISSING. A mkdocs.yml or a Helm
                    # template it does not count leaves "no CloudFormation template".
                    if holds_cloudformation_template([cfn_file], scan_root):
                        self._nothing_scanned_reason = (
                            NO_PARSEABLE_CLOUDFORMATION_TEMPLATE
                        )
                        # Named on the scanner's error stream, as a refused or
                        # unreadable file is: a damaged template left at TRACE
                        # vanished from the results, while cdk-nag records it.
                        self._plugin_log(
                            f"Skipped {cfn_file}: it could be a CloudFormation "
                            "template but could not be parsed: "
                            f"{describe_parse_error(e)}",
                            target_type=target_type,
                            level=logging.WARNING,
                            append_to_stream="stderr",
                        )
                        continue
                    self._plugin_log(
                        f"Not a CloudFormation file: {cfn_file}. "
                        f"Exception: {describe_parse_error(e)}",
                        target_type=target_type,
                        level=logging.TRACE,
                    )
                    continue
                if cfn_model is None:
                    self._plugin_log(
                        f"Not a CloudFormation file: {cfn_file}",
                        target_type=target_type,
                        level=logging.TRACE,
                    )
                    continue
                # Counted here rather than at the top of the loop: the two continues above
                # are non-CloudFormation files, which are an expected skip rather than a
                # scanner failure.
                self.targets_attempted += 1
                # Case is folded so two templates whose paths differ in case alone
                # (``Stack.yaml`` and ``stack.yaml``) do not share a directory on a
                # filesystem that ignores case, and the name is held to what one
                # path component may take, so a deeply nested template still gets
                # a directory.
                normalized_filename = _unique_name(
                    get_normalized_filename(
                        str_to_normalize=cfn_file,
                        fold_case=True,
                        max_bytes=_RESULTS_DIR_NAME_BYTES,
                    ),
                    results_dir_names,
                )
                results_file_dir = target_results_dir.joinpath(normalized_filename)
                try:
                    results_file_dir.mkdir(exist_ok=True, parents=True)
                    staged_input = _stage_cfn_nag_input(
                        results_file_dir, cfn_file, template_text
                    )
                except OSError as e:
                    # One template's results directory or staged copy could not
                    # be written. A failed target, named, and the loop goes on:
                    # escaping here aborted the whole scan and discarded every
                    # other template's findings.
                    reason = (
                        "the template's results directory or staged copy could "
                        f"not be written: {type(e).__name__}"
                    )
                    ASH_LOGGER.error(f"CFN Nag did not evaluate {cfn_file}: {reason}")
                    self.targets_failed += 1
                    self.errors.append(f"{cfn_file}: {reason}")
                    self.record_unevaluated_target(cfn_file)
                    continue
                try:
                    final_args = self._resolve_arguments(
                        target=staged_input, results_file=results_file_dir
                    )
                    proc_resp = self._run_subprocess(
                        command=final_args,
                        results_dir=results_file_dir,
                        stdout_preference="both",
                        stderr_preference="both",
                        timeout=self._effective_scan_timeout(),
                    )
                finally:
                    staged_input.unlink(missing_ok=True)
                    with contextlib.suppress(OSError):
                        staged_input.parent.rmdir()
                try:
                    stdout = proc_resp.get("stdout", "")
                    if not stdout or not stdout.strip():
                        reason = (
                            "cfn_nag returned no stdout "
                            f"(exit code {proc_resp.get('returncode', '?')})"
                        )
                        # error, not debug: no rule was evaluated against this template, and
                        # at debug level that was invisible on a default run.
                        ASH_LOGGER.error(f"CFN Nag returned no stdout for {cfn_file}")
                        self.targets_failed += 1
                        self.errors.append(f"{cfn_file}: {reason}")
                        unrendered.append(cfn_file)
                        continue
                    sarif_text, dropped_lines = _cfn_nag_sarif_text(stdout)
                    if dropped_lines:
                        # Their text can quote the template, so only the count.
                        ASH_LOGGER.warning(
                            f"cfn_nag wrote {dropped_lines} line(s) to stdout before "
                            f"its SARIF document for {cfn_file}; they are not part "
                            "of the report and were left out of the parse."
                        )
                    file_sarif = SarifReport.model_validate_json(json_data=sarif_text)
                    parsed_sarif += 1
                    _restore_cfn_nag_uris(
                        file_sarif, staged_input, cfn_file, self.context.source_dir
                    )
                    raised = _rule_exception_lines(proc_resp.get("stderr") or "")
                    if raised:
                        # A rule that raised under --isolate-custom-rule-exceptions:
                        # cfn_nag prints the exception to stderr, exits 0 and
                        # renders the other rules' results, so the template read
                        # as fully evaluated. Its findings are kept; the template
                        # is a failed target the executor will not grade clean.
                        reason = (
                            f"{len(raised)} cfn_nag rule(s) raised and were isolated, "
                            "so not every rule was evaluated against this template: "
                            f"{tool_output_excerpt(raised[0], 200)}"
                        )
                        ASH_LOGGER.error(
                            f"CFN Nag did not evaluate {cfn_file}: {reason}"
                        )
                        self.targets_failed += 1
                        self.errors.append(f"{cfn_file}: {reason}")
                        self.record_unevaluated_target(cfn_file)
                        failed_counted = True
                    # Counted once: a template whose rules raised is already a
                    # failed target above, whatever its exit code and result set.
                    if not raised and self._evaluated_no_rule(
                        file_sarif, proc_resp.get("returncode")
                    ):
                        reason = (
                            "cfn_nag reported a failure it could not render "
                            f"(exit code {proc_resp.get('returncode', '?')} with an "
                            "empty result set), which means no rule was evaluated "
                            "against this template"
                        )
                        ASH_LOGGER.error(
                            f"CFN Nag did not evaluate {cfn_file}: {reason}"
                        )
                        self.targets_failed += 1
                        self.errors.append(f"{cfn_file}: {reason}")
                        self.record_unevaluated_target(cfn_file)
                        continue
                    # cfn_nag writes its whole rule list into every report, so the
                    # first parsed one supplies the rules the merged results name.
                    # The merge below carries neither driver nor rules, and the
                    # branch that was meant to keep the first report's driver was
                    # dead (sarif_report is built above and is never None), so the
                    # merged report named rule ids its driver did not define.
                    driver = sarif_report.runs[0].tool.driver
                    file_run = file_sarif.runs[0] if file_sarif.runs else None
                    file_driver = (
                        file_run.tool.driver
                        if file_run is not None and file_run.tool is not None
                        else None
                    )
                    if (
                        not driver.rules
                        and file_driver is not None
                        and file_driver.rules
                    ):
                        driver.rules = list(file_driver.rules)
                    sarif_report.merge_sarif_report(
                        sarif_report=file_sarif,
                        include_invocation=False,
                        include_driver=False,
                        include_rules=False,
                    )
                except Exception as e:
                    ASH_LOGGER.warning(
                        f"Failed to parse CFN Nag results as SARIF: {str(e)}"
                    )
                    self.errors.append(f"{cfn_file}: {type(e).__name__}: {e}")
                    if not failed_counted:
                        self.targets_failed += 1
                        self.record_unevaluated_target(cfn_file)
                    continue

            # Every template failed. This is the one line that separates "your templates are
            # compliant" from "cfn_nag never evaluated a rule"; the reports are otherwise
            # identical. The zero case stays a success, because a run with no CloudFormation
            # in it completed fine and carries that fact as a SKIPPED status instead.
            if (
                self.targets_attempted > 0
                and self.targets_failed >= self.targets_attempted
            ):
                ASH_LOGGER.error(
                    f"cfn_nag failed on all {self.targets_attempted} template(s) in "
                    f"{target}. No rules were evaluated, so this result is NOT a clean scan."
                )

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            sarif_invocation: Invocation = Invocation(
                commandLine="ash-CFN Nag-scanner",
                arguments=[
                    "--target",
                    get_shortest_name(input=target),
                    "--scanner",
                ],
                startTimeUtc=self.start_time,
                endTimeUtc=self.end_time,
                executionSuccessful=self._sarif_execution_successful(),
                exitCode=self.exit_code,
                exitCodeDescription="\n".join(self.errors),
                workingDirectory=ArtifactLocation(
                    uri=get_shortest_name(input=target),
                ),
                properties=PropertyBag(
                    tool=sarif_tool,
                ),
            )
            if sarif_report.runs:
                sarif_report.runs[0].invocations = [sarif_invocation]
            with open_for_write(sarif_output_file) as fp:
                report_str = sarif_report.model_dump_json(
                    exclude_none=True,
                    exclude_unset=True,
                )
                fp.write(report_str)

            if unrendered and parsed_sarif == 0:
                # A hard scanner failure rather than one failed target among many,
                # and the distinction is the whole reason this raises: no template's
                # stdout parsed as SARIF, which with more than one template points
                # at the tool rather than at any one of them. With fewer than two
                # invoked templates the check cannot tell a tool fault from a
                # template fault, and this is the stricter reading.
                #
                # Raised here, after _post_scan and after the report is on disk, so
                # the timings are recorded.
                raise ScannerError(
                    "cfn_nag_scan produced no output for "
                    f"{len(unrendered)} of {self.targets_attempted} template(s), so "
                    "no rule was evaluated against them and this run is not a clean "
                    f"scan: {', '.join(unrendered)}"
                )
            for cfn_file in unrendered:
                # Some templates' documents parsed and these produced nothing: a
                # property of each template (a name cfn_nag_scan cannot render is
                # one), not of the tool. Raising here threw the other templates'
                # findings away with the verdict. The names are recorded instead,
                # and the executor refuses to grade the run PASSED over them
                # (unevaluated_targets), so the surviving findings are kept and the
                # run is still not a clean scan. Each name is already in
                # self.errors, which the invocation carries as its
                # exitCodeDescription.
                self.record_unevaluated_target(cfn_file)

            return sarif_report

        except Exception as e:
            # The end time is recorded on this path too: without it the executor
            # computed the row's duration from the previous target's end time.
            with contextlib.suppress(Exception):
                self._post_scan(target=target, target_type=target_type)
            # Check if there are useful error details
            raise ScannerError(f"{self.__class__.__name__} failed: {str(e)}")
