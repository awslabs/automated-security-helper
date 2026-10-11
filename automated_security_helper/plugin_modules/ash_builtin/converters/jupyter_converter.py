# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the JupyterConverter implementation."""

import glob
import json
import os
import re
import shutil
import subprocess  # nosec B404 — required for fallback when uv tool unavailable
import tempfile
from pathlib import Path
from typing import Annotated, List, Literal, Optional, Tuple

from pydantic import Field, PrivateAttr

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)

from automated_security_helper.base.options import (
    ConverterOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches as path_matches_pattern,
)
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    refusal_reason,
)
from automated_security_helper.utils.subprocess_utils import (
    child_environ,
    lookup_for_scan,
)

#: The name nbconvert is given the staged copy under, and the name it writes its
#: output under. Not the notebook's own name: nbconvert expands each notebook
#: argument with ``glob.glob``, so ``[x].ipynb`` matches only ``x.ipynb``, and it
#: passes the output name through ``str.format``, which a ``{`` in it breaks. ASH
#: names the converted file after the original notebook itself.
_STAGED_NAME = "notebook"

#: A ``language_info.file_extension`` the copy keeps. nbconvert's generic script
#: exporter appends the notebook's value to the output name, so one holding a path
#: separator or ``..`` would place the output outside the directory it was given.
_PLAIN_EXTENSION = re.compile(r"\.[A-Za-z0-9_+-]{1,16}")


class JupyterConverterConfigOptions(ConverterOptionsBase):
    tool_version: Annotated[
        str | None,
        tool_version_constraint("converters.jupyter.options.tool_version"),
        Field(
            description="Version constraint for nbconvert tool installation (e.g., '>=7.16.0'). If not specified, the latest version will be installed."
        ),
    ] = ">=7.16.0,<8.0.0"
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation (default: 300)"),
    ] = 300


class JupyterConverterConfig(ConverterPluginConfigBase):
    """Jupyter Notebook (.ipynb) to Python converter configuration."""

    name: Literal["jupyter"] = "jupyter"
    enabled: bool = True
    options: Annotated[
        JupyterConverterConfigOptions,
        Field(description="Configure Jupyter Notebook converter"),
    ] = JupyterConverterConfigOptions()


def _is_uv_error(stderr: object) -> bool:
    """Whether ``uv tool run`` failed itself, before nbconvert ran.

    uv reports its own errors on stderr either as ``error: ...`` or, for a tool it
    cannot resolve (offline with nbconvert not in its cache, for one), as a
    diagnostic that starts with ``×``. nbconvert's own failures start with a
    traceback or ``[NbConvertApp]``. Judged by the first line that is not blank.
    """
    if not isinstance(stderr, str):
        return False
    first = next((line.strip() for line in stderr.splitlines() if line.strip()), "")
    return first.startswith(("error:", "\u00d7"))


@ash_converter_plugin
class JupyterConverter(ConverterPluginBase[JupyterConverterConfig]):
    """Converter implementation for Jupyter notebooks security scanning."""

    # The jupyter-nbconvert executable for a direct run, once looked up, and when
    # it is None because an in-tree copy was refused, the reason.
    _direct_nbconvert: Optional[Tuple[Optional[str], Optional[str]]] = PrivateAttr(
        default=None
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = JupyterConverterConfig()

        self.command = "jupyter-nbconvert"
        self.uv_tool_package_name = "nbconvert"
        self.use_uv_tool = True  # Enable UV tool execution

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # Update tool version detection to work with explicit installation
        self.tool_version = self._get_uv_tool_version(
            self.command, self.uv_tool_package_name
        )

        return super().model_post_init(context)

    def _get_tool_version_constraint(self) -> Optional[str]:
        """Get version constraint for nbconvert installation.

        Returns:
            Version constraint string for nbconvert (e.g., ">=7.16.0") or None for latest
        """
        return self.config.options.tool_version

    def _get_tool_package_extras(self) -> Optional[List[str]]:
        """Get package extras for nbconvert installation.

        Returns:
            List of package extras needed for nbconvert. Should be nothing needed by
            default for script export.
        """
        return []

    def _get_tool_with_dependencies(self) -> Optional[List[str]]:
        """Get additional dependencies to install with nbconvert.

        Returns:
            List of additional dependencies needed for nbconvert (jupyter for CLI access)
        """
        return ["jupyter"]

    def validate_plugin_dependencies(self) -> bool:
        """Enhanced validation with explicit tool installation.

        This method implements the enhanced validation workflow that:
        1. Checks if UV tool is available when required
        2. Checks if tool is already available (UV or pre-installed)
        3. Attempts explicit tool installation if needed
        4. Falls back to existing validation methods
        5. Provides comprehensive logging for troubleshooting

        Returns:
            True if converter is ready to use, False otherwise
        """
        if self.use_uv_tool:
            # Check if tool is already available (UV-installed or pre-installed)
            installation_info = self._get_tool_installation_info()

            if installation_info.get("available"):
                # Tool is available either via UV or pre-installed
                source = installation_info.get("preferred_source", "unknown")
                if source == "uv":
                    ASH_LOGGER.debug(f"{self.command} already installed via UV tool")
                elif source == "pre_installed":
                    ASH_LOGGER.debug(
                        f"Using pre-installed {self.command} at {installation_info.get('pre_installed_path')}"
                    )
                return True

            # Tool not available, attempt installation
            installation_success = self._install_uv_tool(
                timeout=self.config.options.install_timeout
            )

            if installation_success:
                ASH_LOGGER.debug(f"UV tool installation successful for {self.command}")
                # Update tool version after successful installation
                self.tool_version = self._get_uv_tool_version(
                    self.command, self.uv_tool_package_name
                )
                return True
            else:
                ASH_LOGGER.warning(
                    f"UV tool installation failed for {self.command}, attempting fallback validation"
                )

        # Fallback: an installed jupyter-nbconvert, run directly by its absolute path,
        # in an empty directory like the conversion itself.
        nbconvert = self._nbconvert_for_direct_run()
        if nbconvert is not None:
            try:
                with tempfile.TemporaryDirectory(prefix="ash-nbconvert-cwd-") as empty:
                    result = subprocess.run(  # nosec B603 — list args, absolute path from find_executable_for_scan
                        [nbconvert, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=empty,
                        env=child_environ(),
                    )
                if result.returncode == 0:
                    ASH_LOGGER.debug(f"Found jupyter-nbconvert at {nbconvert}")
                    return True
            except (subprocess.SubprocessError, OSError):
                pass

        ASH_LOGGER.warning(
            f"Converter {self.command} is not available. "
            f"Jupyter notebook conversion will be skipped."
        )
        return False

    def _execute_nbconvert_via_uv(
        self, cmd: List[str], timeout: int = 60, cwd: Optional[Path] = None
    ) -> bool:
        """Execute jupyter nbconvert command via UV tool runner.

        Args:
            cmd: Command list to execute (should start with 'jupyter')
            timeout: Timeout in seconds
            cwd: Working directory for nbconvert. It must not be the scanned tree.
                ``NbConvertApp.init_syspath`` puts the working directory first on
                ``sys.path``, so a module there is importable by the exporter name a
                notebook gives, and ``TemplateExporter.extra_template_basedirs``
                defaults to it, so a ``python/`` or ``script/`` directory there
                replaces the template nbconvert renders the output with. With no
                value, an empty temporary directory is used.

        Returns:
            True if nbconvert succeeded, False if uv could not run it at all: uv is
            unavailable, the runner raised, or the process did not start. Only then
            does the caller fall back to running nbconvert directly; running it a
            second time after it failed on the notebook would double the time and
            report the second failure's reason.

        Raises:
            subprocess.CalledProcessError: nbconvert ran under uv and exited non-zero.
            subprocess.TimeoutExpired: nbconvert ran under uv and did not finish.
        """
        if cwd is None:
            with tempfile.TemporaryDirectory(prefix="ash-nbconvert-cwd-") as empty:
                return self._execute_nbconvert_via_uv(
                    cmd, timeout=timeout, cwd=Path(empty)
                )
        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            uv_runner = get_uv_tool_runner()

            # Check UV availability
            if not uv_runner.is_uv_available():
                ASH_LOGGER.debug("UV is not available for nbconvert execution")
                return False

            # Extract jupyter arguments (skip 'jupyter')
            if len(cmd) < 1 or cmd[0] != "jupyter":
                ASH_LOGGER.error(f"Invalid jupyter command format: {cmd}")
                return False

            jupyter_args = cmd[2:]  # Skip 'jupyter' and 'nbconvert'

            ASH_LOGGER.debug(f"Executing jupyter via UV with args: {jupyter_args}")

            # Use UV tool runner to execute jupyter (nbconvert tool provides jupyter command)
            result = uv_runner.run_tool(
                tool_name=self.command,
                package_name=self.uv_tool_package_name,
                args=jupyter_args,
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
                package_extras=None,
                version_constraint=None,  # Passing this value will cause an error in uv. The version was validated previously
                timeout=timeout,
            )

            from automated_security_helper.utils.subprocess_utils import (
                SpawnFailedProcess,
                TimedOutProcess,
            )

            if result.returncode == 0:
                ASH_LOGGER.debug("jupyter execution via UV succeeded")
                return True
            if isinstance(result, SpawnFailedProcess):
                ASH_LOGGER.warning(f"uv could not be started: {result.stderr}")
                return False
            if _is_uv_error(result.stderr):
                # uv's own failure (it prints "error: ..."), such as an environment
                # it could not provide offline: nbconvert never ran.
                ASH_LOGGER.warning(
                    f"uv could not run nbconvert: {str(result.stderr).strip()}"
                )
                return False
            if isinstance(result, TimedOutProcess):
                raise subprocess.TimeoutExpired(
                    result.args, timeout, result.stdout, result.stderr
                )
            raise subprocess.CalledProcessError(
                result.returncode, result.args, result.stdout, result.stderr
            )

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # nbconvert's own verdict on the notebook, not uv failing to start.
            raise
        except UVToolRunnerError as e:
            ASH_LOGGER.warning(f"UV tool runner error for jupyter: {e}")
            return False
        except ImportError as e:
            ASH_LOGGER.warning(f"UV tool runner module not available: {e}")
            return False
        except Exception as e:
            ASH_LOGGER.warning(f"Unexpected error during UV jupyter execution: {e}")
            return False

    def _notebooks_in_scan_set(self) -> List[str]:
        """Every ``.ipynb`` in the scan set, found without invoking nbconvert.

        Extracted from ``convert`` so ``candidate_input_count`` can answer from the same
        predicate rather than a second copy of it. A second copy is the specific thing to
        avoid here: the count decides whether a missing nbconvert costs coverage, so a
        copy that drifted from the real selection would make the completeness gate fire
        on files this converter would not have touched, or stay silent on ones it would.
        """
        ipynb_files = scan_set(
            source=self.context.source_dir,
            output=self.context.output_dir,
        )
        return [f.strip() for f in ipynb_files if f.strip().endswith(".ipynb")]

    def candidate_input_count(self) -> int | None:
        """How many notebooks this converter would convert, tool or no tool.

        ``scan_set`` reads the filesystem and the ignore rules; nbconvert is not involved,
        which is what lets this be answered for a converter that has already been dropped
        for an unavailable tool. That is the case it exists for: in ``--mode nix`` the dev
        shell supplies scanner binaries and exports ``ASH_OFFLINE=YES``, so
        ``uv tool install nbconvert`` is correctly refused and this converter is
        unavailable on every such run. Before this method the completeness gate reported
        that as lost conversion coverage even on a tree with no notebooks in it, which is
        what failed both nix CI legs on a fixture holding one YAML template, one Python
        file and one package.json.

        Returning a real count rather than None on the error path is deliberate: if the
        scan set cannot be read, that is not evidence of zero notebooks, so it answers
        None and the gate stays strict.
        """
        try:
            # Less the notebooks convert() would refuse, judged by the same check it
            # opens them with, so a symlinked notebook is not counted as lost coverage.
            return len(
                [
                    notebook
                    for notebook in self._notebooks_in_scan_set()
                    if refusal_reason(notebook, self.context.source_dir) is None
                ]
            )
        except Exception as exc:  # pragma: no cover - defensive
            ASH_LOGGER.debug(
                f"Could not count .ipynb candidates for the jupyter converter ({exc!r}); "
                "reporting no count so the completeness gate stays strict"
            )
            return None

    @staticmethod
    def _stage_notebook(content: bytes, staged: Path) -> str:
        """Write the notebook nbconvert will read, and choose its exporter.

        The exporter is ASH's choice, by the notebook's language: ``python`` for a
        Python notebook or one that names no language, and nbconvert's generic
        ``script`` otherwise. Two ``language_info`` keys are removed from the copy,
        because the notebook is tree content: ``nbconvert_exporter``, since nbconvert
        imports whatever class it names, and ``file_extension`` unless it is a plain
        extension, since the script exporter appends it to the output name. Content
        that is not a JSON object is copied unchanged and left for nbconvert to
        reject.

        Returns:
            The ``--to`` value to run nbconvert with.
        """
        exporter = "python"
        try:
            notebook = json.loads(content)
        except ValueError:
            notebook = None
        if isinstance(notebook, dict):
            metadata = notebook.get("metadata")
            language_info = (
                metadata.get("language_info") if isinstance(metadata, dict) else None
            )
            if isinstance(language_info, dict):
                language = language_info.get("name")
                if isinstance(language, str) and language.lower() not in ("", "python"):
                    exporter = "script"
                removed = "nbconvert_exporter" in language_info
                language_info.pop("nbconvert_exporter", None)
                extension = language_info.get("file_extension")
                if extension is not None and not (
                    isinstance(extension, str) and _PLAIN_EXTENSION.fullmatch(extension)
                ):
                    del language_info["file_extension"]
                    removed = True
                if removed:
                    content = json.dumps(notebook).encode("utf-8")
        staged.write_bytes(content)
        return exporter

    def _nbconvert_for_direct_run(self) -> Optional[str]:
        """The ``jupyter-nbconvert`` to run when uv cannot run nbconvert, or None.

        Looked up once, by :func:`find_executable_for_scan`, and run by that absolute
        path: ``jupyter-nbconvert`` itself, so ASH's lookup is the only one. A copy
        inside the scanned tree is refused here unless the operator allowed it.
        """
        if self._direct_nbconvert is None:
            self._direct_nbconvert = lookup_for_scan(
                self.command, self.context.source_dir
            )
        return self._direct_nbconvert[0]

    def _run_nbconvert(
        self,
        notebook: Path,
        output_dir: Path,
        display: str,
        exporter: str = "python",
    ) -> None:
        """Run nbconvert on ``notebook``, writing its output into ``output_dir``.

        nbconvert runs in the staged notebook's directory, which holds nothing but the
        copy. It must not run in the scanned tree: ``NbConvertApp.init_syspath`` puts
        the working directory first on ``sys.path``, and
        ``TemplateExporter.extra_template_basedirs`` defaults to it, so a module or a
        template directory there would be used.

        Args:
            notebook: The staged copy to convert.
            output_dir: An empty directory for nbconvert to write into. The output is
                named after the copy, ``notebook`` plus the exporter's extension.
            display: The original notebook's path, for messages.
            exporter: The ``--to`` exporter, as :meth:`_stage_notebook` chose it.

        Raises:
            subprocess.CalledProcessError: nbconvert exited non-zero.
            subprocess.TimeoutExpired: nbconvert did not finish in time.
            FileNotFoundError: uv could not run nbconvert and no jupyter-nbconvert
                was found to run it with.
        """
        run_dir = notebook.parent
        cmd = [
            "jupyter",
            "nbconvert",
            "--log-level",
            "WARN",
            "--to",
            exporter,
            # nbconvert expands each notebook argument with glob.glob. The name is
            # fixed, but the staging directory's path comes from TMPDIR.
            glob.escape(str(notebook)),
            "--output",
            notebook.stem,
            "--output-dir",
            str(output_dir),
        ]

        # Execute using UV tool runner if available, otherwise direct execution
        if self.use_uv_tool:
            if self._execute_nbconvert_via_uv(cmd, timeout=60, cwd=run_dir):
                return
            ASH_LOGGER.warning(
                f"UV tool execution failed for {display}, trying direct execution"
            )
        nbconvert = self._nbconvert_for_direct_run()
        if nbconvert is None:
            refusal = self._direct_nbconvert[1] if self._direct_nbconvert else None
            raise FileNotFoundError(
                "uv could not run nbconvert, and "
                + (refusal or "no jupyter-nbconvert executable was found on PATH")
            )
        direct = [nbconvert, *cmd[2:]]
        result = subprocess.run(  # nosec B603 — list args, absolute path from find_executable_for_scan
            direct,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=run_dir,
            env=child_environ(),
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, direct, result.stdout, result.stderr
            )

    @staticmethod
    def _move_output(output_dir: Path, target_base: Path) -> Optional[Path]:
        """Move nbconvert's output to ``target_base`` plus its extension.

        nbconvert names its output after the staged copy: ``notebook.py`` from the
        python exporter, and from the script exporter ``notebook`` plus the
        notebook's ``file_extension`` (``.r`` for R). The extension is kept, so the
        converted file of an R notebook is ``<name>-converted.r``, as it was when
        nbconvert wrote it there itself.

        Returns:
            The converted file, or None when nbconvert did not write exactly one.
        """
        written = [
            entry
            for entry in output_dir.iterdir()
            if (entry.name == _STAGED_NAME or entry.name.startswith(f"{_STAGED_NAME}."))
            and entry.is_file()
            and not entry.is_symlink()
        ]
        if len(written) != 1:
            return None
        (produced,) = written
        target = target_base.with_name(
            target_base.name + produced.name[len(_STAGED_NAME) :]
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        # Created fresh and never through a link: anything already at the name is
        # removed, and O_EXCL|O_NOFOLLOW refuses whatever appears in its place.
        target.unlink(missing_ok=True)
        fd = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
            0o644,
        )
        with os.fdopen(fd, "wb") as out, produced.open("rb") as source:
            shutil.copyfileobj(source, out)
        return target

    def convert(self) -> List[Path]:
        """Converts Jupyter notebooks (.ipynb files) in the source_dir to Python files using CLI.

        Returns:
            List[Path]: List of converted Python files
        """
        ASH_LOGGER.debug(
            f"Searching for .ipynb files in search_path within the ASH scan set: {self.context.source_dir}"
        )
        # Find all notebook files to scan from the scan set
        ipynb_files = self._notebooks_in_scan_set()

        ASH_LOGGER.debug(f"Found {len(ipynb_files)} .ipynb files in scan set.")
        results: List[Path] = []

        # Add warning if no Jupyter notebook files found
        if not ipynb_files:
            ASH_LOGGER.info(
                f"No Jupyter notebook (.ipynb) files found in {self.context.source_dir}"
            )
            return results

        self.results_dir.mkdir(parents=True, exist_ok=True)

        for ipynb_file in ipynb_files:
            try:
                skip_item = False
                # Skip directories
                if Path(ipynb_file).is_dir():
                    ASH_LOGGER.debug(f"Skipping directory: {ipynb_file}")
                    skip_item = True
                else:
                    for ignore_path in self.context.config.global_settings.ignore_paths:
                        rel_path = (
                            Path(ipynb_file)
                            .relative_to(self.context.source_dir)
                            .as_posix()
                        )
                        if path_matches_pattern(rel_path, ignore_path.path):
                            ASH_LOGGER.debug(
                                f"Skipping conversion of ignored path: {ipynb_file} due to global ignore_path '{ignore_path.path}' with reason '{ignore_path.reason}'"
                            )
                            skip_item = True
                            break
                if skip_item:
                    continue

                ASH_LOGGER.debug(f"Converting {ipynb_file} to .py")
                short_ipynb_file = get_shortest_name(ipynb_file)
                normalized_ipynb_file = get_normalized_filename(short_ipynb_file)
                # The converted file is <name>-converted plus the exporter's extension,
                # .py for a Python notebook; see _move_output.
                filename_base = normalized_ipynb_file.replace(".ipynb", "")
                target_base = self.results_dir.joinpath(f"{filename_base}-converted")

                ASH_LOGGER.verbose(
                    f"Converting {ipynb_file} to target_path: {target_base.as_posix()}"
                )

                # Opened under the scanned-tree rule. nbconvert is given a copy made
                # through this handle, never the original path, so it cannot follow a
                # link that replaced the notebook after the check.
                try:
                    notebook_handle = self.open_source_file(ipynb_file)
                except TreeInputRefused as refused:
                    self.record_refused_input(refused)
                    continue

                # The copy is staged as run/notebook.ipynb, and nbconvert, run in
                # run/, writes into out/. Neither directory is in the tree, and run/
                # holds nothing but the copy.
                with (
                    notebook_handle,
                    tempfile.TemporaryDirectory(prefix="ash-nbconvert-") as staging_dir,
                ):
                    run_dir = Path(staging_dir).joinpath("run")
                    output_dir = Path(staging_dir).joinpath("out")
                    run_dir.mkdir()
                    output_dir.mkdir()
                    staged_notebook = run_dir.joinpath(f"{_STAGED_NAME}.ipynb")
                    exporter = self._stage_notebook(
                        notebook_handle.read(), staged_notebook
                    )
                    self._run_nbconvert(
                        staged_notebook, output_dir, ipynb_file, exporter
                    )
                    converted = self._move_output(output_dir, target_base)

                if converted is None:
                    self.record_failed_input(
                        ipynb_file, "nbconvert exited 0 but wrote no output"
                    )
                    continue
                results.append(converted)
                ASH_LOGGER.debug(f"Successfully converted {ipynb_file} to {converted}")

            # Every failure is recorded, not only logged: the completeness gate reads
            # failed_inputs, and a notebook that was not converted is coverage lost.
            except subprocess.TimeoutExpired as e:
                self.record_failed_input(
                    ipynb_file, f"nbconvert did not finish within {e.timeout}s"
                )
            except subprocess.CalledProcessError as e:
                self.record_failed_input(
                    ipynb_file, f"nbconvert exited with code {e.returncode}"
                )
                if e.stderr:
                    ASH_LOGGER.debug(f"nbconvert stderr: {e.stderr}", extra=NO_MARKUP)
            except Exception as e:
                self.record_failed_input(ipynb_file, f"{type(e).__name__}: {e}")
                import traceback

                ASH_LOGGER.debug(
                    f"Jupyter conversion error traceback: {traceback.format_exc()}"
                )

        return results
