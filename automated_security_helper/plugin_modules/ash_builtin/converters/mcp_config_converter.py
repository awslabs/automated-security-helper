# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the McpConfigConverter implementation.

Turns each command-declaring server entry of a repo-local MCP config file
(``.mcp.json``, ``.cursor/mcp.json``, ``.codex/config.toml`` and the other formats
listed in ``utils/mcp_config/readers.py``) into one shell script, so the script
scanners that already run over the converted tree (semgrep, opengrep) read the
command a config would launch — whether or not the entry also spells a url. Each
script has a ``.spanmap.json`` sidecar beside it that maps every script line back
to the entry's place in the config file.

The converter only writes text. It never executes, resolves or fetches anything a
config names, and it starts no process.
"""

from pathlib import Path
from typing import Annotated, Any, Dict, List, Literal, Set

from pydantic import Field

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.models.core import ignore_paths_that_skip_scanning
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import (
    honors_ignore_files,
    scan_set,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.mcp_config import (
    McpConfigParseError,
    McpServerEntry,
    detect_format,
    parse_mcp_config_text,
)
from automated_security_helper.utils.mcp_config.emit import (
    emit_script,
    sidecar_text,
    slug,
    source_slug,
)
from automated_security_helper.utils.mcp_config.readers import MAX_CONFIG_BYTES
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.scan_output_dirs import record_converted_sources
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    relative_display,
)
from automated_security_helper.utils.suppression_matcher import (
    active_ignore_paths,
    ignore_path_matches,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line

#: The suffix of the file a script's span rows are written to, beside the script.
SPANMAP_SUFFIX = ".spanmap.json"


class McpConfigConverterConfigOptions(ConverterOptionsBase):
    """The MCP config converter has no options of its own."""


class McpConfigConverterConfig(ConverterPluginConfigBase):
    """MCP server config (.mcp.json and similar) to shell script converter configuration."""

    name: Literal["mcp_config"] = "mcp_config"
    enabled: bool = True
    options: Annotated[
        McpConfigConverterConfigOptions,
        Field(description="Configure MCP server config converter"),
    ] = McpConfigConverterConfigOptions()


@ash_converter_plugin
class McpConfigConverter(ConverterPluginBase[McpConfigConverterConfig]):
    """Converter implementation for repo-local MCP server config files."""

    display_name = "MCP config"
    docs_summary = (
        "turns each stdio server in a repo-local MCP config file into a shell "
        "script, with a sidecar that maps script lines back to the config"
    )

    def model_post_init(self, context: Any) -> None:
        # Without a config, ConverterPluginBase would give a nameless one, and the
        # work directory would be named for the class rather than the converter.
        if self.config is None:
            self.config = McpConfigConverterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        # Entirely Python: there is no tool to check for.
        return True

    def _skipped(self, path: str) -> bool:
        """Whether ``path`` is under an ignore path that keeps it out of conversion."""
        ignore_paths = ignore_paths_that_skip_scanning(
            active_ignore_paths(self.context.config.global_settings.ignore_paths),
            ignore_suppressions=self.context.ignore_suppressions,
        )
        if not ignore_paths:
            return False
        try:
            rel_path = Path(path).relative_to(self.context.source_dir).as_posix()
        except ValueError:
            return False
        for ignore_path in ignore_paths:
            if ignore_path_matches(rel_path, ignore_path.path):
                ASH_LOGGER.debug(
                    shown_on_one_line(
                        f"Skipping conversion of ignored path: {path} due to global "
                        f"ignore_path '{ignore_path.path}'"
                    ),
                    extra=NO_MARKUP,
                )
                return True
        return False

    def _read_entries(self, path: str, display: str) -> List[McpServerEntry]:
        """The server entries of one config file, or [] after recording why not."""
        try:
            with self.open_source_file(path) as handle:
                data = handle.read(MAX_CONFIG_BYTES + 1)
        except TreeInputRefused as refused:
            self.record_refused_input(refused)
            return []
        except OSError:
            self.record_failed_input(path, "the file could not be read", kind="input")
            return []
        if len(data) > MAX_CONFIG_BYTES:
            self.record_failed_input(path, "the file is too large", kind="input")
            return []
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            self.record_failed_input(path, "the file is not UTF-8", kind="input")
            return []
        try:
            return parse_mcp_config_text(text, display)
        except McpConfigParseError as error:
            where = f" at line {error.line}, column {error.col}" if error.line else ""
            # The reason names a position and never quotes the file.
            self.record_failed_input(path, f"{error.reason}{where}", kind="input")
            return []

    def convert(self) -> List[Path]:
        """Write one script and one sidecar per command-declaring entry of each config.

        Returns:
            List[Path]: The scripts written, sorted by path.
        """
        ASH_LOGGER.debug(
            f"Searching for MCP config files in the ASH scan set: {self.context.source_dir}"
        )
        workspace_output_dir = getattr(self.context, "workspace_output_dir", None)
        candidates = scan_set(
            source=self.context.source_dir,
            output=self.context.output_dir,
            honor_ignore_files=honors_ignore_files(self.context.config),
            run_id=getattr(self.context, "run_id", None),
            workspace_output_dir=(
                None if workspace_output_dir is None else str(workspace_output_dir)
            ),
        )
        targets: Dict[str, str] = {}
        for path in candidates:
            display = relative_display(path, self.context.source_dir)
            if detect_format(display) is None:
                continue
            try:
                if self._skipped(path):
                    continue
            except (OSError, ValueError):
                continue
            targets[display] = path

        results: List[Path] = []
        if not targets:
            ASH_LOGGER.info(f"No MCP config files found in {self.context.source_dir}")
            return results

        sources: Dict[Path, str] = {}
        taken_directories: Set[str] = set()
        # Sorted, so the same tree always gets the same names.
        for display in sorted(targets):
            entries = self._read_entries(targets[display], display)
            # Every entry that declares a command, never the classed kind: an
            # entry spelling both a command and a url is classed remote, and a
            # kind gate would let one decoy url key keep its command out of the
            # scripts the script scanners read.
            with_command = [entry for entry in entries if entry.command]
            if not with_command:
                continue
            directory = self.results_dir / source_slug(display, taken_directories)
            taken_names: Set[str] = set()
            for entry in with_command:
                emitted = emit_script(entry)
                if emitted is None:
                    ASH_LOGGER.debug(
                        shown_on_one_line(
                            f"MCP server '{entry.server_name}' in '{display}' has no "
                            "command; no script written"
                        ),
                        extra=NO_MARKUP,
                    )
                    continue
                script_text, rows = emitted
                directory.mkdir(parents=True, exist_ok=True)
                script_path = directory / f"{slug(entry.server_name, taken_names)}.sh"
                sidecar_path = script_path.with_name(script_path.name + SPANMAP_SUFFIX)
                # newline="": the text already ends each line with a bare LF.
                # open_for_write refuses a link at any component below the output
                # directory, so a planted link cannot redirect the write.
                with open_for_write(script_path, newline="") as handle:
                    handle.write(script_text)
                with open_for_write(sidecar_path, newline="") as handle:
                    handle.write(sidecar_text(rows))
                results.append(script_path)
                sources[script_path] = display
                sources[sidecar_path] = display

        if sources:
            record_converted_sources(self.results_dir, self.context.work_dir, sources)
        return sorted(results)
