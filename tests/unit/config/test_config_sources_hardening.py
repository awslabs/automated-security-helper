# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Failure paths of config discovery and `extends` that must not be silent.

Each test pins a case where the first implementation either fell back to the
default config without saying so, let an unrelated pyproject.toml break a
working config, or let a base outside the repository be read.
"""

import os
import textwrap
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

DEFAULT_PROJECT_NAME = AshConfig().project_name


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


class TestMalformedDirectivesFailClosed:
    """These raised exception types resolve_config's catch-all turned into defaults."""

    @pytest.mark.parametrize(
        "patch_yaml",
        [
            "[{op: [add], path: /project_name, value: x}]",
            "[{op: {a: b}, path: /project_name, value: x}]",
            "[{op: replace, path: '/global_settings/ignore_paths/²', value: x}]",
        ],
    )
    def test_malformed_patch_raises(self, tmp_path, patch_yaml):
        _write(
            tmp_path / ".ash.yaml",
            "project_name: marker\nglobal_settings:\n  ignore_paths: []\n"
            f"patch: {patch_yaml}\n",
        )
        with pytest.raises(ASHConfigValidationError):
            resolve_config(source_dir=tmp_path)

    def test_nul_in_extends_raises(self, tmp_path):
        _write(tmp_path / ".ash.yaml", 'project_name: marker\nextends: "a\\0b.yaml"\n')
        with pytest.raises(ASHConfigValidationError, match="NUL"):
            resolve_config(source_dir=tmp_path)


class TestUnrelatedPyprojectCannotBreakAWorkingConfig:
    def test_non_utf8_pyproject_is_ignored_when_a_dedicated_file_exists(self, tmp_path):
        _write(tmp_path / ".ash" / ".ash.yaml", "project_name: marker\n")
        (tmp_path / "pyproject.toml").write_bytes(
            "[project]\nname = 'café'\n".encode("latin-1")
        )
        assert resolve_config(source_dir=tmp_path).project_name == "marker"

    @pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="needs POSIX permissions that root ignores",
    )
    def test_unreadable_pyproject_is_ignored_when_a_dedicated_file_exists(
        self, tmp_path
    ):
        _write(tmp_path / ".ash" / ".ash.yaml", "project_name: marker\n")
        pyproject = _write(tmp_path / "pyproject.toml", '[project]\nname = "x"\n')
        pyproject.chmod(0)
        try:
            assert resolve_config(source_dir=tmp_path).project_name == "marker"
        finally:
            pyproject.chmod(0o644)

    def test_broken_tool_ash_is_ignored_when_a_dedicated_file_exists(self, tmp_path):
        _write(tmp_path / ".ash" / ".ash.yaml", "project_name: marker\n")
        _write(tmp_path / "pyproject.toml", '[tool]\nash = "x"\n')
        assert resolve_config(source_dir=tmp_path).project_name == "marker"

    def test_broken_tool_ash_still_fails_when_it_is_the_only_source(self, tmp_path):
        _write(tmp_path / "pyproject.toml", '[tool]\nash = "x"\n')
        with pytest.raises(ASHConfigValidationError, match="must be a table"):
            resolve_config(source_dir=tmp_path)

    def test_non_utf8_pyproject_declaring_tool_ash_fails_closed(self, tmp_path):
        (tmp_path / "pyproject.toml").write_bytes(
            "[tool.ash]\nproject_name = 'café'\n".encode("latin-1")
        )
        with pytest.raises(ASHConfigValidationError, match="UTF-8"):
            resolve_config(source_dir=tmp_path)

    def test_pyproject_with_a_byte_order_mark_is_read(self, tmp_path):
        (tmp_path / "pyproject.toml").write_bytes(
            b"\xef\xbb\xbf[tool.ash]\nproject_name = 'bom'\n"
        )
        assert resolve_config(source_dir=tmp_path).project_name == "bom"


class TestConfinementDoesNotWidenToTheCwd:
    def test_explicit_config_without_source_dir_is_confined_to_its_project(
        self, tmp_path, monkeypatch
    ):
        # The cwd is an ancestor of both the repo and the target. Before the
        # fix the cwd became the root, so this base was readable.
        _write(tmp_path / "private" / "hosts.yaml", "project_name: leaked\n")
        config = _write(
            tmp_path / "src" / "repo" / ".ash" / ".ash.yaml",
            "extends: ../../../private/hosts.yaml\n",
        )
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ASHConfigValidationError, match="outside the directory"):
            resolve_config(config_path=config)

    def test_failed_test_op_does_not_print_the_value_it_read(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            "project_name: p\nexternal_reports_to_include: [secret-marker-value]\n",
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            patch:
              - {op: test, path: /external_reports_to_include/0, value: guess}
            """,
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=tmp_path)
        assert "secret-marker-value" not in str(excinfo.value)
        assert "does not equal" in str(excinfo.value)

    def test_dotdot_escape_is_refused_before_touching_the_target(self, tmp_path):
        # The escaping path does not exist; the refusal must still name the
        # confinement, not a missing file, so it never got as far as a lookup.
        repo = tmp_path / "repo"
        _write(repo / ".ash.yaml", "extends: ../nowhere/base.yaml\n")
        with pytest.raises(ASHConfigValidationError, match="outside the directory"):
            resolve_config(source_dir=repo)


class TestEveryReaderUsesTheSameDiscovery:
    def test_exit_code_fields_read_an_ashrc_file(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _resolve_config_fail_on_findings,
            _resolve_config_fail_on_incomplete_scanners,
        )

        _write(
            tmp_path / ".ashrc.yaml",
            "project_name: p\nfail_on_findings: false\n"
            "fail_on_incomplete_scanners: false\n",
        )
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_findings(opts) is False
        assert _resolve_config_fail_on_incomplete_scanners(opts) is False

    def test_exit_code_fields_follow_extends(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _resolve_config_fail_on_findings,
        )

        _write(tmp_path / "base.yaml", "project_name: p\nfail_on_findings: false\n")
        _write(tmp_path / "pyproject.toml", '[tool.ash]\nextends = "base.yaml"\n')
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_findings(opts) is False

    def test_workspace_settings_read_pyproject(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _resolve_workspace_execution_config,
        )

        _write(
            tmp_path / "pyproject.toml",
            "[tool.ash]\nproject_name = 'p'\n[tool.ash.workspace]\n"
            "max_parallel_projects = 3\n",
        )
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        assert _resolve_workspace_execution_config(opts).max_parallel_projects == 3


class TestMcpConfigTools:
    def test_get_config_keeps_the_repo_as_the_root_for_a_dot_ash_file(self, tmp_path):
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        _write(tmp_path / "shared" / "base.yaml", "project_name: shared-base\n")
        config = _write(
            tmp_path / ".ash" / ".ash.yaml", "extends: ../shared/base.yaml\n"
        )
        assert mcp_get_config(config_path=str(config))["project_name"] == "shared-base"
        assert mcp_get_config(search_dir=str(tmp_path))["project_name"] == "shared-base"

    def test_get_config_raw_reads_the_tool_ash_table(self, tmp_path):
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        _write(
            tmp_path / "pyproject.toml",
            '[project]\nname = "x"\n[tool.ash]\nproject_name = "raw-table"\n',
        )
        raw = mcp_get_config(search_dir=str(tmp_path), raw=True)
        assert raw == {"project_name": "raw-table"}

    def test_validate_content_cannot_extend_files_beside_it(self, tmp_path):
        import tempfile

        from automated_security_helper.cli.mcp_tools import mcp_validate_config

        # A file a client did not send, in the shared temp directory.
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", dir=tempfile.gettempdir(), delete=False
        ) as other:
            other.write("project_name: not-sent-by-the-client\n")
        try:
            result = mcp_validate_config(
                config_content=f"project_name: p\nextends: ../{Path(other.name).name}\n"
            )
            assert result["valid"] is False
            messages = " ".join(e["message"] for e in result["errors"])
            assert "extends" in messages
            result = mcp_validate_config(
                config_content=f"project_name: p\nextends: {Path(other.name).name}\n"
            )
            assert result["valid"] is False
        finally:
            Path(other.name).unlink(missing_ok=True)


class TestACallersOwnReaderNeedsItsTextCache:
    """A caller's own reader returns parsed data, so the resolution's only
    as-written view of each file is the ``texts`` cache the reader fills. A
    call without one used to resolve the environment's values into the data
    while recording no reference at all, so nothing downstream redacted them.
    """

    def test_a_readers_call_without_texts_is_a_type_error(self, tmp_path, monkeypatch):
        from automated_security_helper.config.config_sources import (
            parse_config_text,
            read_config_text,
            resolve_config_document,
        )

        monkeypatch.setenv("ASH_HARDENING_READER_VAR", "reader-held-value-7731")
        config = _write(
            tmp_path / "ash.yaml", "project_name: ${ASH_HARDENING_READER_VAR}\n"
        )

        def reader(path: Path):
            return parse_config_text(Path(path), read_config_text(Path(path)))

        with pytest.raises(TypeError, match="texts"):
            resolve_config_document(config, reader=reader, texts=None)

    def test_a_reader_with_its_cache_records_what_the_chain_read(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.config.config_sources import (
            parse_config_text,
            read_config_text,
            resolve_config_document,
        )

        monkeypatch.setenv("ASH_HARDENING_READER_VAR", "reader-held-value-7731")
        config = _write(
            tmp_path / "ash.yaml", "project_name: ${ASH_HARDENING_READER_VAR}\n"
        )
        texts: dict = {}

        def reader(path: Path):
            text = read_config_text(Path(path))
            texts[Path(path).resolve()] = text
            return parse_config_text(Path(path), text)

        document = resolve_config_document(config, reader=reader, texts=texts)
        assert document.data == {"project_name": "reader-held-value-7731"}
        assert document.environment_values == ["reader-held-value-7731"]
        assert [r.written for r in document.environment_references] == [
            "${ASH_HARDENING_READER_VAR}"
        ]

    def test_the_literal_reader_still_needs_no_cache(self, tmp_path):
        from automated_security_helper.config.config_sources import (
            read_config_file_literally,
            resolve_config_document,
        )

        config = _write(tmp_path / "ash.yaml", "project_name: plain\n")
        document = resolve_config_document(
            config, reader=read_config_file_literally, texts=None
        )
        assert document.data == {"project_name": "plain"}
        assert document.environment_references == []

    def test_a_texts_mapping_the_reader_never_fills_is_refused(
        self, tmp_path, monkeypatch
    ):
        """Passing an empty mapping satisfied the call-time check while the
        reader filled nothing, so the environment's value was resolved into
        the data with no reference recorded. The read of the unfilled file is
        refused instead."""
        from automated_security_helper.config.config_sources import (
            parse_config_text,
            read_config_text,
            resolve_config_document,
        )

        monkeypatch.setenv("ASH_HARDENING_READER_VAR", "reader-held-value-7731")
        config = _write(
            tmp_path / "ash.yaml", "project_name: ${ASH_HARDENING_READER_VAR}\n"
        )

        def reader(path: Path):
            return parse_config_text(Path(path), read_config_text(Path(path)))

        with pytest.raises(TypeError, match="no held text"):
            resolve_config_document(config, reader=reader, texts={})

    def test_a_reader_filling_only_the_top_file_is_refused_at_the_base(
        self, tmp_path, monkeypatch
    ):
        """A fill of the first file alone left every base of the chain without
        an as-written view, so a base's environment read went unrecorded. The
        base's refusal reaches the caller through the chain's own error
        (``_resolve`` wraps what following ``extends`` raises), with the
        constant no-held-text reason and no value in it."""
        from automated_security_helper.config.config_sources import (
            parse_config_text,
            read_config_text,
            resolve_config_document,
        )
        from automated_security_helper.core.exceptions import ASHConfigSourceError

        monkeypatch.setenv("ASH_HARDENING_READER_VAR", "reader-held-value-7731")
        base = _write(
            tmp_path / "base.yaml", "project_name: ${ASH_HARDENING_READER_VAR}\n"
        )
        top = _write(tmp_path / "ash.yaml", f"extends: {base.name}\n")
        texts: dict = {}
        filled: list = []

        def reader(path: Path):
            text = read_config_text(Path(path))
            if not filled:
                texts[Path(path).resolve()] = text
                filled.append(Path(path).resolve())
            return parse_config_text(Path(path), text)

        with pytest.raises(ASHConfigSourceError, match="no held text") as refused:
            resolve_config_document(top, reader=reader, texts=texts)
        assert filled == [top.resolve()], filled
        assert "reader-held-value-7731" not in str(refused.value), str(refused.value)

    def test_an_env_named_base_left_unfilled_keeps_the_no_held_text_reason(
        self, tmp_path, monkeypatch
    ):
        """The same top-only fill, with the base named through the environment:
        the chain read from it, so the refusal took the environment-blind path,
        whose generic text points at the file system ("missing, cannot be
        read") when the cause is the caller's reader. The no-held-text refusal
        holds no value by construction, so it is kept as it is."""
        from automated_security_helper.config.config_sources import (
            parse_config_text,
            read_config_text,
            resolve_config_document,
        )
        from automated_security_helper.core.exceptions import ASHConfigSourceError
        from automated_security_helper.utils.error_text import _chain

        hidden = "reader-named-base-7731"
        monkeypatch.setenv("ASH_HARDENING_BASE_VAR", f"{hidden}.yaml")
        _write(tmp_path / f"{hidden}.yaml", "project_name: from-the-base\n")
        top = _write(tmp_path / "ash.yaml", "extends: ${ASH_HARDENING_BASE_VAR}\n")
        texts: dict = {}
        filled: list = []

        def reader(path: Path):
            text = read_config_text(Path(path))
            if not filled:
                texts[Path(path).resolve()] = text
                filled.append(Path(path).resolve())
            return parse_config_text(Path(path), text)

        with pytest.raises(ASHConfigSourceError) as refused:
            resolve_config_document(top, reader=reader, texts=texts)
        assert filled == [top.resolve()], filled
        assert "no held text" in str(refused.value), str(refused.value)
        members = list(_chain(refused.value))
        text = "\n".join(f"{member!s}\n{member!r}" for member in members)
        assert hidden not in text, text[:2000]

    def test_the_no_held_text_refusal_names_no_private_class(
        self, tmp_path, monkeypatch
    ):
        """The refusal names the builtin TypeError and the public source-error
        class, never a private class that marks a refusal internally, on every
        surface that prints it: its text, and each chain-walking printer (repr
        of each member, traceback_text, traceback.format_exception). Through
        the chain's catch-all (an unfilled base, whose kept refusal is the
        document-quoting one) and through resolve_config's own fallback (an
        unheld top file)."""
        import traceback

        from automated_security_helper.utils.error_text import _chain, traceback_text
        from automated_security_helper.config.config_sources import (
            parse_config_text,
            read_config_text,
            resolve_config_document,
        )
        from automated_security_helper.config.resolve_config import resolve_config
        from automated_security_helper.core.exceptions import (
            ASHConfigSourceError,
            ASHConfigValidationError,
        )

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        base = _write(tmp_path / "base.yaml", "project_name: from-the-base\n")
        top = _write(tmp_path / "ash.yaml", f"extends: {base.name}\n")
        texts: dict = {}

        def top_only(path: Path):
            text = read_config_text(Path(path))
            if Path(path).resolve() == top.resolve():
                texts[top.resolve()] = text
            return parse_config_text(Path(path), text)

        with pytest.raises(ASHConfigSourceError) as through_the_chain:
            resolve_config_document(top, reader=top_only, texts=texts)
        shown = str(through_the_chain.value)
        assert "no held text" in shown, shown
        assert "_UnheldTextError" not in shown, shown
        assert "TypeError: config_sources._file_references" in shown, shown
        # The kept document-quoting refusal is the public class itself, marked
        # by attribute. Pinned by exact type and repr prefix, not by one
        # private name's absence, which nothing could print once the name
        # left the code: a future private subclass under any name changes
        # both, where the old check knew only the one spelling.
        assert type(through_the_chain.value) is ASHConfigSourceError, type(
            through_the_chain.value
        )
        assert repr(through_the_chain.value).startswith("ASHConfigSourceError("), repr(
            through_the_chain.value
        )

        lone = _write(tmp_path / "lone" / "ash.yaml", "project_name: t\n")
        reads = {lone.resolve(): parse_config_text(lone, read_config_text(lone))}
        with pytest.raises(ASHConfigValidationError) as through_the_fallback:
            resolve_config(
                config_path=lone,
                source_dir=lone.parent,
                reads=reads,
                fallback_to_default=True,
            )
        shown = str(through_the_fallback.value)
        assert "no held text" in shown, shown
        assert "_UnheldTextError" not in shown, shown
        assert "TypeError: config_sources._file_references" in shown, shown

        for refused in (through_the_chain.value, through_the_fallback.value):
            unheld = [
                member
                for member in _chain(refused)
                if str(member).startswith("config_sources._file_references")
            ]
            assert len(unheld) == 1, [type(m).__name__ for m in _chain(refused)]
            assert type(unheld[0]) is TypeError, type(unheld[0])
            for printed in (
                repr(unheld[0]),
                repr(refused),
                traceback_text(refused),
                "".join(
                    traceback.format_exception(
                        type(refused), refused, refused.__traceback__
                    )
                ),
            ):
                assert "_UnheldTextError" not in printed, printed[-2000:]
                assert "TypeError" in printed, printed[-2000:]

    def test_a_run_load_reads_cache_missing_a_bases_text_keeps_the_reason(
        self, tmp_path, monkeypatch
    ):
        """A run load handed a ``reads`` cache that holds a base but no text
        for it never reads that base, so its text is never held. After the top
        file read the environment, the refusal used to take the environment-
        blind path, whose generic text blames a missing or unreadable file in
        the operator's config for what is the caller's cache. It keeps the
        constant no-held-text reason, and names no value."""
        from automated_security_helper.config.config_sources import (
            parse_config_text,
            read_config_text,
        )
        from automated_security_helper.config.resolve_config import (
            load_config_file_for_run,
        )
        from automated_security_helper.core.exceptions import ASHConfigSourceError
        from automated_security_helper.utils.error_text import _chain

        value = "run-load-top-value-7731"
        monkeypatch.setenv("ASH_HARDENING_TOP_VAR", value)
        base = _write(tmp_path / "base.yaml", "fail_on_findings: false\n")
        top = _write(
            tmp_path / "ash.yaml",
            f"project_name: ${{ASH_HARDENING_TOP_VAR}}\nextends: {base.name}\n",
        )
        reads = {base.resolve(): parse_config_text(base, read_config_text(base))}
        with pytest.raises(ASHConfigSourceError) as refused:
            load_config_file_for_run(top, reads=reads)
        shown = str(refused.value)
        assert "no held text" in shown, shown
        assert "missing, cannot be read" not in shown, shown
        text = "\n".join(f"{m!s}\n{m!r}" for m in _chain(refused.value))
        assert value not in text, text[:2000]

    def test_a_readers_own_type_error_still_takes_the_blind_path(
        self, tmp_path, monkeypatch
    ):
        """Only the no-held-text refusal, whose text is a constant, is kept as
        it is. A caller's reader raising a plain TypeError that quotes a value,
        for an env-named base, is still replaced by the environment-blind
        reason: its text is the reader's, and can hold anything."""
        from automated_security_helper.config.config_sources import (
            parse_config_text,
            read_config_text,
            resolve_config_document,
        )
        from automated_security_helper.core.exceptions import ASHConfigSourceError
        from automated_security_helper.utils.error_text import _chain

        hidden = "reader-named-base-7731"
        value = "reader-quoted-value-7731"
        monkeypatch.setenv("ASH_HARDENING_BASE_VAR", f"{hidden}.yaml")
        _write(tmp_path / f"{hidden}.yaml", "project_name: from-the-base\n")
        top = _write(tmp_path / "ash.yaml", "extends: ${ASH_HARDENING_BASE_VAR}\n")
        texts: dict = {}

        def reader(path: Path):
            text = read_config_text(Path(path))
            if Path(path).resolve() == top.resolve():
                texts[top.resolve()] = text
                return parse_config_text(Path(path), text)
            raise TypeError(f"reader refused a file holding {value}")

        with pytest.raises(ASHConfigSourceError) as refused:
            resolve_config_document(top, reader=reader, texts=texts)
        members = list(_chain(refused.value))
        text = "\n".join(f"{member!s}\n{member!r}" for member in members)
        assert value not in text, text[:2000]
        assert hidden not in text, text[:2000]
        assert not any(type(m) is TypeError for m in members), [
            type(m).__name__ for m in members
        ]

    def test_a_run_load_reads_cache_without_texts_is_refused(
        self, tmp_path, monkeypatch
    ):
        """A pre-seeded ``reads`` cache without its matching ``texts`` is a
        cache hit the reader never reads, so the file's text is never held and
        its environment reads went unrecorded; the control with both caches
        records them."""
        from automated_security_helper.config.config_sources import (
            parse_config_text,
            read_config_text,
        )
        from automated_security_helper.config.resolve_config import (
            load_config_file_for_run,
        )

        monkeypatch.setenv("ASH_HARDENING_READER_VAR", "reader-held-value-7731")
        config = _write(
            tmp_path / "ash.yaml", "project_name: ${ASH_HARDENING_READER_VAR}\n"
        )
        key = config.resolve()
        text = read_config_text(config)
        parsed = parse_config_text(config, text)
        with pytest.raises(TypeError, match="no held text"):
            load_config_file_for_run(config, reads={key: dict(parsed)})
        _, built = load_config_file_for_run(
            config, reads={key: dict(parsed)}, texts={key: text}
        )
        assert built._environment_values == ["reader-held-value-7731"]

    def test_a_cached_read_whose_text_is_not_the_files_is_refused_as_changed(
        self, tmp_path
    ):
        """The cached read of a file is read again, held to the identity the walk
        vetted, and used only when the cache's text is what the file holds. A cache
        that holds the text, and a file that says something else, is a changed
        file; a cache with no text at all is the no-held-text refusal above. The
        two stay apart: one says the file changed, the other names the caller's
        cache."""
        from automated_security_helper.config.config_sources import (
            ConfigFileChangedError,
            parse_config_text,
            read_config_text,
        )
        from automated_security_helper.config.resolve_config import (
            load_config_file_for_run,
        )

        config = _write(tmp_path / "ash.yaml", "project_name: as-first-read\n")
        key = config.resolve()
        text = read_config_text(config)
        parsed = parse_config_text(config, text)
        config.write_text("project_name: rewritten-since\n", encoding="utf-8")
        with pytest.raises(ConfigFileChangedError):
            load_config_file_for_run(
                config, reads={key: dict(parsed)}, texts={key: text}
            )
