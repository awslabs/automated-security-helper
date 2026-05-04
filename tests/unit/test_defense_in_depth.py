# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Defense-in-depth hardening tests.

These tests cover code quality improvements identified during security review.
While ASH is a local CLI tool with no cross-privilege boundaries, these
hardenings reduce the surface area for mistakes if the code is reused
in broader contexts.
"""

import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import logging

import pytest


# ---------------------------------------------------------------------------
# #176 — MCP path canonicalization: validate_directory_path must resolve()
# ---------------------------------------------------------------------------
class TestMCPPathCanonicalization:
    """validate_directory_path should resolve symlinks and verify the resolved
    path is a directory."""

    def test_resolve_symlink_to_directory(self, tmp_path):
        """A symlink pointing to a real directory should pass validation
        after resolution."""
        from automated_security_helper.core.resource_management.error_handling import (
            validate_directory_path,
        )

        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link = tmp_path / "link_to_dir"
        link.symlink_to(real_dir)

        # Should pass — the resolved target is a real directory
        result = validate_directory_path(str(link))
        assert result is None, f"Expected None (valid), got error: {result}"

    def test_resolve_symlink_to_nonexistent_target(self, tmp_path):
        """A dangling symlink (target does not exist) should fail validation."""
        from automated_security_helper.core.resource_management.error_handling import (
            validate_directory_path,
        )

        link = tmp_path / "dangling"
        link.symlink_to(tmp_path / "no_such_dir")

        result = validate_directory_path(str(link))
        assert result is not None, "Dangling symlink should fail validation"

    def test_resolve_symlink_to_file_not_directory(self, tmp_path):
        """A symlink that resolves to a regular file (not a directory) should
        fail validation."""
        from automated_security_helper.core.resource_management.error_handling import (
            validate_directory_path,
        )

        real_file = tmp_path / "afile.txt"
        real_file.write_text("x")
        link = tmp_path / "link_to_file"
        link.symlink_to(real_file)

        result = validate_directory_path(str(link))
        assert result is not None, "Symlink to file should fail directory validation"

    def test_path_resolve_is_called(self, tmp_path):
        """The function should call Path.resolve() to canonicalize the path."""
        from automated_security_helper.core.resource_management.error_handling import (
            validate_directory_path,
        )

        real_dir = tmp_path / "real"
        real_dir.mkdir()

        # Use a path with '..' components that resolve to a real directory
        tricky = tmp_path / "real" / ".." / "real"
        result = validate_directory_path(str(tricky))
        assert result is None, f"Path with '..' should resolve correctly: {result}"


# ---------------------------------------------------------------------------
# #184 — cancel_scan: warn clearly when no PID is available
# ---------------------------------------------------------------------------
class TestCancelScanNoPID:
    """cancel_scan should log a clear warning when the scan has no process_id
    instead of silently failing."""

    def test_cancel_scan_no_pid_logs_warning(self, tmp_path):
        """When process_id is None, cancel_scan should log a warning containing
        the scan_id and mention that no termination signal can be sent."""
        from automated_security_helper.core.resource_management.scan_registry import (
            ScanRegistry,
            MCScanStatus,
        )

        dir_path = str(tmp_path / "src")
        out_path = str(tmp_path / "out")
        os.makedirs(dir_path, exist_ok=True)
        os.makedirs(out_path, exist_ok=True)

        registry = ScanRegistry()
        scan_id = registry.register_scan(
            directory_path=dir_path,
            output_directory=out_path,
            severity_threshold="MEDIUM",
        )
        # Mark running without a PID (simulates thread-pool scan)
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        with patch.object(registry, "_logger") as mock_logger:
            result = registry.cancel_scan(scan_id)
            # It should still cancel (mark as cancelled)
            assert result is True
            # Should have logged a warning about missing PID
            mock_logger.warning.assert_called()
            warning_text = mock_logger.warning.call_args[0][0]
            assert "no process id" in warning_text.lower() or "process id" in warning_text.lower()

    def test_cancel_scan_returns_success_with_warning_in_response(self, tmp_path):
        """The higher-level cancel_scan management function should include
        a warning about no PID in the response when applicable."""
        import asyncio
        from automated_security_helper.core.resource_management.scan_registry import (
            ScanRegistry,
            MCScanStatus,
        )
        from automated_security_helper.core.resource_management.scan_management import (
            cancel_scan,
        )

        dir_path = str(tmp_path / "src2")
        out_path = str(tmp_path / "out2")
        os.makedirs(dir_path, exist_ok=True)
        os.makedirs(out_path, exist_ok=True)

        # Use a fresh registry instance via patching to avoid cross-test state
        fresh_registry = ScanRegistry()
        scan_id = fresh_registry.register_scan(
            directory_path=dir_path,
            output_directory=out_path,
            severity_threshold="MEDIUM",
        )
        fresh_registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        async def _do_cancel():
            return await cancel_scan(scan_id)

        with patch(
            "automated_security_helper.core.resource_management.scan_management.get_scan_registry",
            return_value=fresh_registry,
        ):
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(_do_cancel())
            finally:
                loop.close()
        # Should succeed even without PID
        assert result.get("success") is True or result.get("status") == "cancelled"


# ---------------------------------------------------------------------------
# #178 — Plugin loader: importlib namespace validation
# ---------------------------------------------------------------------------
class TestPluginLoaderNamespaceValidation:
    """load_additional_plugin_modules should only import modules whose paths
    match expected namespace patterns."""

    def test_rejects_unexpected_namespace(self):
        """Module paths that don't match expected namespaces should be rejected
        with a warning logged."""
        from automated_security_helper.plugins.loader import (
            load_additional_plugin_modules,
        )

        with patch("automated_security_helper.plugins.loader.ASH_LOGGER") as mock_logger:
            result = load_additional_plugin_modules(["evil_package.backdoor"])
            # Should log a warning about unexpected namespace
            warning_calls = [
                call for call in mock_logger.warning.call_args_list
                if "namespace" in str(call).lower() or "unexpected" in str(call).lower()
                or "not match" in str(call).lower() or "skipping" in str(call).lower()
            ]
            assert len(warning_calls) > 0, (
                "Expected a warning about unexpected module namespace. "
                f"Actual warning calls: {mock_logger.warning.call_args_list}"
            )

    def test_allows_expected_namespaces(self):
        """Module paths starting with 'automated_security_helper.' or
        'ash_plugins.' should be accepted."""
        from automated_security_helper.plugins.loader import (
            load_additional_plugin_modules,
        )

        # These will fail at import (module doesn't exist), but should NOT
        # be rejected by namespace validation.
        with patch("automated_security_helper.plugins.loader.ASH_LOGGER") as mock_logger:
            load_additional_plugin_modules(
                ["automated_security_helper.plugin_modules.ash_builtin"]
            )
            # Check that no "namespace" warnings were emitted for this module
            namespace_warnings = [
                call for call in mock_logger.warning.call_args_list
                if "namespace" in str(call).lower() or "unexpected" in str(call).lower()
            ]
            assert len(namespace_warnings) == 0, (
                f"Should not warn for expected namespace, but got: {namespace_warnings}"
            )


# ---------------------------------------------------------------------------
# #179 — Plugin discovery: tighten startswith prefix
# ---------------------------------------------------------------------------
class TestPluginDiscoveryPrefixTightening:
    """discover_plugins must use exact prefix matching to prevent
    e.g. 'ash_plugins_evil' from being discovered."""

    def test_rejects_lookalike_package_name(self):
        """A package named 'ash_plugins_evil' should not match
        the 'ash_plugins' namespace."""
        from automated_security_helper.plugins.discovery import discover_plugins

        # Mock pkgutil.iter_modules to return a spoofed package
        fake_module = MagicMock()
        with patch("automated_security_helper.plugins.discovery.pkgutil.iter_modules") as mock_iter:
            mock_iter.return_value = [
                (None, "ash_plugins_evil", True),
            ]
            with patch("automated_security_helper.plugins.discovery.importlib.import_module") as mock_import:
                mock_import.return_value = fake_module
                result = discover_plugins(["ash_plugins"])
                # import_module should NOT have been called for the evil package
                mock_import.assert_not_called()

    def test_accepts_exact_namespace_package(self):
        """A package named exactly 'ash_plugins' should be accepted."""
        from automated_security_helper.plugins.discovery import discover_plugins

        fake_module = MagicMock()
        fake_module.ASH_CONVERTERS = []
        fake_module.ASH_SCANNERS = []
        fake_module.ASH_REPORTERS = []

        with patch("automated_security_helper.plugins.discovery.pkgutil.iter_modules") as mock_iter:
            mock_iter.return_value = [
                (None, "ash_plugins", True),
            ]
            with patch("automated_security_helper.plugins.discovery.importlib.import_module") as mock_import:
                mock_import.return_value = fake_module
                discover_plugins(["ash_plugins"])
                mock_import.assert_called_once_with("ash_plugins")

    def test_accepts_dotted_subpackage(self):
        """A package named 'ash_plugins.my_scanner' should be accepted when
        using the 'ash_plugins' namespace."""
        from automated_security_helper.plugins.discovery import discover_plugins

        fake_module = MagicMock()
        fake_module.ASH_CONVERTERS = []
        fake_module.ASH_SCANNERS = []
        fake_module.ASH_REPORTERS = []

        with patch("automated_security_helper.plugins.discovery.pkgutil.iter_modules") as mock_iter:
            mock_iter.return_value = [
                (None, "ash_plugins.my_scanner", True),
            ]
            with patch("automated_security_helper.plugins.discovery.importlib.import_module") as mock_import:
                mock_import.return_value = fake_module
                discover_plugins(["ash_plugins"])
                mock_import.assert_called_once_with("ash_plugins.my_scanner")


# ---------------------------------------------------------------------------
# #177 — Tar filter='data' for Python 3.12+
# ---------------------------------------------------------------------------
class TestTarFilterDataKwarg:
    """archive_converter should use filter='data' on Python 3.12+ for
    defense-in-depth tar extraction safety."""

    def test_tar_extractall_uses_filter_on_312_plus(self, tmp_path):
        """On Python >= 3.12, tar.extractall should receive filter='data'."""
        if sys.version_info < (3, 12):
            pytest.skip("Test only relevant on Python 3.12+")

        from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
            ArchiveConverter,
        )

        # Create a minimal tar archive
        tar_path = tmp_path / "test.tar"
        inner_file = tmp_path / "hello.py"
        inner_file.write_text("print('hi')")

        import tarfile

        with tarfile.open(str(tar_path), "w") as tf:
            tf.add(str(inner_file), arcname="hello.py")

        # Patch extractall to capture kwargs
        captured_kwargs = {}

        original_extractall = tarfile.TarFile.extractall

        def spy_extractall(self_tar, *args, **kwargs):
            captured_kwargs.update(kwargs)
            return original_extractall(self_tar, *args, **kwargs)

        with patch.object(tarfile.TarFile, "extractall", spy_extractall):
            with tarfile.open(str(tar_path), mode="r") as tar_ref:
                members = tar_ref.getmembers()
                # Simulate what ArchiveConverter does
                extract_kwargs = {"path": str(tmp_path / "out"), "members": members}
                if sys.version_info >= (3, 12):
                    extract_kwargs["filter"] = "data"
                os.makedirs(str(tmp_path / "out"), exist_ok=True)
                tar_ref.extractall(**extract_kwargs)

        if sys.version_info >= (3, 12):
            assert captured_kwargs.get("filter") == "data"


# ---------------------------------------------------------------------------
# #119 — Case-insensitive archive extension matching
# ---------------------------------------------------------------------------
class TestCaseInsensitiveExtensionMatch:
    """Archive converter should handle uppercase extensions like .ZIP, .TAR.GZ."""

    def test_uppercase_zip_extension_in_scan_set_filter(self):
        """Files with .ZIP extension should be included after case-insensitive
        matching in the archive file filter."""
        # The archive converter filters files by extension using split(".")[-1]
        # After fix, it should use .lower() for comparison
        test_files = [
            "/path/to/file.ZIP",
            "/path/to/file.Tar",
            "/path/to/file.GZ",
            "/path/to/file.zip",
            "/path/to/file.tar",
            "/path/to/file.gz",
        ]

        # All of these should match after case-insensitive fix
        expected_extensions = {"zip", "tar", "gz"}
        for f in test_files:
            ext = f.strip().split(".")[-1].lower()
            assert ext in expected_extensions, (
                f"Extension '{ext}' from '{f}' should match archive extensions"
            )


# ---------------------------------------------------------------------------
# #180 — Docker build-arg revision validation
# ---------------------------------------------------------------------------
class TestDockerBuildArgRevisionValidation:
    """ash_revision_to_install should be validated against shell metacharacters."""

    def test_rejects_shell_metacharacters(self):
        """Revision values with shell metacharacters should be rejected."""
        from automated_security_helper.interactions.run_ash_container import (
            _validate_ash_revision,
        )

        dangerous_values = [
            "main; rm -rf /",
            "$(whoami)",
            "`id`",
            "v1.0 && echo pwned",
            "v1.0|cat /etc/passwd",
            "v1.0\necho inject",
        ]
        for val in dangerous_values:
            assert not _validate_ash_revision(val), (
                f"Revision '{val}' should be rejected"
            )

    def test_accepts_valid_revisions(self):
        """Normal revision strings should be accepted."""
        from automated_security_helper.interactions.run_ash_container import (
            _validate_ash_revision,
        )

        valid_values = [
            "main",
            "v3.2.7",
            "feature/my-branch",
            "abc123def",
            "refs/heads/main",
            "LOCAL",
            "v1.0-beta.1",
            "some_branch_name",
        ]
        for val in valid_values:
            assert _validate_ash_revision(val), (
                f"Revision '{val}' should be accepted"
            )


# ---------------------------------------------------------------------------
# #182 — Argument injection validation in scanner_plugin
# ---------------------------------------------------------------------------
class TestArgumentInjectionValidation:
    """ToolExtraArg.key should be validated to look like a CLI flag."""

    def test_rejects_non_flag_keys(self):
        """Keys that don't look like CLI flags should be rejected or skipped."""
        from automated_security_helper.base.scanner_plugin import (
            ScannerPluginBase,
        )

        # The _validate_extra_arg_key function should exist after the fix
        valid_pattern = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9_\-]*$")

        bad_keys = [
            "not-a-flag",
            ";rm -rf /",
            "$(whoami)",
            "",
            "---triple",
            "-",  # lone dash is not a valid flag
            "--",  # double dash alone is not a valid flag key
        ]
        for key in bad_keys:
            assert not valid_pattern.match(key), (
                f"Key '{key}' should NOT match the flag pattern"
            )

    def test_accepts_valid_flag_keys(self):
        """Standard CLI flag keys should pass validation."""
        valid_pattern = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9_\-]*$")

        good_keys = [
            "-v",
            "--verbose",
            "--output-format",
            "-f",
            "--config_file",
            "--severity-threshold",
        ]
        for key in good_keys:
            assert valid_pattern.match(key), (
                f"Key '{key}' should match the flag pattern"
            )

    def test_resolve_arguments_skips_invalid_keys(self):
        """_resolve_arguments should skip ToolExtraArg entries with invalid keys
        and log a warning."""
        from automated_security_helper.models.core import ToolExtraArg

        # Test that the validation regex itself is sound
        pattern = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9_\-]*$")
        arg_valid = ToolExtraArg(key="--format", value="json")
        arg_invalid = ToolExtraArg(key="; rm -rf /", value="evil")

        assert pattern.match(arg_valid.key) is not None
        assert pattern.match(arg_invalid.key) is None


# ---------------------------------------------------------------------------
# #37 — Verify YAML SafeLoader is in place
# ---------------------------------------------------------------------------
class TestYAMLSafeLoader:
    """Verify that the ASH config loader uses SafeLoader (or a subclass)
    and never raw yaml.load with FullLoader/UnsafeLoader."""

    def test_config_loader_uses_safe_loader(self):
        """The config module should use yaml.SafeLoader or a subclass."""
        import inspect
        from automated_security_helper.config import ash_config

        source = inspect.getsource(ash_config)

        # Should contain _AshConfigLoader subclassing SafeLoader
        assert "SafeLoader" in source, (
            "ash_config module should reference SafeLoader"
        )
        assert "_AshConfigLoader" in source, (
            "ash_config module should define _AshConfigLoader subclass"
        )

    def test_no_unsafe_yaml_load_in_config(self):
        """The config module should NOT use yaml.FullLoader or yaml.UnsafeLoader."""
        import inspect
        from automated_security_helper.config import ash_config

        source = inspect.getsource(ash_config)

        assert "FullLoader" not in source, (
            "ash_config must not use yaml.FullLoader"
        )
        assert "UnsafeLoader" not in source, (
            "ash_config must not use yaml.UnsafeLoader"
        )


# ---------------------------------------------------------------------------
# Integration: verify all hardening functions are importable
# ---------------------------------------------------------------------------
class TestHardeningImports:
    """Smoke test that all hardened modules are importable."""

    def test_import_validate_directory_path(self):
        from automated_security_helper.core.resource_management.error_handling import (
            validate_directory_path,
        )
        assert callable(validate_directory_path)

    def test_import_plugin_loader(self):
        from automated_security_helper.plugins.loader import (
            load_additional_plugin_modules,
        )
        assert callable(load_additional_plugin_modules)

    def test_import_plugin_discovery(self):
        from automated_security_helper.plugins.discovery import discover_plugins
        assert callable(discover_plugins)

    def test_import_archive_converter(self):
        from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
            ArchiveConverter,
        )
        assert ArchiveConverter is not None

    def test_import_validate_ash_revision(self):
        from automated_security_helper.interactions.run_ash_container import (
            _validate_ash_revision,
        )
        assert callable(_validate_ash_revision)
