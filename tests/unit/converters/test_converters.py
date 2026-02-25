"""Tests for converter implementations."""

import pytest
from pathlib import Path
import tempfile
import zipfile
import tarfile
import json

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
)


class TestArchiveConverter:
    """Test cases for ArchiveConverter."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdirname:
            yield Path(tmpdirname)

    @pytest.fixture
    def sample_zip_file(self, temp_dir):
        """Create a sample zip file with test content."""
        zip_path = temp_dir / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("test.py", 'print("Hello")')
            zf.writestr(
                "test.unknownext", "This file shouldn't match the member inspectors"
            )
            zf.writestr("subfolder/test2.py", 'print("World")')
        return zip_path

    @pytest.fixture
    def sample_tar_file(self, temp_dir):
        """Create a sample tar file with test content."""
        tar_path = temp_dir / "test.tar"
        with tarfile.open(tar_path, mode="w", encoding="utf-8") as tf:
            # Create temporary files to add to tar
            py_file = temp_dir / "temp.py"
            py_file.write_text('print("Hello")')
            txt_file = temp_dir / "test.unknownext"
            txt_file.write_text("This file shouldn't match the member inspectors")

            tf.add(py_file, arcname="test.py")
            tf.add(txt_file, arcname="test.unknownext")
        return tar_path

    def test_archive_converter_init(self, temp_dir, test_plugin_context):
        """Test ArchiveConverter initialization."""
        config = ArchiveConverterConfig()
        converter = ArchiveConverter(context=test_plugin_context, config=config)
        assert converter.config == config

    def test_archive_converter_validate(self, temp_dir, test_plugin_context):
        """Test validate method."""
        converter = ArchiveConverter(
            context=test_plugin_context,
            config=ArchiveConverterConfig(),
        )
        assert converter.validate_plugin_dependencies() is True

    def test_archive_converter_inspect_members_zip(
        self, temp_dir, sample_zip_file, test_plugin_context
    ):
        """Test inspect_members method with ZIP files."""
        converter = ArchiveConverter(
            context=test_plugin_context,
            config=ArchiveConverterConfig(),
        )
        with zipfile.ZipFile(sample_zip_file, "r") as zf:
            members = converter.inspect_members(zf.filelist)
            assert len(members) == 2  # Should find two .py files
            assert any("test.py" in str(m) for m in members)
            assert any("test2.py" in str(m) for m in members)
            assert not any("test.unknownext" in str(m) for m in members)

    def test_archive_converter_inspect_members_tar(
        self, temp_dir, sample_tar_file, test_plugin_context
    ):
        """Test inspect_members method with TAR files."""
        converter = ArchiveConverter(
            context=test_plugin_context,
            config=ArchiveConverterConfig(),
        )
        with tarfile.open(sample_tar_file, mode="r", encoding="utf-8") as tf:
            members = converter.inspect_members(tf.getmembers())
            assert len(members) == 1  # Should find one .py file
            assert any("test.py" in m.name for m in members)
            assert not any("test.unknownext" in m.name for m in members)

    def test_archive_converter_convert_zip(
        self, temp_dir, sample_zip_file, test_plugin_context, monkeypatch
    ):
        """Test convert method with ZIP files."""

        # Mock scan_set to return our sample zip file
        def mock_scan_set(*args, **kwargs):
            return [str(sample_zip_file)]

        # Apply the monkeypatch
        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter.scan_set",
            mock_scan_set,
        )

        converter = ArchiveConverter(
            context=test_plugin_context,
            config=ArchiveConverterConfig(),
        )
        results = converter.convert()
        assert len(results) == 1
        extracted_dir = results[0]
        assert extracted_dir.exists()
        assert (extracted_dir / "test.py").exists()
        assert (extracted_dir / "subfolder" / "test2.py").exists()
        assert not (extracted_dir / "test.txt").exists()

    def test_archive_converter_convert_tar(
        self, temp_dir, sample_tar_file, test_plugin_context, monkeypatch
    ):
        """Test convert method with TAR files."""

        # Mock scan_set to return our sample tar file
        def mock_scan_set(*args, **kwargs):
            return [str(sample_tar_file)]

        # Apply the monkeypatch
        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter.scan_set",
            mock_scan_set,
        )

        converter = ArchiveConverter(
            context=test_plugin_context,
            config=ArchiveConverterConfig(),
        )
        results = converter.convert()
        assert len(results) == 1
        extracted_dir = results[0]
        assert extracted_dir.exists()
        assert (extracted_dir / "test.py").exists()
        assert not (extracted_dir / "test.txt").exists()


class TestArchiveConverterPathTraversal:
    """Security tests for path traversal prevention in ArchiveConverter."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdirname:
            yield Path(tmpdirname)

    @pytest.fixture
    def converter(self, test_plugin_context):
        """Create an ArchiveConverter instance for testing."""
        return ArchiveConverter(
            context=test_plugin_context,
            config=ArchiveConverterConfig(),
        )

    def test_is_path_traversal_detects_dotdot(self, temp_dir):
        """Test that ../sequences are detected as path traversal."""
        target = temp_dir / "extract"
        target.mkdir()
        assert ArchiveConverter._is_path_traversal("../../etc/passwd", target) is True

    def test_is_path_traversal_detects_absolute_path(self, temp_dir):
        """Test that absolute paths are detected as path traversal."""
        target = temp_dir / "extract"
        target.mkdir()
        assert ArchiveConverter._is_path_traversal("/etc/passwd", target) is True

    def test_is_path_traversal_allows_safe_paths(self, temp_dir):
        """Test that normal relative paths are allowed."""
        target = temp_dir / "extract"
        target.mkdir()
        assert ArchiveConverter._is_path_traversal("safe/file.py", target) is False
        assert ArchiveConverter._is_path_traversal("file.py", target) is False
        assert ArchiveConverter._is_path_traversal("a/b/c/file.py", target) is False

    def test_is_path_traversal_detects_deep_traversal(self, temp_dir):
        """Test that deeply nested traversal sequences are detected."""
        target = temp_dir / "extract"
        target.mkdir()
        deep_traversal = "a/b/../../../../../../../../etc/shadow"
        assert ArchiveConverter._is_path_traversal(deep_traversal, target) is True

    def test_inspect_members_rejects_tar_traversal(self, temp_dir, converter):
        """Test that inspect_members rejects tar members with path traversal."""
        target = temp_dir / "extract"
        target.mkdir()

        # Create a tar with a path traversal member
        tar_path = temp_dir / "malicious.tar"
        with tarfile.open(tar_path, mode="w") as tf:
            # Add a safe file
            safe_file = temp_dir / "safe.py"
            safe_file.write_text('print("safe")')
            tf.add(safe_file, arcname="safe.py")

            # Add a malicious file with path traversal
            malicious_file = temp_dir / "malicious.py"
            malicious_file.write_text('print("malicious")')
            tf.add(malicious_file, arcname="../../../../../../tmp/malicious.py")

        with tarfile.open(tar_path, mode="r") as tf:
            members = converter.inspect_members(tf.getmembers(), target_path=target)
            # Only the safe file should remain
            assert len(members) == 1
            assert members[0].name == "safe.py"

    def test_inspect_members_rejects_zip_traversal(self, temp_dir, converter):
        """Test that inspect_members rejects zip members with path traversal."""
        target = temp_dir / "extract"
        target.mkdir()

        # Create a zip with a path traversal member
        zip_path = temp_dir / "malicious.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("safe.py", 'print("safe")')
            zf.writestr("../../../../../../tmp/malicious.py", 'print("malicious")')

        with zipfile.ZipFile(zip_path, "r") as zf:
            members = converter.inspect_members(zf.filelist, target_path=target)
            # Only the safe file should remain
            assert len(members) == 1
            assert members[0].filename == "safe.py"

    def test_inspect_members_rejects_tar_symlinks(self, temp_dir, converter):
        """Test that inspect_members rejects symlinks in tar archives."""
        target = temp_dir / "extract"
        target.mkdir()

        tar_path = temp_dir / "symlink.tar"
        with tarfile.open(tar_path, mode="w") as tf:
            # Add a safe file
            safe_file = temp_dir / "safe.py"
            safe_file.write_text('print("safe")')
            tf.add(safe_file, arcname="safe.py")

            # Add a symlink member
            link_info = tarfile.TarInfo(name="link.py")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "/etc/passwd"
            tf.addfile(link_info)

        with tarfile.open(tar_path, mode="r") as tf:
            members = converter.inspect_members(tf.getmembers(), target_path=target)
            assert len(members) == 1
            assert members[0].name == "safe.py"

    def test_inspect_members_rejects_tar_hardlinks(self, temp_dir, converter):
        """Test that inspect_members rejects hard links in tar archives."""
        target = temp_dir / "extract"
        target.mkdir()

        tar_path = temp_dir / "hardlink.tar"
        with tarfile.open(tar_path, mode="w") as tf:
            # Add a safe file
            safe_file = temp_dir / "safe.py"
            safe_file.write_text('print("safe")')
            tf.add(safe_file, arcname="safe.py")

            # Add a hard link member
            link_info = tarfile.TarInfo(name="hardlink.py")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "/etc/shadow"
            tf.addfile(link_info)

        with tarfile.open(tar_path, mode="r") as tf:
            members = converter.inspect_members(tf.getmembers(), target_path=target)
            assert len(members) == 1
            assert members[0].name == "safe.py"

    def test_convert_tar_with_traversal_does_not_write_outside(
        self, temp_dir, test_plugin_context, monkeypatch
    ):
        """End-to-end test: a malicious tar should not write files outside target dir."""
        # Create a malicious tar file with path traversal
        tar_path = temp_dir / "source-code.tar"
        with tarfile.open(tar_path, mode="w") as tf:
            safe_file = temp_dir / "safe.py"
            safe_file.write_text('print("safe")')
            tf.add(safe_file, arcname="safe.py")

            # This should be blocked by path traversal protection
            malicious_file = temp_dir / "evil.py"
            malicious_file.write_text('import os; os.system("whoami")')
            tf.add(malicious_file, arcname="../../../../../../tmp/evil.py")

        def mock_scan_set(*args, **kwargs):
            return [str(tar_path)]

        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter.scan_set",
            mock_scan_set,
        )

        converter = ArchiveConverter(
            context=test_plugin_context,
            config=ArchiveConverterConfig(),
        )
        results = converter.convert()
        assert len(results) == 1
        extracted_dir = results[0]

        # The safe file should be extracted
        assert (extracted_dir / "safe.py").exists()

        # The malicious file should NOT exist at the traversal path
        assert not Path("/tmp/evil.py").exists()

    def test_convert_zip_with_traversal_does_not_write_outside(
        self, temp_dir, test_plugin_context, monkeypatch
    ):
        """End-to-end test: a malicious zip should not write files outside target dir."""
        # Create a malicious zip file with path traversal
        zip_path = temp_dir / "source-code.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("safe.py", 'print("safe")')
            zf.writestr("../../../../../../tmp/evil.py", 'import os; os.system("whoami")')

        def mock_scan_set(*args, **kwargs):
            return [str(zip_path)]

        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter.scan_set",
            mock_scan_set,
        )

        converter = ArchiveConverter(
            context=test_plugin_context,
            config=ArchiveConverterConfig(),
        )
        results = converter.convert()
        assert len(results) == 1
        extracted_dir = results[0]

        # The safe file should be extracted
        assert (extracted_dir / "safe.py").exists()

        # The malicious file should NOT exist at the traversal path
        assert not Path("/tmp/evil.py").exists()

    def test_inspect_members_without_target_path_backward_compat(
        self, temp_dir, converter
    ):
        """Test that inspect_members works without target_path for backward compatibility."""
        tar_path = temp_dir / "test.tar"
        with tarfile.open(tar_path, mode="w") as tf:
            safe_file = temp_dir / "safe.py"
            safe_file.write_text('print("safe")')
            tf.add(safe_file, arcname="safe.py")

        with tarfile.open(tar_path, mode="r") as tf:
            # Call without target_path - should still filter by extension
            members = converter.inspect_members(tf.getmembers())
            assert len(members) == 1
            assert members[0].name == "safe.py"


class TestJupyterConverter:
    """Test cases for JupyterConverter."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdirname:
            yield Path(tmpdirname)

    @pytest.fixture
    def sample_notebook(self, temp_dir):
        """Create a sample Jupyter notebook."""
        # Create a simple notebook structure manually
        notebook_content = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": None,
                    "metadata": {},
                    "outputs": [],
                    "source": ['print("Hello World")'],
                }
            ],
            "metadata": {
                "kernelspec": {
                    "display_name": "Python 3",
                    "language": "python",
                    "name": "python3",
                },
                "language_info": {"name": "python", "version": "3.8.0"},
            },
            "nbformat": 4,
            "nbformat_minor": 4,
        }

        notebook_path = temp_dir / "test.ipynb"
        with open(notebook_path, mode="w", encoding="utf-8") as f:
            json.dump(notebook_content, f, indent=2)
        return notebook_path

    def test_jupyter_converter_init(self, test_plugin_context):
        """Test JupyterConverter initialization."""
        config = JupyterConverterConfig()
        converter = JupyterConverter(
            context=test_plugin_context,
            config=config,
        )
        assert converter.config == config

    def test_jupyter_converter_validate(self, test_plugin_context):
        """Test validate method."""
        converter = JupyterConverter(
            context=test_plugin_context,
            config=JupyterConverterConfig(),
        )
        assert converter.validate_plugin_dependencies() is True

    def test_jupyter_converter_convert(
        self, test_plugin_context, sample_notebook, monkeypatch
    ):
        """Test convert method."""
        from unittest.mock import Mock

        # Mock scan_set to return our sample notebook
        def mock_scan_set(*args, **kwargs):
            return [str(sample_notebook)]

        # Mock subprocess.run to simulate successful nbconvert execution
        def mock_subprocess_run(*args, **kwargs):
            # Create the expected output file
            if len(args) > 0 and isinstance(args[0], list) and "nbconvert" in args[0]:
                # Extract output path from command
                cmd = args[0]
                if "--output" in cmd:
                    output_idx = cmd.index("--output") + 1
                    if output_idx < len(cmd):
                        output_path = Path(cmd[output_idx] + ".py")
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        output_path.write_text(
                            '#!/usr/bin/env python\n# coding: utf-8\n\nprint("Hello World")\n'
                        )

            # Return successful result
            result = Mock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            return result

        # Apply the monkeypatches
        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter.scan_set",
            mock_scan_set,
        )
        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter.subprocess.run",
            mock_subprocess_run,
        )

        converter = JupyterConverter(
            context=test_plugin_context,
            config=JupyterConverterConfig(),
        )

        # Mock the validate method to return True (skip UV tool validation for test)
        monkeypatch.setattr(converter, "validate", lambda: True)
        monkeypatch.setattr(
            converter, "use_uv_tool", False
        )  # Use direct execution for test

        results = converter.convert()
        assert len(results) == 1
        converted_file = results[0]
        assert converted_file.exists()
        assert converted_file.suffix == ".py"

        # Check content
        content = converted_file.read_text()
        assert 'print("Hello World")' in content
