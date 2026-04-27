"""Regression tests for ash_config bug fixes.

PR#274 Bug #37: yaml.SafeLoader class mutation -- !ENV constructor leaks globally.
"""

import textwrap

import pytest
import yaml


class TestYamlSafeLoaderNotMutated:
    """After loading an ASH config via from_file(), the global yaml.SafeLoader
    must NOT carry the !ENV constructor.  A local subclass should be used."""

    def test_safeloader_lacks_env_constructor_after_config_load(self, tmp_path):
        """Loading an ASH YAML config must not register !ENV on the global SafeLoader."""
        # Record the constructors before
        before_constructors = dict(yaml.SafeLoader.yaml_constructors)

        config_file = tmp_path / "ash.yml"
        config_file.write_text(
            textwrap.dedent("""\
            scanners: []
            """)
        )

        from automated_security_helper.config.ash_config import AshConfig

        try:
            AshConfig.from_file(config_file)
        except Exception:
            # Config validation may fail -- that's fine; we care about the loader.
            pass

        after_constructors = yaml.SafeLoader.yaml_constructors
        assert "!ENV" not in after_constructors, (
            "yaml.SafeLoader was mutated with !ENV constructor"
        )
        # Restore in case something leaked
        yaml.SafeLoader.yaml_constructors = before_constructors
