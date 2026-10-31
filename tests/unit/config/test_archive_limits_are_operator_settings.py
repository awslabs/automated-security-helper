# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The archive converter's extraction limits are the operator's to raise.

``max_members``, ``max_member_bytes``, ``max_total_bytes`` and
``max_compression_ratio`` bound what extracting an archive in the scanned tree can
write. A config file the scanned repository wrote (``.ash/.ash.yaml`` in the tree, or
a project's config in workspace mode) and a config an MCP client delivered cannot
raise them above the trusted base: the defaults, ``ASH_CONFIG``'s file, or the
operator's default config in workspace mode. The trusted value is kept, and the
ignored setting is named in a warning, as #784 does for the sandbox grants and
plugin modules such a file sets. An operator config outside the tree and
``--config-overrides`` set the limits as before. A runtime override an MCP client
sends is refused for them by the shipped denylist, even where the operator allows
``/converters/**``.

Each conversion test resolves the config the way the scan does, builds the archive
converter from it the way ConvertPhase does, and converts one archive that the
trusted limits refuse and the raised ones would let through.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_patch,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.config._client_policy_helpers import narrow_client_rules
from tests.utils.archive_builders import (
    LIMIT_OPTIONS,
    MEBIBYTE,
    TEBIBYTE,
    incompressible,
    zip_bytes,
)

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)

#: Above everything ``declared.zip`` declares: one member of 1 TiB in an archive of
#: about 150 bytes, a ratio near 7e9.
RAISED = {
    "max_members": 100_000_000,
    "max_member_bytes": 2 * TEBIBYTE,
    "max_total_bytes": 4 * TEBIBYTE,
    "max_compression_ratio": 1_000_000_000_000,
}


def options_yaml(options: dict, project_name: str = "scanned") -> str:
    lines = "".join(f"      {name}: {value}\n" for name, value in options.items())
    return (
        f"project_name: {project_name}\nconverters:\n  archive:\n    options:\n{lines}"
    )


# One case per limit: (option, the trusted base's value, the larger value the untrusted
# config sets, an archive over the first and under the second). Each archive is small
# in the other three dimensions, so no default for them refuses it.
LIMIT_CASES = [
    pytest.param(
        "max_members",
        2,
        1000,
        {f"m{i}.py": incompressible(16, seed=i) for i in range(3)},
        id="max_members",
    ),
    pytest.param(
        "max_member_bytes",
        1000,
        1_000_000,
        {"large.py": incompressible(2000)},
        id="max_member_bytes",
    ),
    pytest.param(
        "max_total_bytes",
        3000,
        1_000_000,
        {"a.py": incompressible(2000, seed=1), "b.py": incompressible(2000, seed=2)},
        id="max_total_bytes",
    ),
    pytest.param(
        "max_compression_ratio",
        50,
        1_000_000,
        {"zeros.py": bytes(MEBIBYTE)},
        id="max_compression_ratio",
    ),
]

# The same cases without the archive: for the checks that end at the config's
# refusal and convert nothing.
LIMIT_VALUE_CASES = [pytest.param(*case.values[:3], id=case.id) for case in LIMIT_CASES]


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A scanned tree, a directory outside it for operator files, and no ASH_CONFIG."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    tree = tmp_path / "repo"
    (tree / ".ash").mkdir(parents=True)
    outside = tmp_path / "operator"
    outside.mkdir()
    monkeypatch.chdir(tree)
    return tree, outside


def declared_archive(tree: Path) -> Path:
    """A zip whose one member declares 1 TiB; no default limit lets it through."""
    archive = tree / "declared.zip"
    archive.write_bytes(
        zip_bytes(
            {"declared.py": "print('declared large')\n"},
            declared_sizes={"declared.py": TEBIBYTE},
        )
    )
    return archive


def convert_with(config: AshConfig, tree: Path, archive: Path, monkeypatch):
    """Run the archive converter over ``archive`` the way ConvertPhase builds it."""
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    work = tree.parent / "work"
    context = PluginContext(
        source_dir=tree,
        output_dir=work / "out",
        work_dir=work / "converted",
        config=config,
    )
    converter = ArchiveConverter(
        context=context,
        config=config.get_plugin_config(plugin_type="converter", plugin_name="archive"),
    )
    return converter, converter.convert()


def assert_refused(converter, results, archive: Path, option: str | None = None):
    assert results == [], f"{archive.name} was extracted under the untrusted limits"
    refusals = [r for r in converter.refused_inputs if r.path == archive.name]
    assert len(refusals) == 1, converter.refused_inputs
    if option is not None:
        assert option in refusals[0].reason, refusals[0]


def warnings_text(records) -> List[str]:
    return [r.getMessage() for r in records if r.levelno == logging.WARNING]


class TestRepositoryConfig:
    def test_a_repository_config_cannot_raise_the_limits_above_the_defaults(
        self, layout, monkeypatch
    ):
        tree, _ = layout
        (tree / ".ash" / ".ash.yaml").write_text(options_yaml(RAISED))
        archive = declared_archive(tree)

        config = resolve_config(source_dir=tree)
        converter, results = convert_with(config, tree, archive, monkeypatch)

        assert_refused(converter, results, archive)

    def test_each_limit_a_repository_config_tries_to_raise_is_named_in_a_warning(
        self, layout, ash_log
    ):
        tree, _ = layout
        (tree / ".ash" / ".ash.yaml").write_text(options_yaml(RAISED))

        resolve_config(source_dir=tree)

        warnings = warnings_text(ash_log)
        unnamed = [
            name for name in LIMIT_OPTIONS if not any(name in w for w in warnings)
        ]
        assert unnamed == [], f"no warning names {unnamed}; warnings: {warnings}"

    @pytest.mark.parametrize("option, trusted, raised, members", LIMIT_CASES)
    def test_a_repository_config_cannot_raise_a_limit_above_ash_config(
        self, option, trusted, raised, members, layout, monkeypatch
    ):
        tree, outside = layout
        operator = outside / "ash.yaml"
        operator.write_text(options_yaml({option: trusted}, project_name="operator"))
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        (tree / ".ash" / ".ash.yaml").write_text(options_yaml({option: raised}))
        archive = tree / "a.zip"
        archive.write_bytes(zip_bytes(members))

        config = resolve_config(source_dir=tree)
        converter, results = convert_with(config, tree, archive, monkeypatch)

        assert config.project_name == "scanned", "the repository config was not used"
        assert_refused(converter, results, archive, option)

    @pytest.mark.parametrize("empty", ["null", "0", "-1"])
    @pytest.mark.parametrize("option, trusted, raised, members", LIMIT_CASES)
    def test_a_repository_config_cannot_lift_a_limit_with_an_empty_value(
        self, option, trusted, raised, members, empty, layout, monkeypatch
    ):
        """A null, zero or negative limit is not "no limit" when the repository sets it.

        Refusing the config file is as good as keeping the trusted limit; what must
        not happen is the archive being extracted.
        """
        tree, outside = layout
        operator = outside / "ash.yaml"
        operator.write_text(options_yaml({option: trusted}, project_name="operator"))
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        (tree / ".ash" / ".ash.yaml").write_text(options_yaml({option: empty}))
        archive = tree / "a.zip"
        archive.write_bytes(zip_bytes(members))

        try:
            config = resolve_config(source_dir=tree)
        except ASHConfigValidationError as refused_config:
            assert option in str(refused_config), refused_config
            return
        converter, results = convert_with(config, tree, archive, monkeypatch)

        assert_refused(converter, results, archive, option)

    def test_a_repository_config_cannot_raise_a_limit_with_a_hyphenated_key(
        self, layout, monkeypatch
    ):
        tree, outside = layout
        operator = outside / "ash.yaml"
        operator.write_text(
            options_yaml({"max_member_bytes": 1000}, project_name="operator")
        )
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        (tree / ".ash" / ".ash.yaml").write_text(
            options_yaml({"max-member-bytes": 1_000_000})
        )
        archive = tree / "a.zip"
        archive.write_bytes(zip_bytes({"large.py": incompressible(2000)}))

        config = resolve_config(source_dir=tree)
        converter, results = convert_with(config, tree, archive, monkeypatch)

        assert_refused(converter, results, archive, "max_member_bytes")

    def test_config_overrides_set_a_limit_over_a_repository_config(
        self, layout, monkeypatch
    ):
        """--config-overrides is the operator's, whatever the repository config says."""
        tree, _ = layout
        (tree / ".ash" / ".ash.yaml").write_text(options_yaml({"max_members": 1000}))
        archive = tree / "a.zip"
        archive.write_bytes(zip_bytes({f"m{i}.py": f"N = {i}\n" for i in range(3)}))

        config = resolve_config(
            source_dir=tree,
            config_overrides=["converters.archive.options.max_members=2"],
        )
        converter, results = convert_with(config, tree, archive, monkeypatch)

        assert_refused(converter, results, archive, "max_members")

    def test_positive_control_an_operator_config_outside_the_tree_can_raise_the_limits(
        self, layout, monkeypatch
    ):
        tree, outside = layout
        operator = outside / "ash.yaml"
        operator.write_text(options_yaml(RAISED, project_name="operator"))
        (tree / ".ash" / ".ash.yaml").write_text("project_name: scanned\n")
        archive = declared_archive(tree)

        config = resolve_config(config_path=operator, source_dir=tree)
        converter, results = convert_with(config, tree, archive, monkeypatch)

        assert config.project_name == "operator"
        (extracted,) = results
        assert (extracted / "declared.py").read_text() == "print('declared large')\n"
        assert converter.refused_inputs == []

    def test_positive_control_the_repository_config_is_read(self, layout, monkeypatch):
        tree, _ = layout
        (tree / ".ash" / ".ash.yaml").write_text(options_yaml({"max_members": 1000}))
        archive = tree / "a.zip"
        archive.write_bytes(zip_bytes({"ok.py": "print('ok')\n"}))

        config = resolve_config(source_dir=tree)
        converter, results = convert_with(config, tree, archive, monkeypatch)

        assert config.project_name == "scanned"
        (extracted,) = results
        assert (extracted / "ok.py").read_text() == "print('ok')\n"


class TestClientSuppliedConfig:
    """A config an MCP client uploaded is resolved with ``untrusted_config``.

    The extraction limits are in the denied_paths every policy holds
    (ALWAYS_DENIED_PATHS), so an upload that sets one is refused, naming it,
    rather than resolved with the trusted value (client_config_policy). Each
    refusal is checked under the shipped default ``denied_paths`` and under a
    policy whose operator profile replaces that list with one that leaves the
    limits out (``narrow_client_rules``): the refusal does not rest on the
    default list.
    """

    @pytest.mark.parametrize("policy", ["default", "narrowed"])
    def test_an_uploaded_config_cannot_raise_the_limits_above_the_defaults(
        self, layout, policy
    ):
        from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

        tree, outside = layout
        upload = outside / "uploaded.yaml"
        upload.write_text(options_yaml(RAISED, project_name="uploaded"))

        with pytest.raises(ASHConfigFieldDeniedError) as refused:
            resolve_config(
                config_path=upload,
                source_dir=tree,
                scanned_root=tree,
                untrusted_config=True,
                **_client_policy(policy),
            )
        for option in RAISED:
            assert option in str(refused.value), refused.value

    @pytest.mark.parametrize("policy", ["default", "narrowed"])
    @pytest.mark.parametrize("option, trusted, raised", LIMIT_VALUE_CASES)
    def test_an_uploaded_config_cannot_raise_a_limit_above_ash_config(
        self, option, trusted, raised, policy, layout, monkeypatch
    ):
        from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

        tree, outside = layout
        operator = outside / "ash.yaml"
        operator.write_text(options_yaml({option: trusted}, project_name="operator"))
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        upload = outside / "uploaded.yaml"
        upload.write_text(options_yaml({option: raised}, project_name="uploaded"))

        with pytest.raises(ASHConfigFieldDeniedError, match=option):
            resolve_config(
                config_path=upload,
                source_dir=tree,
                scanned_root=tree,
                untrusted_config=True,
                **_client_policy(policy),
            )


def _client_policy(policy: str) -> dict:
    """The ``resolve_config`` keyword for a parametrized client policy."""
    if policy == "default":
        return {}
    return {"client_config_policy": narrow_client_rules()}


class TestWorkspaceProjectConfig:
    @pytest.mark.parametrize("option, trusted, raised, members", LIMIT_CASES)
    def test_a_project_config_cannot_raise_a_limit_above_the_operator_default_config(
        self, option, trusted, raised, members, tmp_path, monkeypatch
    ):
        """Resolved as workspace/execution.py resolves a project's own config."""
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        workspace = tmp_path / "workspace"
        project = workspace / "services" / "api"
        (project / ".ash").mkdir(parents=True)
        project_config = project / ".ash" / ".ash.yaml"
        project_config.write_text(options_yaml({option: raised}))
        operator = tmp_path / "operator" / "default.yaml"
        operator.parent.mkdir()
        operator.write_text(options_yaml({option: trusted}, project_name="operator"))
        archive = project / "a.zip"
        archive.write_bytes(zip_bytes(members))

        config = resolve_config(
            config_path=project_config,
            source_dir=project,
            fallback_to_default=True,
            config_overrides=[],
            scanned_root=workspace,
            trusted_config_path=operator,
        )
        converter, results = convert_with(config, project, archive, monkeypatch)

        assert config.project_name == "scanned"
        assert_refused(converter, results, archive, option)


class TestRuntimeOverrides:
    """The shipped denylist refuses a client's runtime override of a limit."""

    @staticmethod
    def allowlist() -> RuntimeOverridesConfig:
        return RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/converters/**"],
            denied_paths=list(
                AshConfig().global_settings.mcp.runtime_overrides.denied_paths
            ),
        )

    @staticmethod
    def raised_converters() -> dict:
        converters = AshConfig().converters.model_dump(mode="json", by_alias=True)
        converters["archive"]["options"].update(RAISED)
        return converters

    @pytest.mark.parametrize(
        "pointer",
        [f"/converters/archive/options/{name}" for name in LIMIT_OPTIONS]
        + ["/converters/archive/options/max-member-bytes"],
    )
    def test_a_runtime_override_cannot_set_a_limit(self, pointer):
        value = RAISED[pointer.rsplit("/", 1)[-1].replace("-", "_")]
        ops = [{"op": "add", "path": pointer, "value": value}]

        try:
            result = apply_runtime_patch(AshConfig(), ops, allowlist=self.allowlist())
        except RuntimePatchDeniedError:
            return
        pytest.fail(
            f"the override of {pointer} was applied: "
            f"{result.converters.archive.options!r}"
        )

    @pytest.mark.parametrize(
        "pointer", ["/converters/archive/options", "/converters/archive", "/converters"]
    )
    def test_a_runtime_override_of_a_section_holding_the_limits_is_refused(
        self, pointer
    ):
        converters = self.raised_converters()
        value = {
            "/converters/archive/options": converters["archive"]["options"],
            "/converters/archive": converters["archive"],
            "/converters": converters,
        }[pointer]
        ops = [{"op": "replace", "path": pointer, "value": value}]

        try:
            result = apply_runtime_patch(AshConfig(), ops, allowlist=self.allowlist())
        except RuntimePatchDeniedError:
            return
        pytest.fail(
            f"the override of {pointer} was applied: "
            f"{result.converters.archive.options!r}"
        )

    def test_positive_control_another_converter_setting_is_still_overridable(self):
        ops = [{"op": "replace", "path": "/converters/jupyter/enabled", "value": False}]

        result = apply_runtime_patch(AshConfig(), ops, allowlist=self.allowlist())

        assert result.converters.jupyter.enabled is False
