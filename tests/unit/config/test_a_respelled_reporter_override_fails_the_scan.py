"""A respelled reporter override is refused on the scan path, not swallowed.

The exact-spelling control: an operator whose own file enables an off-host
reporter can disable it with ``reporters.<section>.enabled=false``, and the
section a reporter reads (``reporter_section``) shows it off. A respelling of
that section must be refused with the keys-only message, as ``config get``
already refuses it; a resolution that catches the refusal and logs a warning
leaves the off-host reporter enabled while the run reports success.

The fold onto the trusted base exists for one case: the repository's in-tree
config spells a section one way, the operator's file another, and the scan's
own apply already made the operator type the repository's spelling. The cells
below pin that it stays that one case: a respelling of a section only the
trusted base holds is refused, the rewrite never crosses the off-host line,
and the replay's own log lines name no value a section key read from the
environment.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ASHRespelledOverrideError,
)
from tests.utils.helpers import mark_git_checkout


def _scan_resolution(tmp_path, override):
    """resolve_config as a scan calls it: an in-tree repository config without
    the off-host section, and the operator's own file outside the tree that
    enables it."""
    from automated_security_helper.config.operator_only_options import reporter_section
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(
        "project_name: repo\n", encoding="utf-8"
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n",
        encoding="utf-8",
    )
    config = resolve_config(
        source_dir=checkout, trusted_config_path=operator, config_overrides=[override]
    )
    section = reporter_section(config, SecurityHubReporter)
    return section.get("enabled") if isinstance(section, dict) else section.enabled


def test_control_the_exact_operator_disable_reaches_the_offhost_section(tmp_path):
    assert (
        _scan_resolution(tmp_path, "reporters.aws-security-hub.enabled=false") is False
    )


@pytest.mark.parametrize(
    "spelling", ["AwsSecurityHub", "AWS-SECURITY-HUB", "awssecurityhub"]
)
def test_a_respelled_operator_disable_is_refused_or_reaches_the_section(
    tmp_path, spelling
):
    """The respelled disable is refused (so the scan exits with the keys-only
    message), or it reaches the section; silently keeping enabled=true is the
    one outcome that must not happen."""
    try:
        enabled = _scan_resolution(tmp_path, f"reporters.{spelling}.enabled=false")
    except ASHConfigValidationError:
        return
    assert enabled is False, (
        f"the off-host reporter stays enabled={enabled!r} and the run goes on"
    )


def _scan_resolution_with_repo_spelling(tmp_path, override):
    """The lockout shape: the repository's in-tree config spells the section
    one way, the operator's own file another, and the repository controls its
    own spelling. The override is applied twice -- to the resolved
    configuration, then replayed onto the trusted base for the off-host
    section -- and each application sees the other file's spelling."""
    from automated_security_helper.config.operator_only_options import reporter_section
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(
        "project_name: repo\nreporters:\n  AwsSecurityHub:\n    enabled: true\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n",
        encoding="utf-8",
    )
    config = resolve_config(
        source_dir=checkout, trusted_config_path=operator, config_overrides=[override]
    )
    section = reporter_section(config, SecurityHubReporter)
    return section.get("enabled") if isinstance(section, dict) else section.enabled


def test_the_resolved_configs_spelling_reaches_the_offhost_section(tmp_path):
    """The spelling the scan's own apply demands (the repository's) is the one
    the operator is told to use, so the trusted replay takes it too, folded
    onto the trusted base's own section: otherwise no spelling passes both
    applications, and the repository can force that on any operator."""
    enabled = _scan_resolution_with_repo_spelling(
        tmp_path, "reporters.AwsSecurityHub.enabled=false"
    )
    assert enabled is False, enabled


def test_the_operators_own_spelling_is_refused_naming_both_keys(tmp_path):
    """The first application refuses the operator's spelling against the
    repository's existing section, and its message holds the operator's own
    key as well as the one to use, so one retype resolves it."""
    with pytest.raises(ASHConfigValidationError) as refused:
        _scan_resolution_with_repo_spelling(
            tmp_path, "reporters.aws-security-hub.enabled=false"
        )
    message = str(refused.value)
    assert "reporters.aws-security-hub" in message, message
    assert "reporters.AwsSecurityHub" in message, message


def test_a_section_matching_neither_base_still_lands_as_written(tmp_path):
    """The documented leniency survives: a section that is no spelling of any
    existing one lands as written on both applications, and the off-host
    reporter keeps the operator's own setting."""
    enabled = _scan_resolution_with_repo_spelling(
        tmp_path, "reporters.brand-new-reporter.enabled=false"
    )
    assert enabled is True, enabled


def _resolution(tmp_path, repo_text, operator_text, override):
    """resolve_config as a scan calls it, with the repository's in-tree config
    and the operator's file both chosen by the cell."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(repo_text, encoding="utf-8")
    operator = tmp_path / "operator.yaml"
    operator.write_text(operator_text, encoding="utf-8")
    return resolve_config(
        source_dir=checkout, trusted_config_path=operator, config_overrides=[override]
    )


class _Lines(logging.Handler):
    """Every line the ash logger emits while a cell resolves."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _capturing():
    logger = logging.getLogger("ash")
    handler = _Lines()
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    def restore():
        logger.removeHandler(handler)
        logger.setLevel(old_level)

    return handler, restore


def test_a_respelling_of_a_trusted_only_section_is_refused(tmp_path):
    """The repository holds no reporters section, so the scan's own apply never
    made the operator use this spelling: there is no lockout to resolve, and
    the replay refuses the respelling as the docstring says it does. Folding
    it instead would let anyone typing near a trusted section's name reach
    it."""
    with pytest.raises(ASHConfigValidationError):
        _resolution(
            tmp_path,
            "project_name: repo\n",
            "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n",
            "reporters.AwsSecurityHub.enabled=false",
        )


def test_the_replays_applied_line_names_no_env_read_key(tmp_path, monkeypatch):
    """The operator's section key is read from the environment. The lockout
    fold rewrites the override onto that key, and the replay's own debug line
    then holds the variable's value; it has to print the key redacted, as the
    refusals already do."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    value = "Aws_Security-HUB"
    monkeypatch.setenv("ASH_RESPELL_OP_NAME", value)
    operator_text = (
        "project_name: op\nreporters:\n  ${ASH_RESPELL_OP_NAME}:\n    enabled: true\n"
    )
    # The must-fire control: the key really is read from the environment.
    control = tmp_path / "control" / "env.yaml"
    control.parent.mkdir()
    control.write_text(operator_text, encoding="utf-8")
    assert value in (load_config_file_for_run(control)[1].reporters.model_extra or {})

    handler, restore = _capturing()
    try:
        _resolution(
            tmp_path,
            "project_name: repo\nreporters:\n  AwsSecurityHub:\n    enabled: true\n",
            operator_text,
            "reporters.AwsSecurityHub.enabled=false",
        )
    finally:
        restore()
    applied = [
        m
        for m in handler.messages
        if m.startswith(("Applied a config override", "Appended to"))
    ]
    assert applied, handler.messages[-10:]
    leaked = [m for m in applied if value in m]
    assert not leaked, leaked


def test_the_replays_appended_line_names_no_env_read_key(tmp_path, monkeypatch):
    """The append path logs its own line ("Appended to the list at ..."), and
    the fold rewrites an append override's section segment onto the trusted
    base's env-read key the same way, so that line has to print the key
    redacted too. Both applications append -- the repository's section and the
    trusted base's are lists -- which is the must-fire control."""
    value = "Aws_Security-HUB"
    monkeypatch.setenv("ASH_RESPELL_LIST_NAME", value)
    handler, restore = _capturing()
    try:
        _resolution(
            tmp_path,
            "project_name: repo\nreporters:\n  AwsSecurityHub: []\n",
            "project_name: op\nreporters:\n  ${ASH_RESPELL_LIST_NAME}: []\n",
            "reporters.AwsSecurityHub+=x",
        )
    finally:
        restore()
    appended = [m for m in handler.messages if m.startswith("Appended to the list at")]
    assert len(appended) >= 2, handler.messages[-10:]
    leaked = [m for m in appended if value in m]
    assert not leaked, leaked


def test_the_drop_warnings_text_names_no_env_read_key(tmp_path, monkeypatch):
    """A replay failure other than a respelling is dropped with one warning
    that quotes the error, and the error can quote a section key the trusted
    file read from the environment (the fold rewrote an override onto it), so
    the warning's text has to be redacted with that file's values."""
    from automated_security_helper.config.resolve_config import (
        _with_reporter_overrides,
        apply_config_overrides,
        load_config_file_for_run,
    )

    value = "Aws_Security-HUB"
    monkeypatch.setenv("ASH_RESPELL_DROP_NAME", value)
    trusted_path = tmp_path / "drop-trusted.yaml"
    trusted_path.write_text(
        "project_name: op\nreporters:\n  ${ASH_RESPELL_DROP_NAME}:\n    enabled: true\n",
        encoding="utf-8",
    )
    trusted = load_config_file_for_run(trusted_path)[1]
    assert value in (trusted.reporters.model_extra or {})
    repo_path = tmp_path / "drop-repo.yaml"
    repo_path.write_text(REPO_ONE, encoding="utf-8")
    resolved = apply_config_overrides(
        load_config_file_for_run(repo_path)[1], ["project_name=stamped"]
    )
    handler, restore = _capturing()
    try:
        _with_reporter_overrides(
            trusted,
            ["reporters.AwsSecurityHub.enabled=false", "reporters.sarif.enabled=maybe"],
            resolved,
        )
    finally:
        restore()
    warned = [m for m in handler.messages if "do not apply to the operator" in m]
    assert warned, handler.messages[-5:]
    assert not [m for m in warned if value in m], warned
    # The fold did rewrite the first override onto the env-read key: the
    # redaction, not a missing rewrite, is what keeps the value out.
    applied = [m for m in handler.messages if m.startswith("Applied a config override")]
    assert applied, handler.messages[-5:]


def test_over_redaction_of_a_key_word_is_the_accepted_cost(tmp_path, monkeypatch):
    """The redaction is by value, so a hand-typed key word that equals a value
    the operator's file read from the environment ("enabled") is blanked in
    the replay's own line too. Pinned as accepted: a blanked word costs less
    than a leaked value, and the first application's line -- redacted with the
    repository file's values, which hold no such word -- still prints the full
    path."""
    from automated_security_helper.config.config_validator import REDACTED

    monkeypatch.setenv("ASH_RESPELL_WORD", "enabled")
    handler, restore = _capturing()
    try:
        _resolution(
            tmp_path,
            REPO_ONE,
            "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n"
            "    options:\n      tag: ${ASH_RESPELL_WORD}\n",
            "reporters.AwsSecurityHub.enabled=false",
        )
    finally:
        restore()
    applied = [m for m in handler.messages if m.startswith("Applied a config override")]
    assert len(applied) >= 2, handler.messages[-10:]
    assert [m for m in applied if m.endswith(".enabled")], applied
    blanked = [m for m in applied if m.endswith(REDACTED) and "enabled" not in m]
    assert blanked, applied


def test_a_built_in_spelling_never_moves_onto_an_off_host_only_section(tmp_path):
    """sarif-re_porter carries a separator inside the type word, so plugin
    lookup reads it as no built-in reporter's section (off-host), while
    SarifReporter is the built-in sarif reporter's own spelling. The two fold
    together, but an override typed for the built-in must not land on the
    operator's off-host section: the resolution refuses it, or the record
    keeps the operator's setting; silently enabling the off-host section is
    the one outcome that must not happen. The repository spells the section
    SarifReporter itself, so this cell isolates the plugin-name bound from
    the repository-holds-the-section bound."""
    try:
        config = _resolution(
            tmp_path,
            "project_name: repo\nreporters:\n  SarifReporter:\n    enabled: true\n",
            "project_name: op\nreporters:\n  sarif-re_porter:\n    enabled: false\n",
            "reporters.SarifReporter.enabled=true",
        )
    except ASHConfigValidationError:
        return
    record = config._operator_reporters
    extra = record.reporters.model_extra or {}
    assert extra["sarif-re_porter"]["enabled"] is False, extra


def test_an_ambiguous_trusted_fold_still_refuses(tmp_path):
    """Two trusted sections fold together: no rewrite, and the replay refuses
    the repository's spelling against the first of them, so that operator
    stays locked out -- the recorded cost of leaving ambiguous folds as
    written, kept deliberate here."""
    with pytest.raises(ASHRespelledOverrideError):
        _resolution(
            tmp_path,
            "project_name: repo\nreporters:\n  AwsSecurityHub:\n    enabled: true\n",
            "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n"
            "  AWS_SECURITY_HUB:\n    enabled: true\n",
            "reporters.AwsSecurityHub.enabled=false",
        )


def test_the_ambiguous_refusal_names_no_env_read_key(tmp_path, monkeypatch):
    """Both trusted spellings are read from the environment; the replay's
    refusal and every captured line name neither value."""
    first, second = "Aws_Security-HUB", "aws-Security_HUB"
    monkeypatch.setenv("ASH_RESPELL_K1", first)
    monkeypatch.setenv("ASH_RESPELL_K2", second)
    handler, restore = _capturing()
    try:
        with pytest.raises(ASHRespelledOverrideError) as refused:
            _resolution(
                tmp_path,
                "project_name: repo\nreporters:\n  AwsSecurityHub:\n    enabled: true\n",
                "project_name: op\nreporters:\n  ${ASH_RESPELL_K1}:\n    enabled: true\n"
                "  ${ASH_RESPELL_K2}:\n    enabled: true\n",
                "reporters.AwsSecurityHub.enabled=false",
            )
    finally:
        restore()
    text = str(refused.value)
    for value in (first, second):
        assert value not in text, text
        assert not [m for m in handler.messages if value in m], value


def _folded(tmp_path, trusted_text, overrides, repo_text):
    """_folded_onto_trusted as the replay calls it: the trusted base loaded
    from a file, and the resolved configuration stamped by a real first
    application, so its pre-override sections are the file's own."""
    from automated_security_helper.config.resolve_config import (
        _folded_onto_trusted,
        apply_config_overrides,
        load_config_file_for_run,
    )

    trusted_path = tmp_path / "fold-trusted.yaml"
    trusted_path.write_text(trusted_text, encoding="utf-8")
    trusted = load_config_file_for_run(trusted_path)[1]
    repo_path = tmp_path / "fold-repo.yaml"
    repo_path.write_text(repo_text, encoding="utf-8")
    resolved = apply_config_overrides(
        load_config_file_for_run(repo_path)[1], ["project_name=stamped"]
    )
    return _folded_onto_trusted(trusted, overrides, resolved)


OP_ONE = "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n"
REPO_ONE = "project_name: repo\nreporters:\n  AwsSecurityHub:\n    enabled: true\n"
SH = "reporters.aws-security-hub"

_REWRITES = [
    ("reporters.AwsSecurityHub.enabled=false", f"{SH}.enabled=false"),
    ("reporters.AWS_SECURITY_HUB.enabled=false", f"{SH}.enabled=false"),
    (f"{SH}.enabled=false", f"{SH}.enabled=false"),
    ("reporters.AwsSecurityHub+=[1]", f"{SH}+=[1]"),
    ("reporters.AwsSecurityHub", SH),
    (f"reporters.aws{chr(0x17F)}ecurityhub.enabled=false", None),
    (f"reporters.AWS-SECUR{chr(0x130)}TY-HUB.enabled=false", None),
    (f"reporters.{chr(0xFF21)}wsSecurityHub.enabled=false", None),
    (f"reporters.AwsSecurityHub{chr(0x200B)}.enabled=false", None),
    ("reporters=x", None),
    ("reporters.brand-new.enabled=false", None),
    ("scanners.AwsSecurityHub.enabled=false", None),
]


@pytest.mark.parametrize("override,expected", _REWRITES, ids=range(len(_REWRITES)))
def test_the_rewrite_table(tmp_path, override, expected):
    """The fold rewrites exactly the lockout rows. The non-ASCII rows pin the
    ASCII-only fold (a casefold or normalizing fold would read a long s, a
    dotted I, a fullwidth letter or a zero-width space as the section); the
    append row keeps its suffix; a non-reporters key is left as written by the
    function itself, not only by its caller's filter."""
    got = _folded(tmp_path, OP_ONE, [override], REPO_ONE)
    assert got == [override if expected is None else expected], got


def test_a_split_type_word_twin_does_not_make_the_fold_ambiguous(tmp_path):
    """Two trusted sections that fold by NAME alone but name different
    plugins (one's type word split by a separator) are two fold identities,
    not an ambiguous pair: the override typed for the real plugin's section
    still rewrites onto the trusted spelling. The fold reads the one
    identity both patch walks read (the folded section name paired with the
    reduced plugin name), so a name-only twin cannot lock the rewrite out;
    a true case-variant twin, which names the same plugin, stays ambiguous
    (the cell below)."""
    twinned = (
        "project_name: op\nreporters:\n"
        "  bedrock-summary-reporter:\n    enabled: true\n"
        "  Bedrock-Summary-Repo_rter:\n    enabled: true\n"
    )
    repo = (
        "project_name: repo\nreporters:\n"
        "  bedrock-summary-reporter:\n    enabled: true\n"
    )
    override = "reporters.bedrock_summary_reporter.enabled=false"
    assert _folded(tmp_path, twinned, [override], repo) == [
        "reporters.bedrock-summary-reporter.enabled=false"
    ]


def test_an_ambiguous_fold_is_left_as_written(tmp_path):
    ambiguous = (
        "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n"
        "  AWS_SECURITY_HUB:\n    enabled: true\n"
    )
    override = "reporters.AwsSecurityHub.enabled=false"
    assert _folded(tmp_path, ambiguous, [override], REPO_ONE) == [override]


def test_a_trusted_only_section_is_not_a_rewrite_target(tmp_path):
    """The repository's file spelled no reporters section, so nothing was
    forced on the operator: every spelling is left as written for the apply's
    own resolver, which refuses respellings of existing sections."""
    override = "reporters.AwsSecurityHub.enabled=false"
    assert _folded(tmp_path, OP_ONE, [override], "project_name: repo\n") == [override]


@pytest.mark.parametrize(
    "override",
    [
        "reporters.AwsSecurityHub.enabled=false",
        f"{SH}.enabled=false",
        "reporters.AwsSecurityHub+=[1]",
        f"{SH}.options.x=1",
    ],
    ids=range(4),
)
def test_an_override_the_unfolded_replay_applied_applies_identically(
    tmp_path, override
):
    """The fold only turns refusals into landings: wherever the replay without
    the fold applied an override, the folded replay applies it to the same
    result."""
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
        load_config_file_for_run,
    )

    trusted_path = tmp_path / "parity-trusted.yaml"
    trusted_path.write_text(OP_ONE, encoding="utf-8")
    trusted = load_config_file_for_run(trusted_path)[1]
    try:
        unfolded = apply_config_overrides(trusted, [override]).model_dump()
    except ASHConfigValidationError:
        unfolded = None
    folded = _folded(tmp_path, OP_ONE, [override], REPO_ONE)
    try:
        with_fold = apply_config_overrides(trusted, folded).model_dump()
    except ASHConfigValidationError:
        with_fold = None
    if unfolded is not None:
        assert with_fold == unfolded


def test_the_pre_override_stamp_is_the_first_applications(tmp_path):
    """The stamp holds the sections the file spelled before any override, so a
    second application must not rewrite it: re-stamping would read the first
    application's own additions as the file's, and an override-created section
    would then pass the fold's the-file-held-it test. Copies carry it."""
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
        load_config_file_for_run,
    )

    repo = tmp_path / "stamp-repo.yaml"
    repo.write_text("project_name: repo\n", encoding="utf-8")
    loaded = load_config_file_for_run(repo)[1]
    assert loaded._reporters_before_overrides is None
    first = apply_config_overrides(loaded, ["reporters.created-one.enabled=true"])
    stamp = first._reporters_before_overrides
    assert stamp is not None and "created-one" not in stamp
    second = apply_config_overrides(first, ["reporters.created-two.enabled=true"])
    assert "created-one" not in second._reporters_before_overrides
    assert first.model_copy()._reporters_before_overrides == stamp
    assert first.model_copy(deep=True)._reporters_before_overrides == stamp
