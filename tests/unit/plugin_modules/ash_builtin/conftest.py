"""Fixtures the ash_builtin plugin tests share.

``checkouts_below_tmp_path`` is opt-in (``pytest.mark.usefixtures``), not
autouse: only the tests that place a baseline or a config under ``tmp_path`` and
need it read as the operator's use it.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def checkouts_below_tmp_path(monkeypatch, tmp_path):
    """Let the trust rules see only the git checkouts at or below ``tmp_path``.

    They walk EVERY checkout at or above the scanned directory, not the nearest
    (``path_trust._checkouts_holding``), so a temporary directory placed inside a
    work tree (a pytest base temp under a clone) would make a file the test puts
    in ``tmp_path`` the repository's, and flip the cases that need the
    operator's. The checkouts these tests are about are the ones they make.
    """
    from automated_security_helper.config import path_trust
    from automated_security_helper.config.sandbox_grants import is_within

    real = path_trust._checkouts_holding
    monkeypatch.setattr(
        path_trust,
        "_checkouts_holding",
        lambda scan_root: [c for c in real(scan_root) if is_within(c, tmp_path)],
    )
