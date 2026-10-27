"""The environment the tests start pwsh in.

Shared by the tests that run ``utils/ash_helpers.ps1``, so they cannot drift apart
on what they keep from the developer's environment.
"""

import os
from pathlib import Path

#: Variables that make a shell read one of the developer's startup files. pwsh can
#: itself be a shell script (nix installs it as a bash wrapper), and a non-interactive
#: bash runs $BASH_ENV before anything else, so a startup file there could export
#: OCI_RUNNER again after a test removed it. ENV is read by sh and ksh, and zsh reads
#: $ZDOTDIR/.zshenv.
SHELL_STARTUP_VARIABLES = ("BASH_ENV", "ENV", "ZDOTDIR")

#: pwsh's telemetry and update check, both off.
QUIET_PWSH = {"POWERSHELL_TELEMETRY_OPTOUT": "1", "POWERSHELL_UPDATECHECK": "Off"}


def inherited_env(*drop: str) -> dict[str, str]:
    """``os.environ`` without the shell startup variables or the names in ``drop``."""
    excluded = {*SHELL_STARTUP_VARIABLES, *drop}
    return {name: value for name, value in os.environ.items() if name not in excluded}


def scratch_home(tmp_path: Path) -> dict[str, str]:
    """A HOME and XDG directories of the test's own, and ``QUIET_PWSH``.

    pwsh writes caches under them. Not for a test that runs a real OCI runner, which
    reads its configuration and (for podman) its image store from the same places.
    """
    home = tmp_path / "pwsh-home"
    for sub in ("", ".cache", ".local/share", ".config"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    return {
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        **QUIET_PWSH,
    }
