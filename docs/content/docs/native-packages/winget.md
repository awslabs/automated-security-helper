# Installing with winget (Windows)

The winget package identifier is `Amazon.AutomatedSecurityHelper` and its moniker is `ash`. The command it installs is `ashx`. The package is not in the winget community repository, so `winget install ash` finds nothing. The manifest set under `packaging/winget/` installs the [MSIX](msix.md), and you install it with a local manifest. See [Publication status](index.md#publication-status).

The manifest set is schema-valid and CI installs, upgrades and uninstalls through it, but it is not ready to submit to `microsoft/winget-pkgs`. The MSIX it points at is self-signed, and the community repository requires an installer signed by a certificate its validation pipeline trusts.

## Prerequisites

- winget 1.12.210 or later, the first client that reads the 1.12 manifest schemas.
- An elevated shell, both for trusting the MSIX certificate and for enabling local manifests.
- `uv` and a checkout of the repository, to render the manifest set.
- Everything the [MSIX prerequisites](msix.md#prerequisites) list, since that is what winget installs.

## Install from a local manifest

1. Get the `.msix` and trust its certificate, following [Get the package](msix.md#get-the-package) and steps 1 and 2 of [Trust the certificate and install](msix.md#trust-the-certificate-and-install). Do not run `Add-AppxPackage`; winget installs it.

2. Serve the directory holding the `.msix` on loopback. Leave this running in its own shell:

    ```powershell
    python -m http.server 8000 --bind 127.0.0.1 --directory C:\path\to\msix-dir
    ```

3. Render a manifest set for that file. `set-release-metadata.py` reads the digest, architecture, minimum OS version and package family name out of the `.msix`, writes a copy of the manifests, and validates the copy. The validation fetches Microsoft's published schemas, so it needs network access.

    ```powershell
    uv run packaging/winget/set-release-metadata.py `
        --msix C:\path\to\msix-dir\automated-security-helper-<version>.msix `
        --out-dir build\winget `
        --local-url-base http://127.0.0.1:8000
    ```

4. Allow local manifests once, then install:

    ```powershell
    winget settings --enable LocalManifestFiles
    winget install --manifest build\winget --accept-package-agreements --accept-source-agreements
    ```

winget checks the `.msix` against the digest in the manifest and refuses a file that does not match.

## Run it

The installed commands are the MSIX's app execution aliases: `ashx`, the deprecated `ashv3`, and `automated-security-helper`. No `ash` command is installed, because MSYS2 and Git for Windows ship the Almquist shell under that name.

```powershell
ashx --version
ashx dependencies install
```

## Upgrade

Render a manifest set for the newer `.msix` the same way, then:

```powershell
winget upgrade --manifest build\winget --accept-package-agreements --accept-source-agreements
```

## Uninstall

```powershell
winget uninstall --manifest build\winget
```

`winget uninstall` and `winget upgrade --manifest` find the installed MSIX by its package family name, which the rendered set carries. Withdraw the certificate trust afterwards as the [MSIX page](msix.md#uninstall) shows.
