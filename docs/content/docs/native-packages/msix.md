# Installing the MSIX (Windows)

The MSIX package installs ASH on Windows 10 version 2004 (build 19041) or later and Windows 11. It is self-signed and is not in the Microsoft Store, so installing it means deciding to trust its signing certificate first. See [Publication status](index.md#publication-status).

## Prerequisites

- Python 3.10, 3.11, 3.12 or 3.13. The package does not carry an interpreter. Its launcher tries `py -3.13`, `-3.12`, `-3.11` and `-3.10`, then `py -3`, `python3` and `python`, and uses the first one whose version is in range. Set `ASH_MSIX_PYTHON` to the full path of an interpreter to skip the search; that path is not version-checked.
- A reachable Python index on the first run, or a staged wheelhouse (see [Offline machines](#offline-machines)).
- An elevated PowerShell for trusting the certificate.

## Get the package

There is no release asset. Use one of these:

- Download the `.msix` that CI built. Every run of the `ASH - Package` workflow (`ash-package.yml`) that builds the MSIX uploads it as an artifact named `ash-msix-<commit>-attempt-<n>`, kept for 14 days. With the GitHub CLI, signed in:

    ```powershell
    gh run download <run-id> --repo awslabs/automated-security-helper --pattern 'ash-msix-*'
    ```

- Build it from a checkout. You need the Windows SDK, which provides `makeappx.exe` and `signtool.exe`, and `uv`:

    ```powershell
    uv build --out-dir dist
    pwsh -File packaging/msix/build.ps1 -Wheel dist\automated_security_helper-<version>-py3-none-any.whl
    ```

    The package is written to `build\msix\automated-security-helper-<version>.msix`. With no signing secret set, `build.ps1` signs it with a new throwaway self-signed certificate.

## Trust the certificate and install

Run these in an elevated PowerShell. Reading the certificate out of the package means you trust the certificate that signed this file, not one obtained separately.

```powershell
# 1. Read the signing certificate from the package.
$msix = 'C:\path\to\automated-security-helper-<version>.msix'
$signature = Get-AuthenticodeSignature -FilePath $msix
$signature.SignerCertificate | Format-List Subject, Thumbprint, NotAfter

# 2. Check the Subject and Thumbprint, then trust it for package installs.
[System.IO.File]::WriteAllBytes("$env:TEMP\ash-signer.cer", $signature.SignerCertificate.RawData)
Import-Certificate -FilePath "$env:TEMP\ash-signer.cer" -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'

# 3. Install.
Add-AppxPackage -Path $msix
```

Use `LocalMachine\TrustedPeople`, not the Trusted Root store. The certificate is not a certificate authority, and the deployment service checks only the Local Machine store.

## Run it

```powershell
ashx --version
ashx dependencies install
ashx scan --source-dir C:\path\to\repo
```

The first `ashx` is slow: it creates a virtualenv under `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\ash-venv` and installs the bundled wheel into it, and prints two lines on stderr saying so. Later runs use that virtualenv.

The package registers three app execution aliases: `ashx`, the deprecated `ashv3`, and `automated-security-helper`. It does not register `ash`. An alias is only a name on `PATH`, so if another program claims `ashx` earlier on your `PATH`, use `automated-security-helper`. You can see and turn off each alias under **Settings > Apps > Advanced app settings > App execution aliases**.

If pip fails partway through the first run with a path-length error, point the virtualenv somewhere shorter. A virtualenv you place yourself is not removed on uninstall.

```powershell
setx ASH_MSIX_VENV C:\ash-venv
```

## File system access

The package declares `runFullTrust`, which is what lets ASH read the directory you point it at, and `broadFileSystemAccess`, which lists ASH under **File system** in the Windows privacy settings with a toggle. Turning that toggle off makes Windows stop ASH so the change can apply. `packaging/msix/README.msix` explains why no narrower capability can express "whatever directory you ran the command in".

## Upgrade

Install the newer `.msix` with `Add-AppxPackage`. A package signed by a different throwaway certificate needs that certificate trusted first, using the same steps. The launcher rebuilds the virtualenv when the bundled wheel changes. Delete `.ash-bootstrap-complete` inside the virtualenv to force a rebuild on the next run.

## Uninstall

```powershell
Get-AppxPackage -Name AWSLabs.AutomatedSecurityHelper | Remove-AppxPackage
```

Windows deletes the package's per-user state, which includes the default virtualenv. To withdraw the certificate trust afterwards:

```powershell
Get-ChildItem Cert:\LocalMachine\TrustedPeople |
    Where-Object { $_.Subject -like '*ASH Development*' } | Remove-Item
```

## Offline machines

Stage a wheelhouse before the first `ashx`. Resolve it from ASH's own wheel, on a machine that can reach an index. Do not run `pip download automated-security-helper`: that name on PyPI belongs to an unrelated third party, not to this project.

```powershell
pip download .\automated_security_helper-<version>-py3-none-any.whl -d C:\ash-wheels
setx PIP_NO_INDEX true
setx PIP_FIND_LINKS C:\ash-wheels
```
