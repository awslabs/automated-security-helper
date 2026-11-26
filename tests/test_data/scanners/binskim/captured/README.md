# Captured BinSkim output

Real output of BinSkim 4.4.9.14 (`Microsoft.CodeAnalysis.BinSkim` NuGet package, the
`tools/linux-x64` build, run on Amazon Linux 2023 with no .NET install), written by
the argv `BinskimScanner._build_arguments` builds:

```
BinSkim analyze --output=<file>.sarif --recurse=true --level=Error;Warning;Note \
  --kind=Fail --quiet=true --disable-telemetry=true --ignorePdbLoadError=true -- <dir>
```

Both runs exited 0. The files are byte-for-byte what BinSkim wrote.

The package `binskim_install.py` pins is the one these runs came from: its SHA256 is
`ea2f48ed02e6d7ff569614d0895b80c2669fbc261c8b386639de551af049bcf4`, and the
`tools/linux-x64/BinSkim` executable inside it is
`1c587424acd112daeb31e0ecde819e24402f544a4919d4fe707729ef4948da0d`. On 2026-11-26
that build, taken from the digest-checked package, wrote the same eight results for a
positive tree built the same way (rule ids, levels, files and message arguments
compared) with and without `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`, the same eight
again inside the ASH image's base image (which has no ICU) with the variable set, and
no result for the negative tree.

| File | Directory scanned | Contents |
| --- | --- | --- |
| `positive.sarif` | `/tmp/binskim-capture/positive` | 8 results: BA3001, BA3003, BA3010 and BA3011 (all `error`) on `bin/app` and on `sp ace/app 2`, plus a `readme.txt` the tool skipped |
| `negative.sarif` | `/tmp/binskim-capture/negative` | 0 results |

The positive tree holds one ELF built with GCC 11.5 and no hardening
(`gcc -O0 -fno-stack-protector -no-pie -Wl,-z,norelro`), a copy of it under a
directory and file name with a space, and a text file. The negative tree holds the
same program built with `-O2 -fstack-protector-strong -fPIE -pie -D_FORTIFY_SOURCE=2
-fcf-protection=full -Wl,-z,relro,-z,now,-z,noexecstack`. The program is
`int main(void){char b[64];return b[0];}`.

What the capture shows, and the adapter handles:

- A result has no `kind` and no `message.text`. Its message is `{"id": "Error",
  "arguments": ["app"]}`, and the text lives in the rule's `messageStrings`
  (`tool.driver.rules`, only for the rules that fired). The adapter resolves it and
  writes it as the message text.
- Artifact URIs are absolute `file://` URIs with the path percent-encoded
  (`sp%20ace/app%202`).
- A tree with no hardening gap writes a log with an empty `results` array, and a
  tree holding only a Java class file exits 0 and writes the same.
- Rules that cannot run on Linux are listed in `invocations[].toolConfigurationNotifications`.

Not in the capture: `warning` and `note` results, PE and Mach-O files. The
level-to-severity rows for those levels are inline in the tests, not captured.
Regenerate the logs when the BinSkim pin moves.
