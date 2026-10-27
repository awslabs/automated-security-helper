# Write a converter plugin

A converter runs before the scanners and writes files they can read. ASH's own converters extract archives and turn Jupyter notebooks into Python. This page builds `markdown-python`, a converter that copies the Python code blocks out of Markdown files so that Python scanners check the code in your documentation too. It keeps each line at its original line number, so a finding in the converted file points at the same line of the Markdown file.

Prerequisites:

- ASH installed ([Install ASH](../how-to/install.md));
- a repository to scan, with your shell in its top directory. To keep the steps short, this page saves the plugin package in an `ash-plugins` directory there; a plugin you keep belongs outside the repositories you scan ([Package a third-party plugin](index.md#package-a-third-party-plugin)).

[Plugins](index.md) explains how ASH loads plugin packages and what a loaded plugin can do.

## 1. Write the plugin

Save this as `ash-plugins/acme_ash_plugins/__init__.py`:

<!-- doctest: save-as=ash-plugins/acme_ash_plugins/__init__.py -->
````python
import re
from pathlib import Path
from typing import List, Literal

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.models.core import ignore_paths_that_skip_scanning
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scanned_tree import TreeInputRefused
from automated_security_helper.utils.suppression_matcher import file_path_matches

FENCE_OPEN = re.compile(r"^\s*```(python|py)\s*$")
FENCE_CLOSE = re.compile(r"^\s*```\s*$")


class MarkdownPythonConfig(ConverterPluginConfigBase):
    name: Literal["markdown-python"] = "markdown-python"
    enabled: bool = True


@ash_converter_plugin
class MarkdownPythonConverter(ConverterPluginBase[MarkdownPythonConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = MarkdownPythonConfig()
        super().model_post_init(context)

    def _inputs(self) -> List[Path]:
        ignored = ignore_paths_that_skip_scanning(
            self.context.config.global_settings.ignore_paths,
            ignore_suppressions=self.context.ignore_suppressions,
        )
        inputs = []
        for name in scan_set(
            source=self.context.source_dir, output=self.context.output_dir
        ):
            path = Path(name.strip())
            relative = path.relative_to(self.context.source_dir).as_posix()
            if path.suffix == ".md" and not any(
                file_path_matches(relative, ignore.path) for ignore in ignored
            ):
                inputs.append(path)
        return inputs

    def convert(self) -> List[Path]:
        written = []
        for path in self._inputs():
            try:
                with self.open_source_file(path) as handle:
                    text = handle.read().decode("utf-8", errors="replace")
            except TreeInputRefused as refusal:
                self.record_refused_input(refusal)
                continue
            # Keep every line, blanking the ones outside python fences, so a
            # finding's line number is the same in the Markdown file.
            lines, inside, found = [], False, False
            for line in text.splitlines():
                if inside and FENCE_CLOSE.match(line):
                    inside = False
                    lines.append("")
                elif not inside and FENCE_OPEN.match(line):
                    inside = found = True
                    lines.append("")
                else:
                    lines.append(line if inside else "")
            if not found:
                continue
            relative = path.relative_to(self.context.source_dir)
            target = self.results_dir / relative.with_name(relative.name + ".py")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
            written.append(target)
        return written


ASH_CONVERTERS = [MarkdownPythonConverter]
````

## 2. Check that ASH finds it

```bash
export PYTHONPATH="$PWD/ash-plugins"
ash plugin list --ash-plugin-modules acme_ash_plugins
```

The converters table has a row for the plugin:

```text
│ markdown-python │ True    │ MarkdownPython… │ acme_ash_plug… │               │
```

## 3. Scan with it

Save this as `docs/usage.md` in the repository. It has a Python example at lines 5 to 8:

<!-- doctest: save-as=docs/usage.md -->
````markdown
# Usage

Call it like this:

```python
import subprocess
subprocess.call(user_input, shell=True)
```
````

Run a scan with the module loaded:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --ash-plugin-modules acme_ash_plugins --scanners detect-secrets --offline
```

The scan exits with code 2 for the hardcoded password in `app.py`. List what the converter wrote:

```bash
ls .ash/ash_output/converted/markdown-python/docs
```

The converter wrote `usage.md.py`, which has the two lines of code at lines 6 and 7 and blank lines everywhere else. ASH passes the directory of converted files to every scanner as a second target, after the source directory. This scan ran only detect-secrets, which needs no download, so it shows the conversion but no finding in the converted file. A Python scanner, such as bandit or the `ruff-security` scanner from [Write a scanner plugin](write-a-scanner.md), reports the `shell=True` call at `.ash/ash_output/converted/markdown-python/docs/usage.md.py`, line 7. bandit reports it once, from the converted target: on its run over the source directory, ASH tells it to skip ASH's output directory.

## How ASH runs a converter

ASH runs the converters in the convert phase, before any scanner. It constructs each enabled converter and calls its `convert()` with no arguments, once per scan. The converter finds its own inputs and returns the list of files it wrote.

The base class, `ConverterPluginBase`, declares the method as `convert(self)`, as ASH's own converters define it. A `convert()` that requires one parameter, such as `convert(self, target)`, still runs: ASH passes the source directory as that parameter and logs a warning that asks for `convert(self)`. A `convert()` that requires more than one parameter, or is declared `async`, fails with an error that says to declare `def convert(self)`, and the converter counts as failed.

Inside `convert()`:

- Find inputs with `scan_set(source=..., output=...)` from `automated_security_helper.utils.get_scan_set`. It returns the files ASH scans: the files under the source directory that the repository's `.gitignore` and `.ignore` files do not exclude. ASH's output directories are left out: the scan's output directory and `.ash/ash_output` under the source directory and under the working directory. In a git checkout, the files git tracks in those directories stay in the scan set.
- Skip the inputs that `global_settings.ignore_paths` covers, as the example does with `ignore_paths_that_skip_scanning` and `file_path_matches`. ASH removes findings under an ignored path after the scan by matching the finding's path, and a converted file's path is under `.ash/ash_output/converted/`, so findings in a converted copy of an ignored file would otherwise be reported. `ignore_paths_that_skip_scanning` leaves out the ignore paths an MCP client supplied, which ASH reports as suppressed findings instead of skipping. An ignore path stops applying on its `expiration` date, and its files are scanned again; `active_ignore_paths` from `automated_security_helper.utils.suppression_matcher` returns the entries that still apply, and ASH's own converters skip only those.
- Read each input through `self.open_source_file(path)`, not `open()`. It refuses a symbolic link or a path outside the source directory by raising `TreeInputRefused`. Pass that to `self.record_refused_input()`, which logs a warning and lists the input in the converter's results.
- Write output only under `self.results_dir`, which is `.ash/ash_output/converted/<name>/`. Every file you write there is scanned, whether or not you return it, as long as at least one name under `.ash/ash_output/converted/` has an extension, such as `.py`; if none does, ASH does not scan the converted directory at all.
- Return a list of the paths you wrote. An empty list means there was nothing to convert.

How a converter's problems affect the scan:

| What happens | Result |
|---|---|
| `convert()`, or the constructor, raises an exception | the converter is recorded as failed and the scan exits with code 1, because some files were not given to the scanners |
| you call `self.record_failed_input(path, reason)` for an input you could not convert | the input is listed in the results, the error is logged, and the scan exits with code 1 for the same reason |
| an input is refused and recorded with `record_refused_input()` | the input is listed in the results; the exit code is unaffected |

The exit code 1 for lost coverage comes from `fail_on_incomplete_scanners`, which is on by default ([Set the gate](../how-to/set-the-gate.md)). The results row for each converter is under `converter_results` in `.ash/ash_output/ash_aggregated_results.json`.

## A converter that needs a tool

If your converter runs a program, override `validate_plugin_dependencies()` to return `False` when the program is not available; ASH then skips the converter. Also override `candidate_input_count()` to return how many inputs the converter would have converted, counted without the tool. When a converter that is skipped this way had inputs, ASH treats the scan as incomplete; when it had none, the skip costs nothing. A converter that does not override `candidate_input_count()` counts as having had inputs.

## Converted files in the results

Findings in converted files point at the converted file under `.ash/ash_output/converted/`, not at the original. ASH drops the findings a scanner reports in its output directories, except those in the converted files and in files git tracks there, and it does not deduplicate findings. So a scanner that walks the whole source directory and does not skip ASH's output directory, which is inside the source directory by default, can report a converted file twice, once under each target.
