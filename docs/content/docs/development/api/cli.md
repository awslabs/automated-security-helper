<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/cli.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `cli`





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/cli.py#L34"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `scan`

```python
scan(
    source_dir: Annotated[str, <OptionInfo object at 0x104689cf0>] = '/Users/nateferl/WorkGit/github.com/awslabs/ash-github',
    output_dir: Annotated[str, <OptionInfo object at 0x104689c60>] = '/Users/nateferl/WorkGit/github.com/awslabs/ash-github/ash_output',
    config: Annotated[str, <OptionInfo object at 0x104689ea0>] = None,
    verbose: Annotated[bool, <OptionInfo object at 0x104689e40>] = False,
    debug: Annotated[bool, <OptionInfo object at 0x104689a50>] = False,
    offline: Annotated[bool, <OptionInfo object at 0x104689ab0>] = False,
    no_build: Annotated[bool, <OptionInfo object at 0x104689b10>] = False,
    no_run: Annotated[bool, <OptionInfo object at 0x1046899c0>] = False,
    build_target: Annotated[AshBuildTarget, <OptionInfo object at 0x104689780>] = 'default',
    oci_runner: Annotated[str, <OptionInfo object at 0x1046897b0>] = 'docker',
    strategy: Annotated[Strategy, <OptionInfo object at 0x104689990>] = 'parallel',
    scanners: Annotated[List[str], <OptionInfo object at 0x104689930>] = [],
    no_cleanup: Annotated[bool, <OptionInfo object at 0x104689660>] = False,
    progress: Annotated[bool, <OptionInfo object at 0x104689630>] = True,
    output_formats: Annotated[List[ExportFormat], <OptionInfo object at 0x1046896f0>] = ['sarif', 'cyclonedx', 'json', 'html', 'junitxml']
)
```

Main entry point. 


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/cli.py#L24"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `Strategy`
An enumeration. 





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/cli.py#L29"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `AshBuildTarget`
An enumeration. 







---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
