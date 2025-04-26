<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `core.execution_engine`
Execution engine for security scanners.



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L27"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ExecutionStrategy`
Strategy for executing scanners.





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L34"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ScanProgress`
Tracks progress of security scans.

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L37"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `__init__`

```python
__init__(total: int)
```

Initialize scan progress tracker.




---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L42"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `increment`

```python
increment()
```

Increment the completed count.


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L47"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ScanExecutionEngine`
Manages the execution of security scanners.

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L50"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `__init__`

```python
__init__(
    source_dir: Path = None,
    output_dir: Path = None,
    enabled_scanners: Optional[List[str]] = [],
    strategy: Optional[ExecutionStrategy] = <ExecutionStrategy.PARALLEL: 'parallel'>,
    asharp_model: Optional[ASHARPModel] = None,
    config: Optional[AshConfig] = None,
    show_progress: bool = True
)
```

Initialize the execution engine.



**Args:**

 - <b>`source_dir`</b>:  Source directory to scan
 - <b>`output_dir`</b>:  Output directory for scan results
 - <b>`enabled_scanners`</b>:  List of scanner names to enable. If None, all scanners are enabled.  If empty list, no scanners are enabled.
 - <b>`strategy`</b>:  Execution strategy to use for scanner execution (default: PARALLEL)


---

#### <kbd>property</kbd> completed_scanners

Get list of completed scanners.

---

#### <kbd>property</kbd> progress

Get current scan progress.



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L287"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ensure_initialized`

```python
ensure_initialized(config: Optional[AshConfig] = None) → None
```

Ensure scanner factory and scanners are properly initialized.

This method: 1. Registers and enables all default scanners from factory 2. Processes config if provided to override scanner settings 3. Maintains all scanners enabled by default if no explicit config



**Args:**

 - <b>`config`</b>:  ASH configuration object for initialization

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L177"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `get_scanner`

```python
get_scanner(scanner_name: str, check_enabled: bool = True) → ScannerPluginBase
```

Get a scanner instance by name.

Attempts to find and instantiate a scanner in the following order: 1. First validates if scanner is enabled if check_enabled=True 2. Looks up scanner in registered scanners (including placeholders) 3. Tries base name without 'scanner' suffix 4. Attempts to get implementation from scanner factory 5. Auto-registers from factory if found



**Args:**

 - <b>`scanner_name`</b>:  Name of the scanner to retrieve
 - <b>`check_enabled`</b>:  If True, validate against enabled scanners list first



**Returns:**
 Scanner instance configured with current engine paths



**Raises:**

 - <b>`ValueError`</b>:  If scanner does not exist or is not enabled

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L312"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `run_prepare_phase`

```python
run_prepare_phase(config: Optional[AshConfig] = None) → None
```

The Prepare phase of ASH runs any tasks that need to be ran before scanning starts. This typically includes running any registered Converters to make unscannable content scannable, resolving any remaining configuration items, or preparing other scanner peripherals such as sidecar containers for reporter storage.



**Args:**

 - <b>`config`</b> (Optional[AshConfig], optional):  An override configuration to be provided at the start of this phase. Defaults to None.

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L329"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `run_scan_phase`

```python
run_scan_phase(config: Optional[AshConfig] = None) → ASHARPModel
```

Execute registered scanners based on provided configuration.



**Args:**

 - <b>`config`</b> (Optional[AshConfig], optional):  An override configuration to be provided at the start of this phase. Defaults to None.



**Returns:**

 - <b>`Dict[str, Any]`</b>:  Results dictionary with scanner results and ASHARPModel



**Raises:**

 - <b>`ValueError`</b>:  If config is invalid or mode is invalid
 - <b>`RuntimeError`</b>:  If scanner execution fails critically

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/execution_engine.py#L779"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `set_max_workers`

```python
set_max_workers(workers: int) → None
```

Set maximum number of worker threads for parallel execution.




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
