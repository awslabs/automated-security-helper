<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/orchestrator.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `core.orchestrator`
Main entry point for ASH multi-scanner execution. 



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/orchestrator.py#L27"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ASHScanOrchestrator`
Orchestrator class for ASH security scanning operations. 


---

#### <kbd>property</kbd> model_extra

Get extra fields set during validation. 



**Returns:**
  A dictionary of extra fields, or `None` if `config.extra` is not set to `"allow"`. 

---

#### <kbd>property</kbd> model_fields_set

Returns the set of fields that have been explicitly set on this model instance. 



**Returns:**
  A set of strings representing the fields that have been set,  i.e. that were not filled from defaults. 



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/orchestrator.py#L93"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ensure_directories`

```python
ensure_directories()
```

Ensure required directories exist in a thread-safe manner. 

Creates work_dir if it doesn't exist or if no_cleanup is True, and output_dir if it doesn't exist. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/orchestrator.py#L242"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `execute_scan`

```python
execute_scan() → Dict
```

Execute the security scan and return results. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/orchestrator.py#L143"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```

Post initialization configuration. 




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
