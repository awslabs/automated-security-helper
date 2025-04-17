<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/custom_scanner.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `scanners.ash_default.custom_scanner`
Module containing the generic security scanner implementation. 

This security scanner depends on a valid ScannerPluginConfig to be provided in the `build.custom_scanners` section of an ASHConfig instance or ASH configuration YAML/JSON file. 

**Global Variables**
---------------
- **ASH_DOCS_URL**
- **ASH_REPO_URL**


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/custom_scanner.py#L51"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CustomScannerConfigOptions`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/custom_scanner.py#L55"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CustomScannerConfig`
Custom scanner configuration. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/custom_scanner.py#L66"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CustomScanner`
CustomScanner provides an interface for custom scanners using known formats. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/custom_scanner.py#L71"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/custom_scanner.py#L90"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `scan`

```python
scan(
    target: Path,
    config: Optional[Any, CustomScannerConfig] = None
) → SarifReport
```

Execute Checkov scan and return results. 



**Args:**
 
 - <b>`target`</b>:  Path to scan 



**Returns:**
 SarifReport containing the scan findings and metadata 



**Raises:**
 
 - <b>`ScannerError`</b>:  If the scan fails or results cannot be parsed 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/custom_scanner.py#L79"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `validate`

```python
validate() → bool
```

Validate the scanner configuration and requirements. 



**Returns:**
  True if validation passes, False otherwise 



**Raises:**
 
 - <b>`ScannerError`</b>:  If validation fails 




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
