<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/bandit_scanner.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `scanners.ash_default.bandit_scanner`
Module containing the Bandit security scanner implementation. 



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/bandit_scanner.py#L33"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `BanditScannerConfigOptions`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/bandit_scanner.py#L71"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `BanditScannerConfig`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/bandit_scanner.py#L79"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `BanditScanner`
Implementation of a Python security scanner using Bandit. 

This scanner uses Bandit to perform static security analysis of Python code and returns results in a structured format using the StaticAnalysisReport model. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/bandit_scanner.py#L115"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `configure`

```python
configure(config: ScannerPluginBase | None = None)
```

Configure the scanner with the provided configuration. 



**Args:**
 
 - <b>`config`</b>:  Scanner configuration 



**Raises:**
 
 - <b>`ScannerError`</b>:  If configuration fails 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/bandit_scanner.py#L86"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/bandit_scanner.py#L193"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `scan`

```python
scan(target: Path, config: BanditScannerConfig | None = None) → SarifReport
```

Execute Bandit scan and return results. 



**Args:**
 
 - <b>`target`</b>:  Path to scan 



**Returns:**
 StaticAnalysisReport containing the scan findings and metadata 



**Raises:**
 
 - <b>`ScannerError`</b>:  If the scan fails or results cannot be parsed 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/bandit_scanner.py#L133"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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
