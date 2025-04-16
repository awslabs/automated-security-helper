<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/cdk_nag_scanner.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `scanners.ash_default.cdk_nag_scanner`
Module containing the CDK Nag security scanner implementation. 

**Global Variables**
---------------
- **ASH_DOCS_URL**
- **ASH_REPO_URL**


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/cdk_nag_scanner.py#L38"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CdkNagPacks`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/cdk_nag_scanner.py#L65"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CdkNagScannerConfigOptions`
CDK Nag IAC SAST scanner options. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/cdk_nag_scanner.py#L76"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CdkNagScannerConfig`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/cdk_nag_scanner.py#L84"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CdkNagScanner`
CDK Nag security scanner, custom CDK-CLI-less implementation. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/cdk_nag_scanner.py#L87"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/cdk_nag_scanner.py#L126"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `scan`

```python
scan(target: Path, config: CdkNagScannerConfig | None = None) → SarifReport
```

Scan the target and return findings. 



**Args:**
 
 - <b>`target`</b>:  Path to scan. Can be a file or directory. 



**Returns:**
 IaC scan report containing findings 



**Raises:**
 
 - <b>`ScannerError`</b>:  If scanning fails 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/cdk_nag_scanner.py#L96"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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
