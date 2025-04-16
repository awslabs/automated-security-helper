<!-- markdownlint-disable -->

# Reference mkdocsstrings

::: automated_security_helper.scanners.ash_default.BanditScanner

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/detect_secrets_scanner.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `scanners.ash_default.detect_secrets_scanner`
Module containing the Checkov security scanner implementation.



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/detect_secrets_scanner.py#L39"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `DetectSecretsScannerConfigOptions`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/detect_secrets_scanner.py#L44"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `DetectSecretsScannerConfig`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/detect_secrets_scanner.py#L53"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `DetectSecretsScanner`
DetectSecretsScanner implements SECRET scanning using detect-secrets.


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/detect_secrets_scanner.py#L56"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/detect_secrets_scanner.py#L84"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `scan`

```python
scan(
    target: Path,
    config: DetectSecretsScannerConfig | None = None
) → SarifReport
```

Execute detect-secrets scan and return results.



**Args:**

 - <b>`target`</b>:  Path to scan



**Returns:**
 SarifReport containing the scan findings and metadata



**Raises:**

 - <b>`ScannerError`</b>:  If the scan fails or results cannot be parsed

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/scanners/ash_default/detect_secrets_scanner.py#L65"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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
