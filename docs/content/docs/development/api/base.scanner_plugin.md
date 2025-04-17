<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/scanner_plugin.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `base.scanner_plugin`






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/scanner_plugin.py#L16"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ScannerPluginConfigBase`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/scanner_plugin.py#L23"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ScannerPluginBase`
Base class for all scanner plugins. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/scanner_plugin.py#L60"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/scanner_plugin.py#L92"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `scan`

```python
scan(
    target: Path,
    config: Union[~T, ScannerPluginConfigBase] = None,
    *args,
    **kwargs
) → Any
```

Execute scanner against a target. 



**Args:**
 
 - <b>`*args`</b>:  Variable length argument list 
 - <b>`**kwargs`</b>:  Arbitrary keyword arguments 



**Returns:**
 
 - <b>`SecurityReport`</b>:  Full scan results 



**Raises:**
 
 - <b>`ScannerError`</b>:  if scanning failed for any reason 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/scanner_plugin.py#L81"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `validate`

```python
validate() → bool
```

Validate scanner configuration. 



**Returns:**
 
 - <b>`bool`</b>:  True if validation passes 




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
