<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/reporter_plugin.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `base.reporter_plugin`
Module containing the ReporterPlugin base class. 



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/reporter_plugin.py#L14"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ReporterPluginConfigBase`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/reporter_plugin.py#L21"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ReporterPluginBase`
Base reporter plugin with some methods of the IReporter abstract class implemented for convenience. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/reporter_plugin.py#L54"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `configure`

```python
configure(config: ReporterPluginConfigBase | None = None) → None
```

Configure the reporter with provided configuration. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/reporter_plugin.py#L78"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `convert`

```python
convert(target: Path | str) → List[Path]
```

Execute the reporter on the target prior to scans. 

Returns the list of Path objects emitted by the `convert()` operation. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/reporter_plugin.py#L44"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `setup_paths`

```python
setup_paths() → Self
```

Set up default paths and initialize plugin configuration. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/reporter_plugin.py#L62"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `validate`

```python
validate() → bool
```

Validate reporter configuration and requirements. 




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
