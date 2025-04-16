<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/converter_plugin.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `base.converter_plugin`
Module containing the ConverterPlugin base class. 



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/converter_plugin.py#L13"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ConverterPluginConfigBase`





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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/converter_plugin.py#L20"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ConverterPluginBase`
Base converter plugin with some methods of the IConverter abstract class implemented for convenience. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/converter_plugin.py#L51"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `configure`

```python
configure(config: ConverterPluginConfigBase | None = None) → None
```

Configure the converter with provided configuration. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/converter_plugin.py#L64"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `convert`

```python
convert(target: Path | str) → List[Path]
```

Execute the converter on the target prior to scans. 

Returns the list of Path objects emitted by the `convert()` operation that correspond to scannable files emitted to the work_dir. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/converter_plugin.py#L35"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `setup_paths`

```python
setup_paths() → Self
```

Set up default paths and initialize plugin configuration. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/base/converter_plugin.py#L59"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `validate`

```python
validate() → bool
```

Validate converter configuration and requirements. 




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
