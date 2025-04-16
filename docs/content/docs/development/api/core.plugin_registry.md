<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/plugin_registry.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `core.plugin_registry`






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/plugin_registry.py#L28"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `PluginType`
An enumeration. 





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/plugin_registry.py#L34"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `RegisteredPlugin`
Represents a plugin that has been registered. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/plugin_registry.py#L59"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `PluginRegistry`
Registry for plugins. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/plugin_registry.py#L82"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `discover_plugins`

```python
discover_plugins(
    plug_type: str,
    package: str = None,
    config: ASHConfig | None = None
) → dict
```

Discover plugins and register them. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/plugin_registry.py#L198"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `get_plugin`

```python
get_plugin(
    plugin_type: PluginType,
    plugin_name: str = None
) → Union[RegisteredPlugin, Dict[str, RegisteredPlugin], NoneType]
```

Get a plugin by name or get all plugins for a specific type. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/plugin_registry.py#L65"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```








---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
