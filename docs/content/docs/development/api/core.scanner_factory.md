<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/scanner_factory.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `core.scanner_factory`
Module containing the ScannerFactory class for creating scanner instances.



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/scanner_factory.py#L15"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ScannerFactory`
Factory class for creating and configuring scanner instances.

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/scanner_factory.py#L18"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `__init__`

```python
__init__(
    config: AshConfig = None,
    registered_scanner_plugins: Dict[str, RegisteredPlugin] = {}
) → None
```

Initialize the scanner factory with empty scanner registry.



**Args:**

 - <b>`config`</b>:  Optional AshConfig instance to load custom scanner configurations




---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/scanner_factory.py#L237"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `available_scanners`

```python
available_scanners() → Dict[str, Type[ScannerPluginBase]]
```

Get dictionary of all registered scanners.



**Returns:**
  Dictionary mapping scanner names to scanner classes



**Raises:**

 - <b>`TypeError`</b>:  If scanner class cannot be determined for any scanner

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/scanner_factory.py#L165"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `create_scanner`

```python
create_scanner(
    scanner_name: str,
    config: Optional[ScannerPluginBase, ScannerPluginConfigBase] = None,
    source_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None
) → ScannerPluginBase
```

Create a scanner instance of the specified type with optional configuration.



**Args:**

 - <b>`scanner_type`</b>:  Type of scanner to create (name, class, config object, or dict)
 - <b>`config`</b>:  Optional configuration for the scanner



**Returns:**
 An instance of the requested scanner type



**Raises:**

 - <b>`ValueError`</b>:  If scanner type is not registered
 - <b>`TypeError`</b>:  If scanner type is invalid

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/scanner_factory.py#L213"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `get_scanner_class`

```python
get_scanner_class(scanner_name: str) → Type[ScannerPluginBase]
```

Get the scanner class for a given name.



**Args:**

 - <b>`scanner_name`</b>:  Name of scanner to retrieve (will be normalized)



**Returns:**
 The scanner class



**Raises:**

 - <b>`ValueError`</b>:  If scanner_name is not registered
 - <b>`TypeError`</b>:  If stored value is not a scanner class

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/core/scanner_factory.py#L111"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `register_scanner`

```python
register_scanner(
    scanner_name: str,
    scanner_input: Union[Type[ScannerPluginBase], Callable[[], ScannerPluginBase]]
) → None
```

Register a scanner with the factory.

The scanner name will be normalized to lowercase. Both the original name and base name without 'scanner' suffix (if present) will be registered.



**Args:**

 - <b>`scanner_name`</b>:  Name of scanner to register (will be normalized)
 - <b>`scanner_input`</b>:  Scanner class or factory function to register



**Raises:**

 - <b>`ValueError`</b>:  If scanner name is empty or already registered
 - <b>`TypeError`</b>:  If scanner input is not valid




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
