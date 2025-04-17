<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/scan_results_container.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `models.scan_results_container`
Module containing the ScanResultsContainer class for wrapping scanner results. 



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/scan_results_container.py#L9"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ScanResultsContainer`
Container for scanner results with metadata. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/scan_results_container.py#L41"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `add_metadata`

```python
add_metadata(key: str, value: Any) → None
```

Add metadata to the container. 



**Args:**
 
 - <b>`key`</b>:  Metadata key 
 - <b>`value`</b>:  Metadata value 




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
