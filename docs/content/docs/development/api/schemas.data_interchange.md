<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `schemas.data_interchange`
Models and interfaces for data interchange and report generation. 



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L18"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `DataInterchange`
Base model for data interchange capabilities. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L64"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L54"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `validate_datetime`

```python
validate_datetime(v: Union[str, datetime] = None) → str
```

Validate that value is timestamp or, if empty, set to current datetime 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L45"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `validate_name`

```python
validate_name(v: str) → str
```

Validate name is not empty. 


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L71"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ReportMetadata`
Metadata for security reports. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L126"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L116"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `validate_datetime`

```python
validate_datetime(v: Union[str, datetime] = None) → str
```

Validate that value is timestamp or, if empty, set to current datetime 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L107"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `validate_non_empty_str`

```python
validate_non_empty_str(v: str, info) → str
```

Validate string fields are not empty. 


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L137"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `SecurityReport`
Model for comprehensive security reports. 


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

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L169"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `add_finding`

```python
add_finding(finding: BaseFinding) → None
```

Add a finding to the report. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L203"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `export`

```python
export(
    format: ExportFormat = <ExportFormat.JSON: 'json'>
) → Union[str, Dict[str, Any]]
```

Export the report in the specified format. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L256"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `from_json`

```python
from_json(json_data: Union[str, Dict[str, Any]]) → SecurityReport
```

Import a report from JSON data. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L173"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `merge`

```python
merge(other: 'SecurityReport') → None
```

Merge another report into this one. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L64"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L263"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `track_history`

```python
track_history(previous_report: 'SecurityReport') → Dict[str, Any]
```

Compare with a previous report to track changes. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L54"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `validate_datetime`

```python
validate_datetime(v: Union[str, datetime] = None) → str
```

Validate that value is timestamp or, if empty, set to current datetime 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L45"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `validate_name`

```python
validate_name(v: str) → str
```

Validate name is not empty. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/schemas/data_interchange.py#L185"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `validate_scan_type`

```python
validate_scan_type(v: str) → str
```

Validate scan type. 




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
