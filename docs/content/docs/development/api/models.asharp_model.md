<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/asharp_model.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `models.asharp_model`




**Global Variables**
---------------
- **ASH_DOCS_URL**
- **ASH_REPO_URL**


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/asharp_model.py#L36"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `ASHARPModel`
Main model class for parsing security scan reports from ASH tooling. 


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

#### <kbd>property</kbd> scanners

Get scanners as Scanner objects for backward compatibility. 



**Returns:**
 
 - <b>`List[Scanner]`</b>:  List of Scanner objects converted from scanners_used data.  Returns empty list if no scanners are defined. 



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/asharp_model.py#L243"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `add_report`

```python
add_report(reporter: str, report: SarifReport | CycloneDXReport | str)
```

Add a report to the model. 



**Args:**
 
 - <b>`report`</b>:  The report to add. Can be a SarifReport, CycloneDXReport, or a JSON string. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/asharp_model.py#L289"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `format`

```python
format(output_formats: List[ExportFormat], output_dir: Path | None = None) → str
```

Format ASH model using specified formatter. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/asharp_model.py#L225"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `from_json`

```python
from_json(json_data: Union[str, Dict[str, Any]]) → ASHARPModel
```

Parse JSON data into an ASHARPModel instance. 



**Args:**
 
 - <b>`json_data`</b>:  Either a JSON string or dictionary containing the report data.  Must include metadata and findings fields. 



**Returns:**
 ASHARPModel instance populated with the report data. 



**Raises:**
 
 - <b>`ValidationError`</b>:  If the JSON data is missing required fields or has invalid values. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/asharp_model.py#L278"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `load_model`

```python
load_model(json_path: Path) → Optional[ForwardRef('ASHARPModel')]
```

Load ASHARPModel from JSON file. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/asharp_model.py#L142"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `model_post_init`

```python
model_post_init(context)
```

Initialize aggregator and trend analyzer with current findings. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/asharp_model.py#L258"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `save_model`

```python
save_model(output_dir: Path) → None
```

Save ASHARPModel as JSON alongside aggregated results. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/asharp_model.py#L132"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `validate_ash_config`

```python
validate_ash_config(v: <built-in function any>)
```








---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
