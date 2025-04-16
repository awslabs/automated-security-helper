<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `models.aggregation`
Module containing aggregation functionality for security findings. 



---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L9"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `FindingAggregator`
Aggregates and correlates findings from multiple scans. 

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L12"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `__init__`

```python
__init__()
```








---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L16"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `add_finding`

```python
add_finding(finding: BaseFinding) → None
```

Add a finding to be aggregated. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L28"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `deduplicate`

```python
deduplicate() → List[BaseFinding]
```

Remove duplicate findings based on key attributes. 

Deduplication is based on matching: 
- Location information 
- Scanner and rule information 
- Finding title and description 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L58"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `group_by_severity`

```python
group_by_severity() → Dict[str, List[BaseFinding]]
```

Group findings by their severity level. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L48"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `group_by_type`

```python
group_by_type() → Dict[str, List[BaseFinding]]
```

Group findings by their scanner rule ID. 


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L68"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `TrendAnalyzer`
Analyzes finding trends over time. 

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L71"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `__init__`

```python
__init__()
```








---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L75"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `add_scan_findings`

```python
add_scan_findings(scan_time: datetime, findings: List[BaseFinding]) → None
```

Add findings from a scan at a specific time. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L93"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `get_finding_counts_over_time`

```python
get_finding_counts_over_time() → Dict[datetime, int]
```

Get the count of findings at each scan time. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L109"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `get_new_findings`

```python
get_new_findings(
    previous_scan: datetime,
    current_scan: datetime
) → List[BaseFinding]
```

Get findings that appeared in current scan but not in previous scan. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L142"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `get_resolved_findings`

```python
get_resolved_findings(
    previous_scan: datetime,
    current_scan: datetime
) → List[BaseFinding]
```

Get findings that were in previous scan but not in current scan. 

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/models/aggregation.py#L97"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `get_severity_trends`

```python
get_severity_trends() → Dict[str, Dict[datetime, int]]
```

Get finding counts by severity over time. 




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
