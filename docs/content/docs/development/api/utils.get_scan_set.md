<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `utils.get_scan_set`




**Global Variables**
---------------
- **ASH_INCLUSIONS**

---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L22"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `red`

```python
red(msg) → str
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L26"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `green`

```python
green(msg) → str
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L30"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `yellow`

```python
yellow(msg) → str
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L34"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `lightPurple`

```python
lightPurple(msg) → str
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L38"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `purple`

```python
purple(msg) → str
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L42"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `cyan`

```python
cyan(msg) → str
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L46"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gray`

```python
gray(msg) → str
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L50"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `black`

```python
black(msg) → str
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L54"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `debug_echo`

```python
debug_echo(*msg, debug: bool = False) → str
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L65"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_ash_ignorespec_lines`

```python
get_ash_ignorespec_lines(
    path,
    ignorefiles: List[str] = [],
    debug: bool = False
) → List[str]
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L111"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_ash_ignorespec`

```python
get_ash_ignorespec(lines: List[str], debug: bool = False) → PathSpec
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L120"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_files_not_matching_spec`

```python
get_files_not_matching_spec(path, spec, debug: bool = False)
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L144"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `parse_args`

```python
parse_args() → Namespace
```

Parse command line arguments. 



**Returns:**
  Parsed command line arguments. 


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L179"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `scan_set`

```python
scan_set(
    source: str = '/Users/nateferl/WorkGit/github.com/awslabs/ash-github',
    output: Optional[str] = None,
    ignorefile: Optional[list[str]] = None,
    debug: bool = False,
    print_results: bool = False,
    filter_pattern: Optional[Pattern] = None
) → list[str]
```

Get list of files not matching .gitignore underneath source path. 



**Args:**
 
 - <b>`source`</b>:  Path to scan. Defaults to current working directory. 
 - <b>`output`</b>:  Output path to save the ash-ignore-report.txt and ash-scan-set-files-list.txt files. 
 - <b>`ignorefile`</b>:  List of ignore files to use in addition to the standard gitignore. 
 - <b>`debug`</b>:  Enable debug logging. 
 - <b>`print_results`</b>:  Print results to stdout. Defaults to False for library usage. 
 - <b>`filter_pattern`</b>:  Filter results against a re.Pattern. Defaults to returning the full scan set. 



**Returns:**
 List of files not matching ignore specifications. 


---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/get_scan_set.py#L267"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `main`

```python
main() → int
```

Main entry point for CLI usage. 



**Returns:**
  Exit code (0 for success). 




---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
