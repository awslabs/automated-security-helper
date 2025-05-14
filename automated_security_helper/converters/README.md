# Converters

Converters are responsible for converting files in the source directory that are in an un-scannable format into a scannable one.

Currently, ASH includes the following formatters with the core library:

- `jupyter`: Converts Jupyter notebooks (*.ipynb files) into Python.
- `archive`: Extracts archives so the contents can be scanned. NOTE - This does not recursively extract archives within archives at this time.
