# cdxgen captured output

`cdxgen_pypi_requirements.cdx.json` is the file a real cdxgen run wrote, unedited.

- Tool: `@cyclonedx/cdxgen` 12.9.2, installed from npm into an empty prefix
  (`npm install @cyclonedx/cdxgen@12.9.2`), run with Node.js 22.23.3 on Linux x86_64.
- Input: a directory named `proj` holding one file, `requirements.txt`, with the line
  `requests==2.19.0`.
- Command, the same flags the scanner passes (`CdxgenScanner._build_arguments`):

  ```
  cdxgen --output=<file> --spec-version=1.6 --no-install-deps <dir>/proj
  ```

- Exit status 0. The file is a CycloneDX 1.6 document with one component
  (`pkg:pypi/requests@2.19.0`).

The capture holds no host paths: component sources are relative (`../proj/requirements.txt`).
