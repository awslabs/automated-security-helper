import warnings

warnings.warn(
    "automated_security_helper.cli.inspect.sarif_fields is deprecated. "
    "Import from automated_security_helper.utils.sarif_field_analysis instead.",
    DeprecationWarning,
    stacklevel=2,
)

from automated_security_helper.utils.sarif_field_analysis import (  # noqa: F401, E402
    analyze_sarif_fields,
    flatten_sarif_results,
    _flatten_object,
    get_scanner_name_from_path,
)
