from pathlib import Path
from automated_security_helper.models.config import ASHConfig
from automated_security_helper.models.asharp_model import ASHARPModel
import json


def generate_schemas():
    """Generate JSON schemas for the models."""
    cur_file_path = Path(__file__)
    # create schemas dir if not existing
    schemas_dir = cur_file_path.parent
    for model in [ASHConfig, ASHARPModel]:
        json_schema_path = schemas_dir.joinpath(f"{model.__name__}.json").resolve()
        schema = model.model_json_schema()
        with open(json_schema_path, "w") as f:
            json.dump(schema, f, indent=2, sort_keys=True)
            # add final new line so pre-commit doesn't see changes on every run
            f.writelines("\n")
    return
