from pathlib import Path
from automated_security_helper.models.config import ASHConfig
from automated_security_helper.models.asharp_model import ASHARPModel
import json


def generate_schemas():
    """Generate JSON schemas for the models."""
    cur_file_path = Path(__file__)
    # create schemas dir if not existing
    schemas_dir = cur_file_path.parent.parent.joinpath("schemas")
    schemas_dir.mkdir(exist_ok=True)
    for model in [ASHConfig, ASHARPModel]:
        json_schema_path = schemas_dir.joinpath(f"{model.__name__}.json").resolve()
        schema = model.model_json_schema()
        with open(json_schema_path, "w") as f:
            json.dump(schema, f)
    return
