"""JSON serialization utilities for ASHARPModel."""

import json
from pathlib import Path
from typing import Optional
from .asharp_model import ASHARPModel


class ASHARPModelSerializer:
    """Serializer for ASHARPModel instances."""

    @staticmethod
    def save_model(model: ASHARPModel, output_dir: Path) -> None:
        """Save ASHARPModel as JSON alongside aggregated results."""
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Save model as JSON
        json_path = output_dir / "asharp_model.json"
        with open(json_path, "w") as f:
            json.dump(model.dict(), f, indent=2, default=str)

    @staticmethod
    def load_model(json_path: Path) -> Optional[ASHARPModel]:
        """Load ASHARPModel from JSON file."""
        if not json_path.exists():
            return None

        with open(json_path) as f:
            json_data = json.load(f)

        return ASHARPModel.from_json(json_data)
