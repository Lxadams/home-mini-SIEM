from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

def load_config(config_path: str = REPO_ROOT / "config" / "config.yaml") -> dict:
    with open(config_path, "r") as f:
        return yaml.safe_load(f)
    

def resolve(path_str: str) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else REPO_ROOT / p
