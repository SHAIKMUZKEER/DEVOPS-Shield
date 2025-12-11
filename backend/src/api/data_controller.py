from fastapi import APIRouter, HTTPException
from pathlib import Path
import json
import os

router = APIRouter()

# Find the datasets directory relative to this file
BASE_DIR = Path(__file__).resolve().parent.parent / "utils" / "datasets"

def load_json(filename: str):
    path = BASE_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Dataset not found at {path}: {filename}")
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read dataset: {e}")

@router.get("/data/real_world_security_scenarios")
def get_security_scenarios():
    return load_json("real_world_security_scenarios.json")

@router.get("/data/blockchain_trust_architecture")
def get_trust_architecture():
    return load_json("blockchain_trust_architecture.json")
