# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for IDA Spotlight

import json
import os
import re
from typing import Dict, Any, List, Set


# ----------------------------------------------------------------------
# Config loading
# ----------------------------------------------------------------------

def load_signals_and_config(base_dir: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
    path = os.path.join(base_dir, "signals.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    spotlight_cfg = data.get("spotlight", {})
    signals = {k: v for k, v in data.items() if k != "spotlight"}
    return signals, spotlight_cfg


# ----------------------------------------------------------------------
# Normalization helpers
# ----------------------------------------------------------------------

def normalize_name(s: str) -> str:
    return (s or "").strip().lower()


def normalize_dll_name(name_raw: str) -> str:
    n = normalize_name(name_raw)
    if not n:
        return ""
    if "." in os.path.basename(n):
        return n
    return n + ".dll"


# ----------------------------------------------------------------------
# Filters
# ----------------------------------------------------------------------

def build_func_filters(cfg: Dict[str, Any]) -> List[re.Pattern]:
    out = []
    for p in cfg.get("func_filters", []):
        try:
            out.append(re.compile(p))
        except re.error:
            pass
    return out


def is_filtered_func(name: str, filters: List[re.Pattern]) -> bool:
    for r in filters:
        if r.match(name):
            return True
    return False


def build_common_sections(cfg: Dict[str, Any]) -> Set[str]:
    return {normalize_name(x) for x in cfg.get("common_sections", []) if x}


def build_common_import_dlls(cfg: Dict[str, Any]) -> Set[str]:
    out = set()
    for x in cfg.get("common_import_dlls", []):
        nx = normalize_dll_name(x)
        if nx:
            out.add(nx)
    return out


# ----------------------------------------------------------------------
# Defaults
# ----------------------------------------------------------------------

def default_kb_db_path() -> str:
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    base = os.path.join(appdata, "Hex-Rays", "Ida Pro", "IDA Spotlight")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "ida-spotlight-kb.sqlite")
