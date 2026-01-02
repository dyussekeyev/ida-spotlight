# SPDX-License-Identifier: Apache-2.0
"""
Configuration handling and constants for IDA Spotlight.

This module provides centralized configuration management including:
- Loading and validating the JSON configuration
- Global constants for KB limits and scoring
- Netnode-based per-IDB settings storage
"""

import json
import os
import re
from typing import Any, Dict, List, Pattern, Set, Tuple

import ida_netnode


__all__ = [
    # Configuration loading
    "load_config",
    "default_kb_db_path",
    # Module-level configuration
    "BASE_DIR",
    "SIGNALS",
    "CONFIG",
    "IGNORED_FUNCTIONS",
    "IGNORED_SECTIONS",
    "IGNORED_DLLS",
    # Scoring parameters
    "CONTEXT_BONUS_FACTOR",
    "LIBRARY_SCORE_PENALTY",
    # KB Limits
    "KB_LIMITS",
    "KB_LIMIT_STRONG",
    "KB_LIMIT_IMPORT_OVERLAP",
    "KB_LIMIT_SECTION_OVERLAP",
    "KB_LIMIT_NAME_RECALL",
    "KB_LIMIT_CALLEE_RECALL_PER_CALLEE",
    "KB_LIMIT_CALLEE_RECALL_MAX_CALLEES",
    "KB_LIMIT_MAX_QUERY_IMPORT_FUNCS",
    "KB_LIMIT_MAX_QUERY_SECTIONS",
    # Per-IDB settings
    "KB_NODE_NAME",
    "kb_node",
    "kb_get_setting",
    "kb_set_setting",
    "kb_db_path",
]


# ----------------------------------------------------------------------
# Config loading helpers
# ----------------------------------------------------------------------

def _safe_regex(pattern: str) -> bool:
    """
    Check if a regex pattern is valid.

    Args:
        pattern: The regex pattern string to validate.

    Returns:
        True if the pattern is valid, False otherwise.
    """
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def _normalize_name(name: str) -> str:
    """
    Normalize a name to lowercase for comparison.

    Args:
        name: The name string to normalize.

    Returns:
        The normalized lowercase string.
    """
    return (name or "").strip().lower()


def _normalize_dll_name(name_raw: str) -> str:
    """
    Normalize a DLL name, adding .dll extension if missing.

    Args:
        name_raw: The raw DLL name string.

    Returns:
        The normalized DLL name with extension.
    """
    normalized = _normalize_name(name_raw)
    if not normalized:
        return ""
    if "." in os.path.basename(normalized):
        return normalized
    return normalized + ".dll"


def load_config(base_dir: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Load and parse the spotlight configuration file.

    Args:
        base_dir: The directory containing the config file.

    Returns:
        A tuple of (signals, config) dictionaries.

    Raises:
        FileNotFoundError: If the configuration file is not found.
        json.JSONDecodeError: If the configuration file is invalid JSON.
    """
    config_path = os.path.join(base_dir, "spotlight.json")
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Missing {config_path}")

    with open(config_path, "r", encoding="utf-8") as config_file:
        raw_config = json.load(config_file)

    filters = raw_config.get("filters", {}) or {}

    config: Dict[str, Any] = {
        "context_bonus_factor": float(raw_config.get("context_bonus_factor", 0.15)),
        "library_score_penalty": float(raw_config.get("library_score_penalty", 3.0)),
        "ignored_functions": [
            re.compile(pattern)
            for pattern in filters.get("functions", [])
            if _safe_regex(pattern)
        ],
        "ignored_sections": {
            _normalize_name(section)
            for section in filters.get("sections", [])
            if section
        },
        "ignored_dlls": {
            _normalize_dll_name(dll)
            for dll in filters.get("dlls", [])
            if dll
        },
    }

    kb_limits_raw = raw_config.get("kb_limits", {}) or {}
    config["kb_limits"] = {
        "strong": int(kb_limits_raw.get("strong", 25)),
        "import_overlap": int(kb_limits_raw.get("import_overlap", 50)),
        "section_overlap": int(kb_limits_raw.get("section_overlap", 25)),
        "name_recall": int(kb_limits_raw.get("name_recall", 50)),
        "callee_recall_per_callee": int(kb_limits_raw.get("callee_recall_per_callee", 5)),
        "callee_recall_max_callees": int(kb_limits_raw.get("callee_recall_max_callees", 25)),
        "max_query_import_funcs": int(kb_limits_raw.get("max_query_import_funcs", 200)),
        "max_query_sections": int(kb_limits_raw.get("max_query_sections", 100)),
    }

    signals = raw_config.get("signals", {}) or {}

    return signals, config


def default_kb_db_path() -> str:
    """
    Get the default KB database path.

    Returns:
        The path to the default KB SQLite database.
    """
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    kb_base_dir = os.path.join(appdata, "Hex-Rays", "Ida Pro", "IDA Spotlight")
    os.makedirs(kb_base_dir, exist_ok=True)
    return os.path.join(kb_base_dir, "ida-spotlight-kb.sqlite")


# ----------------------------------------------------------------------
# Module-level configuration
# ----------------------------------------------------------------------

BASE_DIR: str = os.path.dirname(__file__)
SIGNALS: Dict[str, Any]
CONFIG: Dict[str, Any]
SIGNALS, CONFIG = load_config(BASE_DIR)

# Extracted configuration values
IGNORED_FUNCTIONS: List[Pattern[str]] = CONFIG["ignored_functions"]
IGNORED_SECTIONS: Set[str] = CONFIG["ignored_sections"]
IGNORED_DLLS: Set[str] = CONFIG["ignored_dlls"]

# Scoring parameters
CONTEXT_BONUS_FACTOR: float = CONFIG["context_bonus_factor"]
LIBRARY_SCORE_PENALTY: float = CONFIG["library_score_penalty"]

# ----------------------------------------------------------------------
# KB Limits Configuration
# ----------------------------------------------------------------------

KB_LIMITS: Dict[str, int] = CONFIG["kb_limits"]

KB_LIMIT_STRONG: int = KB_LIMITS["strong"]
KB_LIMIT_IMPORT_OVERLAP: int = KB_LIMITS["import_overlap"]
KB_LIMIT_SECTION_OVERLAP: int = KB_LIMITS["section_overlap"]
KB_LIMIT_NAME_RECALL: int = KB_LIMITS["name_recall"]
KB_LIMIT_CALLEE_RECALL_PER_CALLEE: int = KB_LIMITS["callee_recall_per_callee"]
KB_LIMIT_CALLEE_RECALL_MAX_CALLEES: int = KB_LIMITS["callee_recall_max_callees"]
KB_LIMIT_MAX_QUERY_IMPORT_FUNCS: int = KB_LIMITS["max_query_import_funcs"]
KB_LIMIT_MAX_QUERY_SECTIONS: int = KB_LIMITS["max_query_sections"]

# Netnode name for per-IDB settings
KB_NODE_NAME: str = "$ ida_spotlight_kb"


# ----------------------------------------------------------------------
# Per-IDB Settings (via netnode)
# ----------------------------------------------------------------------

def kb_node() -> ida_netnode.netnode:
    """
    Get or create the netnode for KB settings.

    Returns:
        The netnode instance for storing KB settings.
    """
    return ida_netnode.netnode(KB_NODE_NAME, ida_netnode.NETNODE_CREATE)


def kb_get_setting(key: str, default: str = "") -> str:
    """
    Retrieve a string setting from the KB netnode.

    Args:
        key: The setting key name.
        default: Default value if key not found or on error.

    Returns:
        The stored string value or the default.
    """
    try:
        value = kb_node().get(key)
        if value is None:
            return default
        return value.decode("utf-8")
    except Exception:
        return default


def kb_set_setting(key: str, value: str) -> None:
    """
    Store a string setting in the KB netnode.

    Args:
        key: The setting key name.
        value: The string value to store.
    """
    try:
        kb_node().set(key, value.encode("utf-8"))
    except Exception:
        pass


def kb_db_path() -> str:
    """
    Get the KB database path from per-IDB settings.

    Falls back to the default path if no custom path is set.

    Returns:
        The path to the KB SQLite database.
    """
    stored_path = kb_get_setting("db_path", "").strip()
    return stored_path if stored_path else default_kb_db_path()
