# SPDX-License-Identifier: Apache-2.0
"""
IDA Spotlight — Function triage for IDA 9.2+ (IDAPython / PySide6)

Main plugin entry point. This module provides the IDA plugin interface
and delegates to the modular components for actual functionality.

Modules:
    spotlight_config: Configuration handling and constants
    spotlight_utils: Utility functions
    spotlight_kb: Knowledge base database operations
    spotlight_scanner: Function scanning and scoring
    spotlight_ui: UI components
    spotlight_actions: IDA action handlers
"""

import idaapi
import ida_kernwin

from spotlight_scanner import CTX
from spotlight_actions import (
    OpenViewHandler,
    register_actions,
    attach_menu_actions,
    install_ui_hooks,
    uninstall_ui_hooks,
)


# ----------------------------------------------------------------------
# Plugin Class
# ----------------------------------------------------------------------

class IDASpotlightPlugin(idaapi.plugin_t):
    """
    Main IDA plugin class for IDA Spotlight.

    Handles plugin initialization, menu registration, and cleanup.
    """

    flags = idaapi.PLUGIN_KEEP
    wanted_name = "IDA Spotlight"

    def init(self) -> int:
        """
        Initialize the plugin and register all actions.

        Returns:
            PLUGIN_KEEP to keep the plugin loaded.
        """
        try:
            idaapi.msg(
                f"[IDA Spotlight] Loaded spotlight.json (categories={len(CTX.categories)})\n"
            )
        except Exception as e:
            CTX.signals, CTX.categories = {}, []
            ida_kernwin.warning(f"IDA Spotlight: failed to load spotlight.json: {e}")

        try:
            ida_kernwin.create_menu(
                "IDASpotlightMenu", "IDA Spotlight", "View/Open subviews/Strings"
            )
        except Exception:
            ida_kernwin.warning("IDA Spotlight: failed to create IDASpotlightMenu")

        register_actions()
        attach_menu_actions()
        install_ui_hooks()

        return idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        """
        Open the main Spotlight view when plugin is run.

        Args:
            arg: Plugin argument (unused).
        """
        OpenViewHandler().activate(None)

    def term(self) -> None:
        """Clean up when plugin is unloaded."""
        uninstall_ui_hooks()


def PLUGIN_ENTRY() -> IDASpotlightPlugin:
    """
    Plugin entry point for IDA.

    Returns:
        The plugin instance.
    """
    return IDASpotlightPlugin()

