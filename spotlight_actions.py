# SPDX-License-Identifier: Apache-2.0
"""
IDA action handlers for IDA Spotlight.

This module contains all IDA action handlers and the global UI state including:
- OpenViewHandler: Opens the main Spotlight view
- OpenInspectHandler: Opens the quick inspector
- InspectSyncHereHandler: Syncs inspector to current view
- KBConfigureHandler: Opens KB settings dialog
- Global form references and UI hooks
"""

from typing import Optional

import idaapi
import ida_kernwin

from spotlight_utils import (
    qt_alive,
    is_code_widget,
    widget_title,
    paired_view_titles,
    get_qt_parent,
)
from spotlight_ui import (
    SpotlightViewForm,
    SpotlightInspectForm,
    SpotlightKBSettingsDialog,
)


__all__ = [
    # Form references
    "VIEW_FORM",
    "INSPECT_FORM",
    # Form management
    "ensure_inspect_view",
    # Action handlers
    "OpenViewHandler",
    "OpenInspectHandler",
    "InspectSyncHereHandler",
    "KBConfigureHandler",
    # Registration helpers
    "register_actions",
    "attach_menu_actions",
    "install_ui_hooks",
    "uninstall_ui_hooks",
]


# ----------------------------------------------------------------------
# Global Form References
# ----------------------------------------------------------------------

VIEW_FORM: Optional[SpotlightViewForm] = None
INSPECT_FORM: Optional[SpotlightInspectForm] = None


def _clear_inspect_form() -> None:
    """Clear the global inspect form reference when form closes."""
    global INSPECT_FORM
    INSPECT_FORM = None


def _inspect_at_ea(ea: int) -> None:
    """
    Open the inspector and navigate to the given EA.

    Args:
        ea: The effective address to inspect.
    """
    ensure_inspect_view().update_for_ea(ea, push_history=True)


# Set the callbacks on the classes to avoid circular imports
SpotlightInspectForm.on_close_callback = _clear_inspect_form
SpotlightViewForm.inspect_callback = _inspect_at_ea


def ensure_inspect_view() -> SpotlightInspectForm:
    """
    Get or create the quick inspector form.

    Returns:
        The SpotlightInspectForm instance.
    """
    global INSPECT_FORM
    if INSPECT_FORM is not None and qt_alive(getattr(INSPECT_FORM, "inspector", None)):
        return INSPECT_FORM
    INSPECT_FORM = SpotlightInspectForm()
    INSPECT_FORM.Show("IDA Spotlight Quick Inspector")
    return INSPECT_FORM


# ----------------------------------------------------------------------
# UI Hooks
# ----------------------------------------------------------------------

class SpotlightUIHooks(ida_kernwin.UI_Hooks):
    """Global UI hooks for tracking cursor movement and populating menus."""

    def screen_ea_changed(self, ea: int, *args) -> None:
        """
        Handle screen EA changes to update the inspector.

        Args:
            ea: The new effective address.
            *args: Additional arguments (unused).
        """
        if INSPECT_FORM is None:
            return
        if not qt_alive(getattr(INSPECT_FORM, "inspector", None)):
            return

        try:
            widget = ida_kernwin.get_current_widget()
        except Exception:
            widget = None

        title = widget_title(widget) if widget is not None else ""
        INSPECT_FORM.on_screen_ea_changed(title, int(ea))

    def finish_populating_widget_popup(
        self,
        widget: object,
        popup: object,
        ctx: object,
    ) -> None:
        """
        Add Spotlight menu items to code view context menus.

        Args:
            widget: The widget being populated.
            popup: The popup menu handle.
            ctx: The context object.
        """
        try:
            widget_type = ida_kernwin.get_widget_type(widget)
        except Exception:
            return

        if widget_type not in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            return

        ida_kernwin.attach_action_to_popup(
            widget, popup, "ida_spotlight:inspect_sync_here", "IDA Spotlight/"
        )
        ida_kernwin.attach_action_to_popup(
            widget, popup, "ida_spotlight:view_open", "IDA Spotlight/"
        )
        ida_kernwin.attach_action_to_popup(
            widget, popup, "ida_spotlight:inspect_open", "IDA Spotlight/"
        )


# Global hooks instance
_UI_HOOKS: Optional[SpotlightUIHooks] = None


# ----------------------------------------------------------------------
# Action Handlers
# ----------------------------------------------------------------------

class OpenViewHandler(ida_kernwin.action_handler_t):
    """Action handler to open the main Spotlight view."""

    def activate(self, ctx: object) -> int:
        """
        Activate the action to open the main view.

        Args:
            ctx: The action context (unused).

        Returns:
            1 to indicate successful activation.
        """
        global VIEW_FORM
        if VIEW_FORM is None:
            VIEW_FORM = SpotlightViewForm()
        VIEW_FORM.Show("IDA Spotlight View")
        return 1

    def update(self, ctx: object) -> int:
        """
        Update the action state.

        Args:
            ctx: The action context (unused).

        Returns:
            AST_ENABLE_ALWAYS to keep the action always enabled.
        """
        return ida_kernwin.AST_ENABLE_ALWAYS


class OpenInspectHandler(ida_kernwin.action_handler_t):
    """Action handler to open the quick inspector."""

    def activate(self, ctx: object) -> int:
        """
        Activate the action to open the inspector.

        Args:
            ctx: The action context (unused).

        Returns:
            1 to indicate successful activation.
        """
        ensure_inspect_view()
        return 1

    def update(self, ctx: object) -> int:
        """
        Update the action state.

        Args:
            ctx: The action context (unused).

        Returns:
            AST_ENABLE_ALWAYS to keep the action always enabled.
        """
        return ida_kernwin.AST_ENABLE_ALWAYS


class InspectSyncHereHandler(ida_kernwin.action_handler_t):
    """Action handler to sync the inspector to the current view."""

    def activate(self, ctx: object) -> int:
        """
        Activate the action to sync the inspector.

        Args:
            ctx: The action context.

        Returns:
            1 to indicate successful activation.
        """
        try:
            source_widget = getattr(ctx, "widget", None) or ida_kernwin.get_current_widget()
        except Exception:
            source_widget = None

        title = widget_title(source_widget) if source_widget is not None else ""
        titles = paired_view_titles(title)

        inspector = ensure_inspect_view()
        inspector.sync_with_titles(titles)
        return 1

    def update(self, ctx: object) -> int:
        """
        Update the action state.

        Args:
            ctx: The action context (unused).

        Returns:
            AST_ENABLE_ALWAYS to keep the action always enabled.
        """
        return ida_kernwin.AST_ENABLE_ALWAYS


class KBConfigureHandler(ida_kernwin.action_handler_t):
    """Action handler to open the KB settings dialog."""

    def activate(self, ctx: object) -> int:
        """
        Activate the action to open KB settings.

        Args:
            ctx: The action context (unused).

        Returns:
            1 to indicate successful activation.
        """
        dialog = SpotlightKBSettingsDialog(get_qt_parent())
        dialog.exec_()
        return 1

    def update(self, ctx: object) -> int:
        """
        Update the action state.

        Args:
            ctx: The action context (unused).

        Returns:
            AST_ENABLE_ALWAYS to keep the action always enabled.
        """
        return ida_kernwin.AST_ENABLE_ALWAYS


# ----------------------------------------------------------------------
# Plugin Registration Helpers
# ----------------------------------------------------------------------

def register_actions() -> None:
    """Register all IDA actions for the plugin."""
    # Main view action
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "ida_spotlight:view",
            "IDA Spotlight View",
            OpenViewHandler(),
            None,
        )
    )

    # Main inspector action
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "ida_spotlight:inspect",
            "IDA Spotlight Inspect",
            OpenInspectHandler(),
            None,
        )
    )

    # Context menu: sync inspector
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "ida_spotlight:inspect_sync_here",
            "Sync IDA Spotlight Inspect to this view",
            InspectSyncHereHandler(),
            None,
        )
    )

    # Context menu: open view
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "ida_spotlight:view_open",
            "IDA Spotlight View",
            OpenViewHandler(),
            None,
        )
    )

    # Context menu: open inspector
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "ida_spotlight:inspect_open",
            "IDA Spotlight Inspect",
            OpenInspectHandler(),
            None,
        )
    )

    # KB configuration action
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "ida_spotlight:kb_configure",
            "Configure Spotlight KB",
            KBConfigureHandler(),
            None,
        )
    )


def attach_menu_actions() -> None:
    """Attach actions to the IDA menu."""
    menu_path = "View/Open subviews/IDA Spotlight/"
    ida_kernwin.attach_action_to_menu(
        menu_path,
        "ida_spotlight:kb_configure",
        ida_kernwin.SETMENU_APP,
    )
    ida_kernwin.attach_action_to_menu(
        menu_path,
        "ida_spotlight:view",
        ida_kernwin.SETMENU_APP,
    )
    ida_kernwin.attach_action_to_menu(
        menu_path,
        "ida_spotlight:inspect",
        ida_kernwin.SETMENU_APP,
    )


def install_ui_hooks() -> None:
    """Install global UI hooks."""
    global _UI_HOOKS
    if _UI_HOOKS is None:
        _UI_HOOKS = SpotlightUIHooks()
        _UI_HOOKS.hook()


def uninstall_ui_hooks() -> None:
    """Uninstall global UI hooks."""
    global _UI_HOOKS
    if _UI_HOOKS is not None:
        try:
            _UI_HOOKS.unhook()
        except Exception:
            pass
        _UI_HOOKS = None
