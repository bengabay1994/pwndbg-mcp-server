"""
Breakpoint Tools

This module contains all breakpoint management related MCP tools for pwndbg.
"""

from typing import Optional
from ..session import get_session


def set_breakpoint(location: str) -> dict:
    """
    Set a breakpoint at the specified location.

    Args:
        location: Address (0x...), symbol name, or function name

    Returns:
        Breakpoint information
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"break {location}")
        return {
            "status": "breakpoint_set",
            "location": location,
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def set_breakpoint_rva(offset: str) -> dict:
    """
    Set a breakpoint at an RVA offset from the PIE base.
    Uses pwndbg's breakrva command.

    Args:
        offset: RVA offset (e.g., "0x1234" or "1234")

    Returns:
        Breakpoint information
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"breakrva {offset}")
        return {
            "status": "breakpoint_set",
            "rva_offset": offset,
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def list_breakpoints() -> dict:
    """
    List all breakpoints.

    Returns:
        List of breakpoints
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("info breakpoints")
        return {
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def delete_breakpoint(number: Optional[int] = None) -> dict:
    """
    Delete breakpoint(s).

    Args:
        number: Breakpoint number to delete. If None, deletes all breakpoints.

    Returns:
        Deletion status
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        if number is not None:
            output = session.execute(f"delete {number}")
        else:
            output = session.execute("delete")
        return {
            "status": "deleted",
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
