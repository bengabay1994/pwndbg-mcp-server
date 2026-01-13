"""
Session Management Tools

This module contains all session management related MCP tools for pwndbg.
"""

from typing import Optional
from ..session import get_session, close_session as close_gdb_session


def start_session(binary_path: Optional[str] = None) -> dict:
    """
    Start a new GDB debugging session with pwndbg.

    Args:
        binary_path: Optional path to the binary to debug. If not provided,
                     starts GDB without loading a binary.

    Returns:
        Session status information
    """
    session = get_session()

    if session.is_active:
        return {
            "status": "error",
            "message": "A session is already active. Close it first with close_session."
        }

    try:
        output = session.start(binary_path)
        return {
            "status": "started",
            "binary": binary_path,
            "message": "GDB session started successfully",
            "initial_output": output
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


def attach_process(target: str) -> dict:
    """
    Attach to a running process.

    Args:
        target: Process ID (as string or int) or process name to attach to.
                Uses pwndbg's attachp command which handles both.

    Returns:
        Attachment status and process information
    """
    session = get_session()

    try:
        # Try to convert to int if it looks like a PID
        try:
            pid = int(target)
            output = session.attach(pid)
        except ValueError:
            output = session.attach(target)

        return {
            "status": "attached",
            "target": target,
            "output": output
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


def detach_process() -> dict:
    """
    Detach from the currently attached process.

    Returns:
        Detachment status
    """
    session = get_session()

    if not session.is_active:
        return {
            "status": "error",
            "message": "No active session"
        }

    try:
        output = session.detach()
        return {
            "status": "detached",
            "output": output
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


def close_session() -> dict:
    """
    Close the current GDB debugging session.

    Returns:
        Session closure status
    """
    try:
        close_gdb_session()
        return {
            "status": "closed",
            "message": "GDB session closed"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


def get_session_status() -> dict:
    """
    Get the current debugging session status.

    Returns:
        Current session state and information
    """
    session = get_session()
    info = session.info

    return {
        "active": session.is_active,
        "state": info.state.value,
        "binary_path": info.binary_path,
        "pid": info.pid,
        "is_attached": info.is_attached
    }
