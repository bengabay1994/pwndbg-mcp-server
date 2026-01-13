"""
Execution Control Tools

This module contains all execution control related MCP tools for pwndbg.
"""

from typing import Optional
from ..session import get_session


def run_binary(args: Optional[str] = None) -> dict:
    """
    Run the loaded binary.

    Args:
        args: Optional command line arguments for the binary

    Returns:
        Execution output
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.run(args)
        return {
            "status": "running",
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def continue_execution() -> dict:
    """
    Continue program execution until the next breakpoint or signal.

    Returns:
        Execution output
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.continue_execution()
        return {
            "status": "continued",
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def step_instruction() -> dict:
    """
    Execute a single instruction (step into calls).

    Returns:
        Current context after stepping
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("stepi")
        return {
            "status": "stepped",
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def step_over() -> dict:
    """
    Step over the current instruction (don't enter calls).

    Returns:
        Current context after stepping
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("nexti")
        return {
            "status": "stepped",
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def next_call() -> dict:
    """
    Continue execution until the next call instruction.
    Uses pwndbg's nextcall command.

    Returns:
        Output showing where execution stopped
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("nextcall")
        return {
            "status": "stopped_at_call",
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def next_ret() -> dict:
    """
    Continue execution until the next return instruction.
    Uses pwndbg's nextret command.

    Returns:
        Output showing where execution stopped
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("nextret")
        return {
            "status": "stopped_at_ret",
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def next_syscall() -> dict:
    """
    Continue execution until the next syscall instruction.
    Uses pwndbg's nextsyscall command.

    Returns:
        Output showing where execution stopped
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("nextsyscall")
        return {
            "status": "stopped_at_syscall",
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def finish_function() -> dict:
    """
    Continue execution until the current function returns.

    Returns:
        Output including return value
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("finish")
        return {
            "status": "finished",
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
