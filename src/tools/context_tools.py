"""
Context Inspection Tools

This module contains all context and register inspection related MCP tools for pwndbg.
"""

from typing import Optional
from ..session import get_session
from ..parsers import parse_context, parse_regs, parse_nearpc, parse_stack


def get_context() -> dict:
    """
    Get the current debugging context including registers, stack, and disassembly.
    Uses pwndbg's context command.

    Returns:
        Parsed context with registers, stack, disassembly, and backtrace
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("context", strip_ansi=False)
        parsed = parse_context(output)
        parsed["raw"] = session.execute("context")  # Also include stripped version
        return parsed
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_registers() -> dict:
    """
    Get all register values.
    Uses pwndbg's regs command for enhanced output.

    Returns:
        Parsed register values with symbols and change indicators
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("regs", strip_ansi=False)
        return parse_regs(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def disassemble(address: Optional[str] = None, count: int = 10) -> dict:
    """
    Disassemble instructions near an address.
    Uses pwndbg's nearpc command.

    Args:
        address: Address to disassemble from. Defaults to current PC.
        count: Number of instructions to show

    Returns:
        Parsed disassembly with addresses, mnemonics, and operands
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        cmd = f"nearpc {count}"
        if address:
            cmd = f"nearpc {address} {count}"

        output = session.execute(cmd, strip_ansi=False)
        return parse_nearpc(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_stack(count: int = 10) -> dict:
    """
    Get stack contents with pointer dereferencing.

    Args:
        count: Number of stack entries to show

    Returns:
        Parsed stack entries with dereferenced values
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"stack {count}", strip_ansi=False)
        return parse_stack(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}
