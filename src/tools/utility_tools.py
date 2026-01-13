"""
Utility Tools

This module contains miscellaneous utility tools for pwndbg.
"""

from typing import Optional
from ..session import get_session


def assemble(instructions: str, arch: str = "amd64") -> dict:
    """
    Assemble instructions into machine code.

    Args:
        instructions: Assembly instructions (semicolon separated for multiple)
        arch: Target architecture (amd64, i386, arm, etc.)

    Returns:
        Assembled bytes
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"asm {instructions}")
        return {"output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def cyclic_pattern(length: int = 100) -> dict:
    """
    Generate a cyclic pattern for finding offsets.

    Args:
        length: Length of the pattern

    Returns:
        Generated cyclic pattern
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"cyclic {length}")
        return {"pattern": output, "length": length}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def cyclic_find(value: str) -> dict:
    """
    Find offset of a value in the cyclic pattern.

    Args:
        value: Value to find (hex or ASCII)

    Returns:
        Offset in the pattern
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"cyclic -l {value}")
        return {"output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def patch_memory(address: str, data: str) -> dict:
    """
    Patch memory with the given data.

    Args:
        address: Address to patch
        data: Data to write (as hex string or assembly)

    Returns:
        Patch status
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"patch {address} {data}")
        return {
            "status": "patched",
            "address": address,
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def rop_gadgets(filter_str: Optional[str] = None) -> dict:
    """
    Search for ROP gadgets.

    Args:
        filter_str: Optional filter for gadgets (e.g., "pop rdi")

    Returns:
        List of ROP gadgets
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        cmd = "rop"
        if filter_str:
            cmd = f"rop --grep {filter_str}"

        output = session.execute(cmd, timeout=60)  # ROP search can be slow
        return {"output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def execute_command(command: str) -> dict:
    """
    Execute an arbitrary GDB/pwndbg command.
    Use this for commands not covered by other tools.

    Args:
        command: The command to execute

    Returns:
        Raw command output
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(command)
        return {"output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}
