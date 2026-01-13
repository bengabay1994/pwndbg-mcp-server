"""
Memory Analysis Tools

This module contains all memory inspection and analysis related MCP tools for pwndbg.
"""

from typing import Optional
from ..session import get_session
from ..parsers import parse_hexdump, parse_telescope, parse_vmmap, parse_xinfo


def hexdump(address: str, count: int = 64) -> dict:
    """
    Hexdump memory at the specified address.

    Args:
        address: Starting address (can be expression like $rsp, 0x1234, etc.)
        count: Number of bytes to dump

    Returns:
        Parsed hexdump with address, hex bytes, and ASCII
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"hexdump {address} {count}")
        return parse_hexdump(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def telescope(address: str, count: int = 10) -> dict:
    """
    Recursively dereference pointers starting at the specified address.

    Args:
        address: Starting address (can be expression like $rsp)
        count: Number of entries to show

    Returns:
        Parsed telescope entries with pointer chains
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"telescope {address} {count}")
        return parse_telescope(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_vmmap(filter_str: Optional[str] = None) -> dict:
    """
    Get the virtual memory map of the process.

    Args:
        filter_str: Optional filter string (e.g., "libc", "heap", "stack")

    Returns:
        Parsed memory regions with addresses, permissions, and paths
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        cmd = "vmmap"
        if filter_str:
            cmd = f"vmmap {filter_str}"

        output = session.execute(cmd)
        return parse_vmmap(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def search_memory(pattern: str, search_type: str = "string") -> dict:
    """
    Search memory for a pattern.

    Args:
        pattern: Pattern to search for
        search_type: Type of search - "string", "bytes", "pointer", "dword", "qword"

    Returns:
        List of matching addresses
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        type_flag = {
            "string": "-s",
            "bytes": "-x",
            "pointer": "-p",
            "dword": "-d",
            "qword": "-q",
        }.get(search_type, "-s")

        output = session.execute(f"search {type_flag} {pattern}")

        # Parse results
        import re
        addresses = re.findall(r'0x[0-9a-fA-F]+', output)

        return {
            "pattern": pattern,
            "type": search_type,
            "matches": addresses,
            "count": len(addresses)
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_xinfo(address: str) -> dict:
    """
    Get extended information about an address.

    Args:
        address: Address to get info about

    Returns:
        Information about the address including region, symbol, permissions
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"xinfo {address}")
        return parse_xinfo(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}
