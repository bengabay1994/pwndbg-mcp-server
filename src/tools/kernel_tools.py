"""
Kernel Debugging Tools

This module contains all kernel debugging related MCP tools for pwndbg.
"""

from ..session import get_session
from ..parsers.kernel import (
    parse_kbase,
    parse_kversion,
    parse_kcmdline,
    parse_kdmesg,
    parse_ksyscalls,
    parse_ktask,
    parse_slab,
    parse_kmod,
    parse_kchecksec,
    parse_pagewalk,
)


def kbase() -> dict:
    """
    Find the kernel virtual base address.

    Returns:
        Kernel base address
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("kbase")
        return parse_kbase(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def kversion() -> dict:
    """
    Get kernel version.

    Returns:
        Kernel version information
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("kversion")
        return parse_kversion(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def kcmdline() -> dict:
    """
    Get kernel command line.

    Returns:
        Kernel command line arguments
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("kcmdline")
        return parse_kcmdline(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def kdmesg(count: int = 50) -> dict:
    """
    Get kernel ring buffer (dmesg) contents.

    Args:
        count: Number of lines to retrieve

    Returns:
        Kernel log messages
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("kdmesg")
        parsed = parse_kdmesg(output)
        # Limit output
        if len(parsed["messages"]) > count:
            parsed["messages"] = parsed["messages"][-count:]
            parsed["count"] = count
            parsed["truncated"] = True
        return parsed
    except Exception as e:
        return {"status": "error", "message": str(e)}


def ksyscalls() -> dict:
    """
    Get kernel syscall table.

    Returns:
        Syscall numbers, addresses, and names
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("ksyscalls")
        return parse_ksyscalls(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def ktask() -> dict:
    """
    Display kernel task information.

    Returns:
        List of kernel tasks
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("ktask")
        return parse_ktask(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def slab_info() -> dict:
    """
    Get SLUB allocator information.

    Returns:
        Slab cache information
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("slab")
        return parse_slab(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def kmod_list() -> dict:
    """
    List loaded kernel modules.

    Returns:
        List of kernel modules with base addresses and sizes
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("kmod")
        return parse_kmod(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def kchecksec() -> dict:
    """
    Check kernel security configuration.

    Returns:
        Kernel security options and their status
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("kchecksec")
        return parse_kchecksec(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def pagewalk(address: str) -> dict:
    """
    Perform a page table walk for an address.

    Args:
        address: Virtual address to walk

    Returns:
        Page table entries at each level
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute(f"pagewalk {address}")
        return parse_pagewalk(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}
