"""
Binary Analysis Tools

This module contains all binary analysis and security feature inspection related MCP tools for pwndbg.
"""

from ..session import get_session
from ..parsers import parse_checksec, parse_got, parse_plt
from ..parsers.misc import parse_canary, parse_aslr, parse_elfsections, parse_piebase


def checksec() -> dict:
    """
    Check binary security features (RELRO, Stack Canary, NX, PIE, etc.).

    Returns:
        Parsed security features with recommendations
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("checksec")
        return parse_checksec(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_got() -> dict:
    """
    Get Global Offset Table entries.

    Returns:
        GOT entries with resolved addresses
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("got")
        return parse_got(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_plt() -> dict:
    """
    Get Procedure Linkage Table entries.

    Returns:
        PLT entries with addresses
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("plt")
        return parse_plt(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_canary() -> dict:
    """
    Get the current stack canary value.

    Returns:
        Canary value and related information
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("canary")
        return parse_canary(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_piebase() -> dict:
    """
    Get the PIE base address.

    Returns:
        PIE base address
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("piebase")
        return parse_piebase(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_elfsections() -> dict:
    """
    Get ELF section information.

    Returns:
        List of ELF sections with addresses and sizes
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("elfsections")
        return parse_elfsections(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_aslr() -> dict:
    """
    Check ASLR status.

    Returns:
        ASLR enabled/disabled status
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = session.execute("aslr")
        return parse_aslr(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}
