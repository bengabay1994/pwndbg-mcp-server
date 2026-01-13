"""
Heap Analysis Tools

This module contains all heap analysis and exploitation related MCP tools for pwndbg.
"""

from typing import Optional
from ..session import get_session
from ..parsers import parse_heap, parse_bins, parse_arena, parse_malloc_chunk


def _execute_heap_command_with_fallback(session, command: str) -> str:
    """
    Execute a pwndbg heap command with automatic fallback to forced heuristic resolution.

    If pwndbg recommends using 'set resolve-heap-via-heuristic force', this function
    automatically applies it and retries the command. This makes heap commands work
    on newer glibc versions without requiring version-specific code.

    Args:
        session: Active GDB session
        command: The pwndbg heap command to execute

    Returns:
        Command output
    """
    output = session.execute(command)

    # Check if pwndbg recommends forcing heuristic resolution
    if "set resolve-heap-via-heuristic force" in output:
        # Auto-retry with forced heuristic resolution
        session.execute("set resolve-heap-via-heuristic force", timeout=2)
        output = session.execute(command)

    return output


def get_heap(count: Optional[int] = None) -> dict:
    """
    List heap chunks.

    Args:
        count: Optional limit on number of chunks to show

    Returns:
        Parsed heap chunks with addresses, sizes, and states
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        cmd = "heap"
        if count:
            cmd = f"heap {count}"

        output = _execute_heap_command_with_fallback(session, cmd)
        return parse_heap(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_bins() -> dict:
    """
    Get all bin contents (tcache, fastbins, unsortedbin, smallbins, largebins).

    Returns:
        Parsed bin structure with chunk chains
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = _execute_heap_command_with_fallback(session, "bins")
        return parse_bins(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_fastbins() -> dict:
    """
    Get fastbin contents.

    Returns:
        Fastbin entries
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = _execute_heap_command_with_fallback(session, "fastbins")
        return {"output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_tcachebins() -> dict:
    """
    Get tcache bin contents.

    Returns:
        Tcache entries
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = _execute_heap_command_with_fallback(session, "tcachebins")
        return {"output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_arena(arena_addr: Optional[str] = None) -> dict:
    """
    Get arena information.

    Args:
        arena_addr: Optional arena address. Defaults to main arena.

    Returns:
        Parsed arena information
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        cmd = "arena"
        if arena_addr:
            cmd = f"arena {arena_addr}"

        output = _execute_heap_command_with_fallback(session, cmd)
        return parse_arena(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def inspect_chunk(address: str) -> dict:
    """
    Inspect a specific malloc chunk.

    Args:
        address: Address of the chunk

    Returns:
        Detailed chunk information including size, flags, fd/bk pointers
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = _execute_heap_command_with_fallback(session, f"malloc_chunk {address}")
        return parse_malloc_chunk(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def find_fake_fast(address: str) -> dict:
    """
    Find candidate fake fast chunks overlapping the specified address.
    Useful for fastbin attacks.

    Args:
        address: Target address to find fake chunks near

    Returns:
        List of potential fake chunk addresses
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = _execute_heap_command_with_fallback(session, f"find_fake_fast {address}")
        return {"output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def try_free(address: str) -> dict:
    """
    Simulate what would happen if free() was called on an address.
    Helps identify potential issues or exploitable conditions.

    Args:
        address: Address to simulate freeing

    Returns:
        Analysis of what free() would do
    """
    session = get_session()

    if not session.is_active:
        return {"status": "error", "message": "No active session"}

    try:
        output = _execute_heap_command_with_fallback(session, f"try_free {address}")
        return {"output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}
