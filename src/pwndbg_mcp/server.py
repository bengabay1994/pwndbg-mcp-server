"""
pwndbg MCP Server - Main Entry Point

This module defines the FastMCP server that exposes pwndbg functionality
to LLMs and AI agents through the Model Context Protocol.
"""

from typing import Optional, Any
from fastmcp import FastMCP

from .session import get_session, close_session as close_gdb_session, SessionState
from .parsers import (
    parse_hexdump,
    parse_telescope,
    parse_vmmap,
    parse_xinfo,
    parse_context,
    parse_regs,
    parse_stack,
    parse_nearpc,
    parse_heap,
    parse_bins,
    parse_arena,
    parse_malloc_chunk,
    parse_checksec,
    parse_got,
    parse_plt,
)
from .parsers.misc import parse_canary, parse_aslr, parse_elfsections, parse_piebase
from .parsers.kernel import (
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

# Create the FastMCP server
mcp = FastMCP("pwndbg-mcp")


# =============================================================================
# Session Management Tools
# =============================================================================

@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


# =============================================================================
# Execution Tools
# =============================================================================

@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


# =============================================================================
# Breakpoint Tools
# =============================================================================

@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


# =============================================================================
# Context and Display Tools
# =============================================================================

@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


# =============================================================================
# Memory Tools
# =============================================================================

@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


# =============================================================================
# Heap Tools
# =============================================================================

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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool  
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


# =============================================================================
# Binary Analysis Tools
# =============================================================================

@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


# =============================================================================
# Kernel Debugging Tools
# =============================================================================

@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


# =============================================================================
# Misc Utility Tools
# =============================================================================

@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Main entry point for the pwndbg MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
