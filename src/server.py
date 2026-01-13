"""
pwndbg MCP Server - Main Entry Point

This module sets up the FastMCP server and registers all pwndbg tools.
"""

from fastmcp import FastMCP

# Import all tool functions
from .tools import (
    # Session Management
    start_session,
    attach_process,
    detach_process,
    close_session,
    get_session_status,
    # Execution Control
    run_binary,
    continue_execution,
    step_instruction,
    step_over,
    next_call,
    next_ret,
    next_syscall,
    finish_function,
    # Breakpoints
    set_breakpoint,
    set_breakpoint_rva,
    list_breakpoints,
    delete_breakpoint,
    # Context & Display
    get_context,
    get_registers,
    disassemble,
    get_stack,
    # Memory Analysis
    hexdump,
    telescope,
    get_vmmap,
    search_memory,
    get_xinfo,
    # Heap Analysis
    get_heap,
    get_bins,
    get_fastbins,
    get_tcachebins,
    get_arena,
    inspect_chunk,
    find_fake_fast,
    try_free,
    # Binary Analysis
    checksec,
    get_got,
    get_plt,
    get_canary,
    get_piebase,
    get_elfsections,
    get_aslr,
    # Kernel Debugging
    kbase,
    kversion,
    kcmdline,
    kdmesg,
    ksyscalls,
    ktask,
    slab_info,
    kmod_list,
    kchecksec,
    pagewalk,
    # Utilities
    assemble,
    cyclic_pattern,
    cyclic_find,
    patch_memory,
    rop_gadgets,
    execute_command,
)

# Create the FastMCP server
mcp = FastMCP("pwndbg-mcp")


# =============================================================================
# Session Management Tools
# =============================================================================

mcp.tool(start_session)
mcp.tool(attach_process)
mcp.tool(detach_process)
mcp.tool(close_session)
mcp.tool(get_session_status)


# =============================================================================
# Execution Control Tools
# =============================================================================

mcp.tool(run_binary)
mcp.tool(continue_execution)
mcp.tool(step_instruction)
mcp.tool(step_over)
mcp.tool(next_call)
mcp.tool(next_ret)
mcp.tool(next_syscall)
mcp.tool(finish_function)


# =============================================================================
# Breakpoint Tools
# =============================================================================

mcp.tool(set_breakpoint)
mcp.tool(set_breakpoint_rva)
mcp.tool(list_breakpoints)
mcp.tool(delete_breakpoint)


# =============================================================================
# Context and Display Tools
# =============================================================================

mcp.tool(get_context)
mcp.tool(get_registers)
mcp.tool(disassemble)
mcp.tool(get_stack)


# =============================================================================
# Memory Analysis Tools
# =============================================================================

mcp.tool(hexdump)
mcp.tool(telescope)
mcp.tool(get_vmmap)
mcp.tool(search_memory)
mcp.tool(get_xinfo)


# =============================================================================
# Heap Analysis Tools
# =============================================================================

mcp.tool(get_heap)
mcp.tool(get_bins)
mcp.tool(get_fastbins)
mcp.tool(get_tcachebins)
mcp.tool(get_arena)
mcp.tool(inspect_chunk)
mcp.tool(find_fake_fast)
mcp.tool(try_free)


# =============================================================================
# Binary Analysis Tools
# =============================================================================

mcp.tool(checksec)
mcp.tool(get_got)
mcp.tool(get_plt)
mcp.tool(get_canary)
mcp.tool(get_piebase)
mcp.tool(get_elfsections)
mcp.tool(get_aslr)


# =============================================================================
# Kernel Debugging Tools
# =============================================================================

mcp.tool(kbase)
mcp.tool(kversion)
mcp.tool(kcmdline)
mcp.tool(kdmesg)
mcp.tool(ksyscalls)
mcp.tool(ktask)
mcp.tool(slab_info)
mcp.tool(kmod_list)
mcp.tool(kchecksec)
mcp.tool(pagewalk)


# =============================================================================
# Utility Tools
# =============================================================================

mcp.tool(assemble)
mcp.tool(cyclic_pattern)
mcp.tool(cyclic_find)
mcp.tool(patch_memory)
mcp.tool(rop_gadgets)
mcp.tool(execute_command)


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Main entry point for the pwndbg MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
