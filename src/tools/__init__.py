"""
Tools module - Contains all MCP tool implementations organized by category.
"""

from .session_tools import (
    start_session,
    attach_process,
    detach_process,
    close_session,
    get_session_status,
)

from .execution_tools import (
    run_binary,
    continue_execution,
    step_instruction,
    step_over,
    next_call,
    next_ret,
    next_syscall,
    finish_function,
)

from .breakpoint_tools import (
    set_breakpoint,
    set_breakpoint_rva,
    list_breakpoints,
    delete_breakpoint,
)

from .context_tools import (
    get_context,
    get_registers,
    disassemble,
    get_stack,
)

from .memory_tools import (
    hexdump,
    telescope,
    get_vmmap,
    search_memory,
    get_xinfo,
)

from .heap_tools import (
    get_heap,
    get_bins,
    get_fastbins,
    get_tcachebins,
    get_arena,
    inspect_chunk,
    find_fake_fast,
    try_free,
)

from .binary_tools import (
    checksec,
    get_got,
    get_plt,
    get_canary,
    get_piebase,
    get_elfsections,
    get_aslr,
)

from .kernel_tools import (
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
)

from .utility_tools import (
    assemble,
    cyclic_pattern,
    cyclic_find,
    patch_memory,
    rop_gadgets,
    execute_command,
)

__all__ = [
    # Session
    "start_session",
    "attach_process",
    "detach_process",
    "close_session",
    "get_session_status",
    # Execution
    "run_binary",
    "continue_execution",
    "step_instruction",
    "step_over",
    "next_call",
    "next_ret",
    "next_syscall",
    "finish_function",
    # Breakpoints
    "set_breakpoint",
    "set_breakpoint_rva",
    "list_breakpoints",
    "delete_breakpoint",
    # Context
    "get_context",
    "get_registers",
    "disassemble",
    "get_stack",
    # Memory
    "hexdump",
    "telescope",
    "get_vmmap",
    "search_memory",
    "get_xinfo",
    # Heap
    "get_heap",
    "get_bins",
    "get_fastbins",
    "get_tcachebins",
    "get_arena",
    "inspect_chunk",
    "find_fake_fast",
    "try_free",
    # Binary
    "checksec",
    "get_got",
    "get_plt",
    "get_canary",
    "get_piebase",
    "get_elfsections",
    "get_aslr",
    # Kernel
    "kbase",
    "kversion",
    "kcmdline",
    "kdmesg",
    "ksyscalls",
    "ktask",
    "slab_info",
    "kmod_list",
    "kchecksec",
    "pagewalk",
    # Utilities
    "assemble",
    "cyclic_pattern",
    "cyclic_find",
    "patch_memory",
    "rop_gadgets",
    "execute_command",
]
