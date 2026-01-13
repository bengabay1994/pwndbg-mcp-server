"""
Output parsers for pwndbg commands.

These parsers transform pwndbg's terminal-formatted output into
structured data that LLMs can easily understand and work with.
"""

from .base import strip_ansi, BaseParser
from .memory import (
    parse_hexdump,
    parse_telescope,
    parse_vmmap,
    parse_xinfo,
    parse_search,
)
from .context import (
    parse_context,
    parse_regs,
    parse_stack,
)
from .disasm import (
    parse_nearpc,
    parse_disasm,
    parse_emulate,
)
from .heap import (
    parse_heap,
    parse_bins,
    parse_arena,
    parse_malloc_chunk,
    parse_vis_heap_chunks,
)
from .misc import (
    parse_checksec,
    parse_got,
    parse_plt,
    parse_canary,
    parse_aslr,
    parse_elfsections,
    parse_piebase,
)
from .kernel import (
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

__all__ = [
    "strip_ansi",
    "BaseParser",
    "parse_hexdump",
    "parse_telescope", 
    "parse_vmmap",
    "parse_xinfo",
    "parse_search",
    "parse_context",
    "parse_regs",
    "parse_stack",
    "parse_nearpc",
    "parse_disasm",
    "parse_emulate",
    "parse_heap",
    "parse_bins",
    "parse_arena",
    "parse_malloc_chunk",
    "parse_vis_heap_chunks",
    "parse_checksec",
    "parse_got",
    "parse_plt",
    "parse_canary",
    "parse_aslr",
    "parse_elfsections",
    "parse_piebase",
    "parse_kbase",
    "parse_kversion",
    "parse_kcmdline",
    "parse_kdmesg",
    "parse_ksyscalls",
    "parse_ktask",
    "parse_slab",
    "parse_kmod",
    "parse_kchecksec",
    "parse_pagewalk",
]

