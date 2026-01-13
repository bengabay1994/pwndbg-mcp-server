"""
Parsers for context-related pwndbg commands.

Handles: context, regs, stack, stackf
"""

import re
from typing import Optional
from .base import strip_ansi, split_into_sections


def parse_regs(output: str) -> dict:
    """
    Parse regs command output.
    
    Example input:
    *RAX  0x0
    *RBX  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2c0 —▸ ...
     RCX  0x555555555190 (__libc_csu_init) ◂— endbr64
    
    Returns:
        Dictionary with register values
    """
    clean = strip_ansi(output)
    registers = {}
    
    # Pattern: [*] REG_NAME  value [optional chain/symbol]
    # The * indicates the register changed since last stop
    pattern = re.compile(
        r'([*\s])'  # changed indicator
        r'([A-Z0-9]+)\s+'  # register name
        r'(0x[0-9a-fA-F]+|[0-9]+)'  # value
        r'(.*)$'  # rest (symbols, chains)
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            changed = match.group(1) == '*'
            name = match.group(2).upper()
            value_str = match.group(3)
            extra = match.group(4).strip()
            
            # Parse value
            if value_str.startswith('0x'):
                value = int(value_str, 16)
            else:
                value = int(value_str)
            
            # Extract symbol if present
            symbol = None
            symbol_match = re.search(r'\(([^)]+)\)', extra)
            if symbol_match:
                symbol = symbol_match.group(1)
            
            registers[name] = {
                "value": hex(value),
                "decimal": value,
                "changed": changed,
                "symbol": symbol,
                "extra": extra if extra else None
            }
    
    return {
        "registers": registers,
        "count": len(registers)
    }


def parse_stack(output: str) -> dict:
    """
    Parse stack/stackf command output.
    
    Similar to telescope but specifically for stack.
    
    Returns:
        Dictionary with stack entries
    """
    clean = strip_ansi(output)
    entries = []
    
    # Pattern similar to telescope
    pattern = re.compile(
        r'([0-9a-fA-F]+):([0-9a-fA-F]+)[│|]\s*'  # offset
        r'(\S*)\s*'  # optional register indicator (like rsp)
        r'(0x[0-9a-fA-F]+)'  # address
        r'(.*)$'  # value/chain
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            offset = int(match.group(2), 16)
            reg_indicator = match.group(3).strip() if match.group(3) else None
            address = int(match.group(4), 16)
            value_chain = match.group(5).strip()
            
            # Parse value from chain
            value_match = re.search(r'[—▸◂]+\s*(0x[0-9a-fA-F]+|[0-9]+)', value_chain)
            value = value_match.group(1) if value_match else None
            
            # Check for string or symbol
            string_match = re.search(r"[◂—]\s*['\"](.+?)['\"]", value_chain)
            string_value = string_match.group(1) if string_match else None
            
            entries.append({
                "offset": offset,
                "address": hex(address),
                "register": reg_indicator,
                "value": value,
                "string": string_value,
                "raw": value_chain
            })
    
    return {
        "entries": entries,
        "count": len(entries)
    }


def parse_context(output: str) -> dict:
    """
    Parse the full context command output.
    
    Context includes multiple sections:
    - REGISTERS
    - DISASM / CODE
    - STACK
    - BACKTRACE
    
    Returns:
        Dictionary with all context sections parsed
    """
    clean = strip_ansi(output)
    
    # Define section markers
    section_markers = ["REGISTERS", "DISASM", "CODE", "STACK", "BACKTRACE", "SOURCE"]
    
    # Split into sections
    sections = split_into_sections(output, section_markers)
    
    result = {
        "sections_found": list(sections.keys())
    }
    
    # Parse each section with appropriate parser
    if "REGISTERS" in sections:
        result["registers"] = parse_regs(sections["REGISTERS"])
    
    if "STACK" in sections:
        result["stack"] = parse_stack(sections["STACK"])
    
    if "DISASM" in sections or "CODE" in sections:
        disasm_section = sections.get("DISASM", sections.get("CODE", ""))
        result["disasm"] = parse_disasm_section(disasm_section)
    
    if "BACKTRACE" in sections:
        result["backtrace"] = parse_backtrace(sections["BACKTRACE"])
    
    if "SOURCE" in sections:
        result["source"] = sections["SOURCE"]
    
    return result


def parse_disasm_section(output: str) -> dict:
    """
    Parse disassembly section from context.
    
    Returns:
        Dictionary with disassembly info
    """
    clean = strip_ansi(output)
    instructions = []
    
    # Pattern: [►] address instruction
    pattern = re.compile(
        r'([►\s])\s*'  # current instruction indicator
        r'(0x[0-9a-fA-F]+)\s+'  # address
        r'(\S+)'  # mnemonic
        r'(.*)$'  # operands
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            is_current = '►' in match.group(1)
            address = int(match.group(2), 16)
            mnemonic = match.group(3)
            operands = match.group(4).strip()
            
            instructions.append({
                "address": hex(address),
                "mnemonic": mnemonic,
                "operands": operands,
                "is_current": is_current
            })
    
    return {
        "instructions": instructions,
        "count": len(instructions)
    }


def parse_backtrace(output: str) -> dict:
    """
    Parse backtrace section from context.
    
    Returns:
        Dictionary with backtrace frames
    """
    clean = strip_ansi(output)
    frames = []
    
    # Pattern: #N address in function (args) at file:line
    pattern = re.compile(
        r'#(\d+)\s+'  # frame number
        r'(0x[0-9a-fA-F]+)?\s*'  # optional address
        r'(?:in\s+)?(\S+)?'  # function name
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            frame_num = int(match.group(1))
            address = match.group(2)
            function = match.group(3)
            
            frames.append({
                "frame": frame_num,
                "address": address,
                "function": function,
                "raw": line.strip()
            })
    
    return {
        "frames": frames,
        "depth": len(frames)
    }
