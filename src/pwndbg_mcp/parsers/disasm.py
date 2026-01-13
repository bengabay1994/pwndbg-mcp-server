"""
Parsers for disassembly-related pwndbg commands.

Handles: nearpc, disasm, emulate
"""

import re
from typing import Optional
from .base import strip_ansi


def parse_nearpc(output: str) -> dict:
    """
    Parse nearpc command output.
    
    Example input:
     ► 0x555555555149 <main>       endbr64 
       0x55555555514d <main+4>     push   rbp
       0x55555555514e <main+5>     mov    rbp, rsp
       0x555555555151 <main+8>     sub    rsp, 0x10
    
    Returns:
        Dictionary with parsed disassembly
    """
    clean = strip_ansi(output)
    instructions = []
    current_address = None
    
    # Pattern: [► ] address [<symbol+offset>] mnemonic operands [; comment]
    pattern = re.compile(
        r'([►\s])\s*'  # current instruction indicator
        r'(0x[0-9a-fA-F]+)\s*'  # address
        r'(?:<([^>]+)>)?\s*'  # optional symbol
        r'(\S+)'  # mnemonic
        r'(.*)$'  # operands and comments
    )
    
    for line in clean.split('\n'):
        if not line.strip():
            continue
            
        match = pattern.search(line)
        if match:
            is_current = '►' in match.group(1)
            address = int(match.group(2), 16)
            symbol = match.group(3)  # e.g., "main+4"
            mnemonic = match.group(4)
            rest = match.group(5).strip()
            
            # Split operands and comments
            operands = rest
            comment = None
            if ';' in rest:
                parts = rest.split(';', 1)
                operands = parts[0].strip()
                comment = parts[1].strip()
            
            # Parse symbol into name and offset
            sym_name = None
            sym_offset = 0
            if symbol:
                sym_match = re.match(r'(\w+)(?:\+(\d+))?', symbol)
                if sym_match:
                    sym_name = sym_match.group(1)
                    if sym_match.group(2):
                        sym_offset = int(sym_match.group(2))
            
            instruction = {
                "address": hex(address),
                "mnemonic": mnemonic,
                "operands": operands,
                "is_current": is_current,
            }
            
            if sym_name:
                instruction["symbol"] = sym_name
                instruction["symbol_offset"] = sym_offset
            
            if comment:
                instruction["comment"] = comment
            
            if is_current:
                current_address = hex(address)
            
            instructions.append(instruction)
    
    return {
        "instructions": instructions,
        "current_address": current_address,
        "count": len(instructions)
    }


def parse_disasm(output: str) -> dict:
    """
    Parse general disassembly output.
    
    This is a more general parser that works with various
    disassembly formats.
    
    Returns:
        Dictionary with parsed disassembly
    """
    # For now, use the same logic as nearpc
    return parse_nearpc(output)


def parse_emulate(output: str) -> dict:
    """
    Parse emulate command output.
    
    Emulate shows predicted instruction execution with
    register changes.
    
    Returns:
        Dictionary with emulation results
    """
    clean = strip_ansi(output)
    instructions = []
    register_changes = []
    
    # Pattern for emulated instructions
    instr_pattern = re.compile(
        r'(0x[0-9a-fA-F]+)\s+'  # address
        r'(\S+)'  # mnemonic
        r'(.*)$'  # operands
    )
    
    # Pattern for register changes (shown after instructions)
    reg_pattern = re.compile(
        r'([A-Z0-9]+)\s*=>\s*(0x[0-9a-fA-F]+)'
    )
    
    for line in clean.split('\n'):
        if not line.strip():
            continue
        
        # Check for instruction
        instr_match = instr_pattern.search(line)
        if instr_match:
            instructions.append({
                "address": instr_match.group(1),
                "mnemonic": instr_match.group(2),
                "operands": instr_match.group(3).strip()
            })
        
        # Check for register changes
        reg_matches = reg_pattern.findall(line)
        for reg, value in reg_matches:
            register_changes.append({
                "register": reg,
                "new_value": value
            })
    
    return {
        "instructions": instructions,
        "register_changes": register_changes,
        "instruction_count": len(instructions)
    }
