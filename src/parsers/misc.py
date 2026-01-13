"""
Parsers for miscellaneous pwndbg commands.

Handles: checksec, got, plt, canary, aslr, elfsections
"""

import re
from typing import Optional
from .base import strip_ansi


def parse_checksec(output: str) -> dict:
    """
    Parse checksec command output.
    
    Example input:
    File:     /bin/ls
    Arch:     amd64
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  No RUNPATH
    
    Returns:
        Dictionary with security features
    """
    clean = strip_ansi(output)
    result = {
        "file": None,
        "arch": None,
        "relro": None,
        "canary": False,
        "nx": False,
        "pie": False,
        "fortify": False,
        "rpath": None,
        "runpath": None,
    }
    
    for line in clean.split('\n'):
        line_lower = line.lower()
        
        if line.startswith('File:'):
            result["file"] = line.split(':', 1)[1].strip()
        
        elif line.startswith('Arch:'):
            result["arch"] = line.split(':', 1)[1].strip()
        
        elif 'relro' in line_lower:
            value = line.split(':', 1)[1].strip() if ':' in line else line
            result["relro"] = value
            result["relro_full"] = 'full' in line_lower
            result["relro_partial"] = 'partial' in line_lower
        
        elif 'stack' in line_lower or 'canary' in line_lower:
            result["canary"] = 'found' in line_lower or 'enabled' in line_lower
        
        elif 'nx' in line_lower:
            result["nx"] = 'enabled' in line_lower
        
        elif 'pie' in line_lower:
            result["pie"] = 'enabled' in line_lower
        
        elif 'fortify' in line_lower:
            result["fortify"] = 'enabled' in line_lower or 'yes' in line_lower
        
        elif 'rpath' in line_lower and 'runpath' not in line_lower:
            value = line.split(':', 1)[1].strip() if ':' in line else None
            result["rpath"] = value if value and value.lower() != 'no rpath' else None
        
        elif 'runpath' in line_lower:
            value = line.split(':', 1)[1].strip() if ':' in line else None
            result["runpath"] = value if value and value.lower() != 'no runpath' else None
    
    # Add summary
    result["summary"] = {
        "is_hardened": result["relro_full"] if "relro_full" in result else False 
                       and result["canary"] 
                       and result["nx"] 
                       and result["pie"],
        "weaknesses": []
    }
    
    if not result.get("relro_full"):
        result["summary"]["weaknesses"].append("No Full RELRO - GOT overwrite possible")
    if not result["canary"]:
        result["summary"]["weaknesses"].append("No stack canary - Buffer overflow easier")
    if not result["nx"]:
        result["summary"]["weaknesses"].append("NX disabled - Shellcode execution possible")
    if not result["pie"]:
        result["summary"]["weaknesses"].append("No PIE - Addresses predictable")
    
    return result


def parse_got(output: str) -> dict:
    """
    Parse got command output.
    
    Example input:
    GOT protection: Full RELRO | GOT functions: 5
    [0x555555557fd8] puts@GLIBC_2.2.5  →  0x7ffff7e4a6a0 (puts)
    [0x555555557fe0] printf@GLIBC_2.2.5  →  0x7ffff7e2e5f0 (printf)
    
    Returns:
        Dictionary with GOT entries
    """
    clean = strip_ansi(output)
    entries = []
    protection = None
    
    for line in clean.split('\n'):
        # Parse protection info
        if 'GOT protection' in line:
            prot_match = re.search(r'GOT protection:\s*([^|]+)', line)
            if prot_match:
                protection = prot_match.group(1).strip()
        
        # Parse GOT entries
        # Pattern: [address] symbol@version → resolved_address (name)
        entry_match = re.search(
            r'\[(0x[0-9a-fA-F]+)\]\s*'  # GOT address
            r'(\S+)'  # symbol name
            r'.*?[→]\s*'  # arrow
            r'(0x[0-9a-fA-F]+)',  # resolved address
            line
        )
        
        if entry_match:
            got_addr = entry_match.group(1)
            symbol = entry_match.group(2)
            resolved = entry_match.group(3)
            
            # Extract just the function name
            func_name = symbol.split('@')[0]
            
            entries.append({
                "got_address": got_addr,
                "symbol": symbol,
                "function": func_name,
                "resolved_address": resolved,
            })
    
    return {
        "protection": protection,
        "entries": entries,
        "count": len(entries)
    }


def parse_plt(output: str) -> dict:
    """
    Parse plt command output.
    
    Returns:
        Dictionary with PLT entries
    """
    clean = strip_ansi(output)
    entries = []
    
    # Pattern: address: symbol
    pattern = re.compile(
        r'(0x[0-9a-fA-F]+):\s*(\S+)'
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            entries.append({
                "address": match.group(1),
                "symbol": match.group(2)
            })
    
    return {
        "entries": entries,
        "count": len(entries)
    }


def parse_canary(output: str) -> dict:
    """
    Parse canary command output.
    
    Example:
    AT_RANDOM = 0x7fffffffea19
    canary value: 0x6f8a2e1d3c4b5a00
    
    Returns:
        Dictionary with canary information
    """
    clean = strip_ansi(output)
    result = {
        "value": None,
        "at_random": None,
        "found": False
    }
    
    for line in clean.split('\n'):
        if 'canary' in line.lower():
            val_match = re.search(r'0x[0-9a-fA-F]+', line)
            if val_match:
                result["value"] = val_match.group()
                result["found"] = True
        
        elif 'AT_RANDOM' in line:
            val_match = re.search(r'0x[0-9a-fA-F]+', line)
            if val_match:
                result["at_random"] = val_match.group()
    
    return result


def parse_aslr(output: str) -> dict:
    """
    Parse aslr command output.
    
    Returns:
        Dictionary with ASLR status
    """
    clean = strip_ansi(output)
    result = {
        "enabled": None,
        "status": clean.strip()
    }
    
    lower = clean.lower()
    if 'on' in lower or 'enabled' in lower:
        result["enabled"] = True
    elif 'off' in lower or 'disabled' in lower:
        result["enabled"] = False
    
    return result


def parse_elfsections(output: str) -> dict:
    """
    Parse elfsections command output.
    
    Returns:
        Dictionary with ELF section information
    """
    clean = strip_ansi(output)
    sections = []
    
    # Pattern: address size name type flags
    pattern = re.compile(
        r'(0x[0-9a-fA-F]+)\s+'  # address
        r'(0x[0-9a-fA-F]+)\s+'  # size
        r'(\S+)'  # name
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            sections.append({
                "address": match.group(1),
                "size": int(match.group(2), 16),
                "name": match.group(3),
            })
    
    return {
        "sections": sections,
        "count": len(sections)
    }


def parse_piebase(output: str) -> dict:
    """
    Parse piebase command output.
    
    Returns:
        Dictionary with PIE base address
    """
    clean = strip_ansi(output)
    result = {
        "base": None,
        "found": False
    }
    
    addr_match = re.search(r'0x[0-9a-fA-F]+', clean)
    if addr_match:
        result["base"] = addr_match.group()
        result["found"] = True
    
    return result
