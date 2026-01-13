"""
Parsers for memory-related pwndbg commands.

Handles: hexdump, telescope, vmmap, xinfo, search
"""

import re
from typing import Optional
from pydantic import BaseModel

from .base import strip_ansi, parse_hex_address


class HexdumpLine(BaseModel):
    """A single line from hexdump output."""
    address: int
    hex_bytes: list[str]
    ascii: str


class HexdumpResult(BaseModel):
    """Parsed hexdump output."""
    lines: list[HexdumpLine]
    total_bytes: int


def parse_hexdump(output: str) -> dict:
    """
    Parse hexdump command output.
    
    Example input:
    +0000 0x7fffffffe000  00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  │................│
    +0010 0x7fffffffe010  f8 e3 ff ff ff 7f 00 00  00 00 00 00 00 00 00 00  │................│
    
    Returns:
        Dictionary with parsed hexdump data
    """
    clean = strip_ansi(output)
    lines = []
    
    # Pattern: offset address hex_bytes ascii
    pattern = re.compile(
        r'\+[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)\s+'  # offset and address
        r'((?:[0-9a-fA-F]{2}\s+)+)'  # hex bytes
        r'[│|](.+)[│|]'  # ASCII representation
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            address = int(match.group(1), 16)
            hex_str = match.group(2).strip()
            hex_bytes = hex_str.split()
            ascii_repr = match.group(3) if match.group(3) else ""
            
            lines.append({
                "address": hex(address),
                "hex_bytes": hex_bytes,
                "ascii": ascii_repr.strip()
            })
    
    return {
        "lines": lines,
        "total_bytes": len(lines) * 16 if lines else 0
    }


class TelescopeEntry(BaseModel):
    """A single telescope dereference entry."""
    offset: int
    address: int
    value: str
    symbol: Optional[str] = None


def parse_telescope(output: str) -> dict:
    """
    Parse telescope command output.
    
    Example input:
    00:0000│ rsp 0x7fffffffe3f0 —▸ 0x7fffffffe4f8 —▸ 0x7fffffffe724 ◂— '/bin/ls'
    01:0008│     0x7fffffffe3f8 —▸ 0x555555555060 ◂— endbr64
    
    Returns:
        Dictionary with parsed telescope data
    """
    clean = strip_ansi(output)
    entries = []
    
    # Pattern to match telescope lines
    # Format: offset:hex│ [regs] address —▸ chain
    pattern = re.compile(
        r'([0-9a-fA-F]+):([0-9a-fA-F]+)[│|]\s*'  # offset
        r'(\S*)\s*'  # optional register names
        r'(0x[0-9a-fA-F]+)'  # address
        r'(.*)$'  # rest of the line (pointer chain)
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            offset_num = int(match.group(1), 16)
            offset_bytes = int(match.group(2), 16)
            registers = match.group(3).strip() if match.group(3) else None
            address = int(match.group(4), 16)
            chain = match.group(5).strip()
            
            # Parse the pointer chain
            chain_values = []
            for addr_match in re.finditer(r'0x[0-9a-fA-F]+', chain):
                chain_values.append(addr_match.group())
            
            # Extract any string or symbol at the end
            symbol_match = re.search(r"[◂—]\s*['\"]?(.+?)['\"]?\s*$", chain)
            symbol = symbol_match.group(1) if symbol_match else None
            
            entries.append({
                "offset": offset_bytes,
                "address": hex(address),
                "registers": registers if registers else None,
                "chain": chain_values,
                "symbol": symbol
            })
    
    return {
        "entries": entries,
        "count": len(entries)
    }


class VmmapRegion(BaseModel):
    """A memory region from vmmap."""
    start: int
    end: int
    permissions: str
    size: int
    offset: int
    path: Optional[str] = None


def parse_vmmap(output: str) -> dict:
    """
    Parse vmmap command output.
    
    Example input:
    LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
        0x555555554000     0x555555555000 r--p     1000 0      /bin/ls
        0x555555555000     0x555555570000 r-xp    1b000 1000   /bin/ls
    
    Returns:
        Dictionary with parsed vmmap data
    """
    clean = strip_ansi(output)
    regions = []
    
    # Pattern for vmmap lines
    pattern = re.compile(
        r'(0x[0-9a-fA-F]+)\s+'  # start address
        r'(0x[0-9a-fA-F]+)\s+'  # end address
        r'([rwxps-]+)\s+'  # permissions
        r'([0-9a-fA-F]+)\s+'  # size
        r'([0-9a-fA-F]+)\s*'  # offset
        r'(.*)$'  # path (optional)
    )
    
    for line in clean.split('\n'):
        # Skip legend and empty lines
        if 'LEGEND' in line or not line.strip():
            continue
            
        match = pattern.search(line)
        if match:
            start = int(match.group(1), 16)
            end = int(match.group(2), 16)
            perms = match.group(3)
            size = int(match.group(4), 16)
            offset = int(match.group(5), 16)
            path = match.group(6).strip() if match.group(6) else None
            
            regions.append({
                "start": hex(start),
                "end": hex(end),
                "permissions": perms,
                "size": size,
                "offset": offset,
                "path": path,
                "readable": 'r' in perms,
                "writable": 'w' in perms,
                "executable": 'x' in perms,
            })
    
    return {
        "regions": regions,
        "count": len(regions)
    }


def parse_xinfo(output: str) -> dict:
    """
    Parse xinfo command output.
    
    Returns:
        Dictionary with address information
    """
    clean = strip_ansi(output)
    result = {
        "address": None,
        "region": None,
        "symbol": None,
        "permissions": None,
        "offset_from_base": None,
    }
    
    # Extract address
    addr_match = re.search(r'Extended info for (0x[0-9a-fA-F]+)', clean)
    if addr_match:
        result["address"] = addr_match.group(1)
    
    # Extract region/mapping info
    for line in clean.split('\n'):
        if "Mapped Area" in line or "Page" in line:
            result["region"] = line.strip()
        elif "Symbol" in line:
            sym_match = re.search(r'Symbol:\s*(\S+)', line)
            if sym_match:
                result["symbol"] = sym_match.group(1)
        elif "Permissions" in line:
            perm_match = re.search(r'Permissions:\s*(\S+)', line)
            if perm_match:
                result["permissions"] = perm_match.group(1)
    
    return result


def parse_search(output: str) -> dict:
    """
    Parse search command output.
    
    Returns:
        Dictionary with search results
    """
    clean = strip_ansi(output)
    results = []
    
    # Pattern: address value or address in section
    pattern = re.compile(r'(0x[0-9a-fA-F]+)')
    
    for line in clean.split('\n'):
        if line.strip():
            addresses = pattern.findall(line)
            if addresses:
                results.append({
                    "address": addresses[0],
                    "line": line.strip()
                })
    
    return {
        "matches": results,
        "count": len(results)
    }
