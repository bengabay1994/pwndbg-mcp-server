"""
Parsers for heap-related pwndbg commands.

Handles: heap, vis-heap-chunks, bins, fastbins, tcachebins, arena, malloc-chunk
"""

import re
from typing import Optional
from .base import strip_ansi


def parse_heap(output: str) -> dict:
    """
    Parse heap command output.
    
    Example input:
    Allocated chunk | PREV_INUSE
    Addr: 0x555555559000
    Size: 0x290
    
    Free chunk (tcachebins) | PREV_INUSE
    Addr: 0x555555559290
    Size: 0x20
    
    Returns:
        Dictionary with parsed heap chunks
    """
    clean = strip_ansi(output)
    chunks = []
    current_chunk = None
    
    for line in clean.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        # Check for chunk header
        if 'chunk' in line.lower():
            # Save previous chunk
            if current_chunk:
                chunks.append(current_chunk)
            
            # Determine chunk state
            state = "unknown"
            if 'allocated' in line.lower():
                state = "allocated"
            elif 'free' in line.lower():
                state = "free"
            elif 'top' in line.lower():
                state = "top"
            
            # Get bin type if free
            bin_type = None
            if 'tcache' in line.lower():
                bin_type = "tcache"
            elif 'fastbin' in line.lower():
                bin_type = "fastbin"
            elif 'smallbin' in line.lower():
                bin_type = "smallbin"
            elif 'largebin' in line.lower():
                bin_type = "largebin"
            elif 'unsorted' in line.lower():
                bin_type = "unsorted"
            
            # Check flags
            flags = []
            if 'PREV_INUSE' in line:
                flags.append("PREV_INUSE")
            if 'IS_MMAPPED' in line:
                flags.append("IS_MMAPPED")
            if 'NON_MAIN_ARENA' in line:
                flags.append("NON_MAIN_ARENA")
            
            current_chunk = {
                "state": state,
                "bin_type": bin_type,
                "flags": flags,
            }
        
        elif current_chunk:
            # Parse chunk details
            if line.startswith('Addr:'):
                addr_match = re.search(r'0x[0-9a-fA-F]+', line)
                if addr_match:
                    current_chunk["address"] = addr_match.group()
            
            elif line.startswith('Size:'):
                size_match = re.search(r'0x[0-9a-fA-F]+', line)
                if size_match:
                    current_chunk["size"] = int(size_match.group(), 16)
            
            elif 'fd:' in line.lower():
                fd_match = re.search(r'fd:\s*(0x[0-9a-fA-F]+)', line, re.I)
                if fd_match:
                    current_chunk["fd"] = fd_match.group(1)
            
            elif 'bk:' in line.lower():
                bk_match = re.search(r'bk:\s*(0x[0-9a-fA-F]+)', line, re.I)
                if bk_match:
                    current_chunk["bk"] = bk_match.group(1)
    
    # Don't forget the last chunk
    if current_chunk:
        chunks.append(current_chunk)
    
    return {
        "chunks": chunks,
        "total_chunks": len(chunks),
        "allocated": len([c for c in chunks if c.get("state") == "allocated"]),
        "free": len([c for c in chunks if c.get("state") == "free"])
    }


def parse_bins(output: str) -> dict:
    """
    Parse bins command output.
    
    Shows all bin types: tcache, fastbins, unsortedbin, smallbins, largebins
    
    Returns:
        Dictionary with all bin contents
    """
    clean = strip_ansi(output)
    result = {
        "tcachebins": [],
        "fastbins": [],
        "unsortedbin": [],
        "smallbins": [],
        "largebins": [],
    }
    
    current_section = None
    
    for line in clean.split('\n'):
        line_lower = line.lower()
        
        # Detect section
        if 'tcache' in line_lower:
            current_section = "tcachebins"
        elif 'fastbin' in line_lower:
            current_section = "fastbins"
        elif 'unsorted' in line_lower:
            current_section = "unsortedbin"
        elif 'smallbin' in line_lower:
            current_section = "smallbins"
        elif 'largebin' in line_lower:
            current_section = "largebins"
        
        # Parse bin entry
        if current_section and '0x' in line:
            # Pattern: [size/index]: address -> address -> ...
            # or: 0xsize: 0xaddr -> 0xaddr
            addresses = re.findall(r'0x[0-9a-fA-F]+', line)
            
            if len(addresses) >= 2:
                size_or_index = addresses[0]
                chain = addresses[1:]
                
                result[current_section].append({
                    "size": size_or_index,
                    "chain": chain,
                    "count": len(chain)
                })
    
    return result


def parse_arena(output: str) -> dict:
    """
    Parse arena command output.
    
    Returns:
        Dictionary with arena information
    """
    clean = strip_ansi(output)
    result = {
        "address": None,
        "top": None,
        "last_remainder": None,
        "next": None,
        "system_mem": None,
        "max_system_mem": None,
    }
    
    for line in clean.split('\n'):
        if 'Arena' in line or 'arena' in line:
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                result["address"] = addr_match.group()
        
        elif 'top' in line.lower():
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                result["top"] = addr_match.group()
        
        elif 'last_remainder' in line.lower():
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                result["last_remainder"] = addr_match.group()
        
        elif 'next' in line.lower() and 'next_free' not in line.lower():
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                result["next"] = addr_match.group()
        
        elif 'system_mem' in line.lower():
            size_match = re.search(r'0x[0-9a-fA-F]+', line)
            if size_match:
                result["system_mem"] = int(size_match.group(), 16)
    
    return result


def parse_malloc_chunk(output: str) -> dict:
    """
    Parse malloc-chunk command output for a single chunk.
    
    Returns:
        Dictionary with detailed chunk information
    """
    clean = strip_ansi(output)
    result = {
        "address": None,
        "prev_size": None,
        "size": None,
        "actual_size": None,
        "flags": [],
        "fd": None,
        "bk": None,
        "fd_nextsize": None,
        "bk_nextsize": None,
    }
    
    for line in clean.split('\n'):
        line_lower = line.lower()
        
        if 'addr' in line_lower and ':' in line:
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                result["address"] = addr_match.group()
        
        elif 'prev_size' in line_lower:
            size_match = re.search(r'0x[0-9a-fA-F]+', line)
            if size_match:
                result["prev_size"] = int(size_match.group(), 16)
        
        elif 'size' in line_lower and 'prev' not in line_lower and 'next' not in line_lower:
            size_match = re.search(r'0x[0-9a-fA-F]+', line)
            if size_match:
                result["size"] = int(size_match.group(), 16)
                # Calculate actual size (size & ~0x7)
                result["actual_size"] = result["size"] & ~0x7
        
        # Parse flags
        if 'PREV_INUSE' in line:
            result["flags"].append("PREV_INUSE")
        if 'IS_MMAPPED' in line:
            result["flags"].append("IS_MMAPPED")
        if 'NON_MAIN_ARENA' in line:
            result["flags"].append("NON_MAIN_ARENA")
        
        # Parse forward/backward pointers
        if line_lower.startswith('fd') and 'nextsize' not in line_lower:
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                result["fd"] = addr_match.group()
        
        elif line_lower.startswith('bk') and 'nextsize' not in line_lower:
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                result["bk"] = addr_match.group()
    
    return result


def parse_vis_heap_chunks(output: str) -> dict:
    """
    Parse vis-heap-chunks (vis) command output.
    
    This is a visual representation that uses colors to show
    different chunks. We extract the structural information.
    
    Returns:
        Dictionary with heap visualization data
    """
    clean = strip_ansi(output)
    chunks = []
    
    # vis output typically shows addresses on the left with chunk boundaries
    # Pattern: address content [chunk info]
    current_chunk = None
    
    for line in clean.split('\n'):
        # Look for chunk boundary markers
        if '─' in line or '┌' in line or '└' in line:
            # This is a visual separator
            continue
        
        # Extract addresses and chunk info
        addr_match = re.match(r'(0x[0-9a-fA-F]+)', line)
        if addr_match:
            address = addr_match.group(1)
            
            # Check for chunk size/type info
            size_match = re.search(r'\[size[:\s]*(0x[0-9a-fA-F]+)\]', line, re.I)
            if size_match:
                if current_chunk:
                    chunks.append(current_chunk)
                
                current_chunk = {
                    "address": address,
                    "size": int(size_match.group(1), 16),
                    "data_preview": []
                }
            elif current_chunk:
                # This is data within the current chunk
                # Extract hex values
                hex_values = re.findall(r'[0-9a-fA-F]{16}', line)
                if hex_values:
                    current_chunk["data_preview"].extend(hex_values[:4])
    
    if current_chunk:
        chunks.append(current_chunk)
    
    return {
        "chunks": chunks,
        "total_chunks": len(chunks)
    }
