"""
Parsers for kernel-related pwndbg commands.

Handles: kbase, kversion, kcmdline, kdmesg, ksyscalls, ktask, slab, kmod, etc.
"""

import re
from typing import Optional
from .base import strip_ansi


def parse_kbase(output: str) -> dict:
    """
    Parse kbase command output.
    
    Returns:
        Dictionary with kernel base address
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


def parse_kversion(output: str) -> dict:
    """
    Parse kversion command output.
    
    Returns:
        Dictionary with kernel version information
    """
    clean = strip_ansi(output)
    result = {
        "version": clean.strip(),
        "major": None,
        "minor": None,
        "patch": None,
    }
    
    # Try to extract version numbers
    ver_match = re.search(r'(\d+)\.(\d+)\.(\d+)', clean)
    if ver_match:
        result["major"] = int(ver_match.group(1))
        result["minor"] = int(ver_match.group(2))
        result["patch"] = int(ver_match.group(3))
    
    return result


def parse_kcmdline(output: str) -> dict:
    """
    Parse kcmdline command output.
    
    Returns:
        Dictionary with kernel command line arguments
    """
    clean = strip_ansi(output)
    result = {
        "raw": clean.strip(),
        "args": {}
    }
    
    # Parse key=value pairs
    for arg in clean.split():
        if '=' in arg:
            key, value = arg.split('=', 1)
            result["args"][key] = value
        else:
            result["args"][arg] = True
    
    return result


def parse_kdmesg(output: str) -> dict:
    """
    Parse kdmesg command output.
    
    Returns:
        Dictionary with kernel ring buffer messages
    """
    clean = strip_ansi(output)
    messages = []
    
    # Pattern: [timestamp] message
    pattern = re.compile(r'\[\s*(\d+\.\d+)\]\s*(.*)')
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            messages.append({
                "timestamp": float(match.group(1)),
                "message": match.group(2)
            })
        elif line.strip():
            messages.append({
                "timestamp": None,
                "message": line.strip()
            })
    
    return {
        "messages": messages,
        "count": len(messages)
    }


def parse_ksyscalls(output: str) -> dict:
    """
    Parse ksyscalls command output.
    
    Returns:
        Dictionary with syscall table entries
    """
    clean = strip_ansi(output)
    syscalls = []
    
    # Pattern: number address name
    pattern = re.compile(
        r'(\d+)\s+'  # syscall number
        r'(0x[0-9a-fA-F]+)\s+'  # address
        r'(\S+)'  # name
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            syscalls.append({
                "number": int(match.group(1)),
                "address": match.group(2),
                "name": match.group(3)
            })
    
    return {
        "syscalls": syscalls,
        "count": len(syscalls)
    }


def parse_ktask(output: str) -> dict:
    """
    Parse ktask command output.
    
    Returns:
        Dictionary with kernel task information
    """
    clean = strip_ansi(output)
    tasks = []
    
    # Pattern varies, try to extract PID and command name
    pattern = re.compile(
        r'(?:pid[:\s]*)?(\d+)\s+'  # PID
        r'.*?'  # anything in between
        r'(?:comm[:\s]*)?(\S+)'  # command name
    )
    
    for line in clean.split('\n'):
        if 'pid' in line.lower() or re.search(r'\d+', line):
            # Get PID
            pid_match = re.search(r'\bpid[:\s]*(\d+)', line, re.I)
            if not pid_match:
                pid_match = re.search(r'\b(\d+)\b', line)
            
            comm_match = re.search(r'\bcomm[:\s]*["\']?(\S+)["\']?', line, re.I)
            
            if pid_match:
                tasks.append({
                    "pid": int(pid_match.group(1)),
                    "comm": comm_match.group(1) if comm_match else None,
                    "raw": line.strip()
                })
    
    return {
        "tasks": tasks,
        "count": len(tasks)
    }


def parse_slab(output: str) -> dict:
    """
    Parse slab command output.
    
    Returns:
        Dictionary with SLUB allocator information
    """
    clean = strip_ansi(output)
    caches = []
    
    # Pattern: name size objects slabs
    pattern = re.compile(
        r'(\S+)\s+'  # cache name
        r'(\d+)\s+'  # object size
        r'(\d+)'  # number of objects or slabs
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            caches.append({
                "name": match.group(1),
                "object_size": int(match.group(2)),
                "count": int(match.group(3)),
            })
    
    return {
        "caches": caches,
        "count": len(caches)
    }


def parse_kmod(output: str) -> dict:
    """
    Parse kmod command output.
    
    Returns:
        Dictionary with loaded kernel modules
    """
    clean = strip_ansi(output)
    modules = []
    
    # Pattern: address size name
    pattern = re.compile(
        r'(0x[0-9a-fA-F]+)\s+'  # base address
        r'(0x[0-9a-fA-F]+|\d+)\s+'  # size
        r'(\S+)'  # module name
    )
    
    for line in clean.split('\n'):
        match = pattern.search(line)
        if match:
            size_str = match.group(2)
            size = int(size_str, 16) if size_str.startswith('0x') else int(size_str)
            
            modules.append({
                "base": match.group(1),
                "size": size,
                "name": match.group(3)
            })
    
    return {
        "modules": modules,
        "count": len(modules)
    }


def parse_kchecksec(output: str) -> dict:
    """
    Parse kchecksec command output.
    
    Returns:
        Dictionary with kernel security options
    """
    clean = strip_ansi(output)
    result = {
        "options": {},
        "raw": clean.strip()
    }
    
    for line in clean.split('\n'):
        if ':' in line:
            parts = line.split(':', 1)
            key = parts[0].strip()
            value = parts[1].strip()
            
            # Determine boolean value
            is_enabled = any(x in value.lower() for x in ['enabled', 'yes', 'on', 'true'])
            
            result["options"][key] = {
                "value": value,
                "enabled": is_enabled
            }
    
    return result


def parse_pagewalk(output: str) -> dict:
    """
    Parse pagewalk command output.
    
    Returns:
        Dictionary with page table walk information
    """
    clean = strip_ansi(output)
    result = {
        "virtual_address": None,
        "physical_address": None,
        "page_levels": [],
        "permissions": None,
    }
    
    for line in clean.split('\n'):
        # Look for virtual/physical address mappings
        if 'virtual' in line.lower():
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                result["virtual_address"] = addr_match.group()
        
        elif 'physical' in line.lower():
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                result["physical_address"] = addr_match.group()
        
        # Page table levels (PGD, PUD, PMD, PTE)
        for level in ['PGD', 'PUD', 'PMD', 'PTE', 'P4D']:
            if level in line:
                addr_match = re.search(r'0x[0-9a-fA-F]+', line)
                if addr_match:
                    result["page_levels"].append({
                        "level": level,
                        "address": addr_match.group()
                    })
    
    return result
