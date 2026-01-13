"""
Base parser utilities for pwndbg output.

Provides common functionality for stripping ANSI codes and
basic parsing helpers.
"""

import re
from typing import Optional
from abc import ABC, abstractmethod


# ANSI escape code pattern
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Common patterns
HEX_ADDR = re.compile(r'0x[0-9a-fA-F]+')
HEX_BYTES = re.compile(r'(?:[0-9a-fA-F]{2}\s*)+')


def strip_ansi(text: str) -> str:
    """
    Remove ANSI escape codes from text.
    
    Args:
        text: Text potentially containing ANSI codes
        
    Returns:
        Clean text without ANSI codes
    """
    return ANSI_ESCAPE.sub('', text)


def parse_hex_address(text: str) -> Optional[int]:
    """
    Extract and parse a hex address from text.
    
    Args:
        text: Text containing a hex address
        
    Returns:
        The address as an integer, or None if not found
    """
    match = HEX_ADDR.search(text)
    if match:
        return int(match.group(), 16)
    return None


def parse_all_hex_addresses(text: str) -> list[int]:
    """
    Extract all hex addresses from text.
    
    Args:
        text: Text containing hex addresses
        
    Returns:
        List of addresses as integers
    """
    return [int(m.group(), 16) for m in HEX_ADDR.finditer(text)]


def split_into_sections(text: str, section_markers: list[str]) -> dict[str, str]:
    """
    Split pwndbg output into sections based on markers.
    
    Many pwndbg commands output sections with headers like:
    ─────[ REGISTERS ]─────
    
    Args:
        text: The full output text
        section_markers: List of section names to look for
        
    Returns:
        Dictionary mapping section names to their content
    """
    sections = {}
    current_section = None
    current_content = []
    
    for line in text.split('\n'):
        # Check if this line is a section header
        found_section = None
        for marker in section_markers:
            if marker.upper() in line.upper():
                found_section = marker
                break
        
        if found_section:
            # Save previous section
            if current_section:
                sections[current_section] = '\n'.join(current_content).strip()
            current_section = found_section
            current_content = []
        elif current_section:
            current_content.append(line)
    
    # Save last section
    if current_section:
        sections[current_section] = '\n'.join(current_content).strip()
    
    return sections


class BaseParser(ABC):
    """
    Abstract base class for pwndbg output parsers.
    
    Subclasses implement specific parsing logic for different
    command outputs.
    """
    
    @abstractmethod
    def parse(self, output: str) -> dict:
        """
        Parse pwndbg command output into structured data.
        
        Args:
            output: Raw command output (may contain ANSI codes)
            
        Returns:
            Parsed data as a dictionary
        """
        pass
    
    def clean(self, output: str) -> str:
        """
        Clean output by stripping ANSI codes.
        
        Args:
            output: Raw output
            
        Returns:
            Cleaned output
        """
        return strip_ansi(output)
