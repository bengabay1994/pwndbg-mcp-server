"""
Unit tests for context command parsers.
"""

import pytest
from pwndbg_mcp.parsers.context import parse_regs


class TestParseRegs:
    """Tests for register parser."""
    
    def test_parse_basic_regs(self, sample_regs_output):
        """Test parsing basic register output."""
        result = parse_regs(sample_regs_output)
        
        assert "registers" in result
        assert "count" in result
        assert result["count"] > 0
        
    def test_parse_register_values(self, sample_regs_output):
        """Test that register values are parsed correctly."""
        result = parse_regs(sample_regs_output)
        
        # Check for common registers
        regs = result["registers"]
        assert "RAX" in regs
        assert "RSP" in regs
        assert "RIP" in regs
        
    def test_parse_register_change_indicator(self, sample_regs_output):
        """Test that change indicators (*) are parsed."""
        result = parse_regs(sample_regs_output)
        
        regs = result["registers"]
        
        # RAX should be marked as changed (has *)
        assert regs["RAX"]["changed"] == True
        
        # RCX should not be marked as changed (no *)
        assert regs["RCX"]["changed"] == False
        
    def test_parse_register_symbols(self, sample_regs_output):
        """Test that symbols are extracted."""
        result = parse_regs(sample_regs_output)
        
        # RIP should have _start symbol
        rip = result["registers"].get("RIP", {})
        assert rip.get("symbol") == "_start"
