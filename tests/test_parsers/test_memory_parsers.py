"""
Unit tests for memory command parsers.
"""

import pytest
from pwndbg_mcp.parsers.memory import (
    parse_hexdump,
    parse_telescope,
    parse_vmmap,
)


class TestParseVmmap:
    """Tests for vmmap parser."""
    
    def test_parse_basic_vmmap(self, sample_vmmap_output):
        """Test parsing basic vmmap output."""
        result = parse_vmmap(sample_vmmap_output)
        
        assert "regions" in result
        assert "count" in result
        assert result["count"] > 0
        
    def test_parse_vmmap_permissions(self, sample_vmmap_output):
        """Test that permissions are parsed correctly."""
        result = parse_vmmap(sample_vmmap_output)
        
        # Find code section (r-xp)
        code_regions = [r for r in result["regions"] if r.get("executable")]
        assert len(code_regions) > 0
        
    def test_parse_vmmap_paths(self, sample_vmmap_output):
        """Test that paths are extracted."""
        result = parse_vmmap(sample_vmmap_output)
        
        # Should have some regions with paths
        path_regions = [r for r in result["regions"] if r.get("path")]
        assert len(path_regions) > 0
        
    def test_parse_vmmap_special_regions(self, sample_vmmap_output):
        """Test that special regions like heap/stack are found."""
        result = parse_vmmap(sample_vmmap_output)
        
        paths = [r.get("path", "") for r in result["regions"]]
        assert any("[heap]" in p for p in paths)
        assert any("[stack]" in p for p in paths)


class TestParseHexdump:
    """Tests for hexdump parser."""
    
    def test_parse_basic_hexdump(self, sample_hexdump_output):
        """Test parsing basic hexdump output."""
        result = parse_hexdump(sample_hexdump_output)
        
        assert "lines" in result
        assert "total_bytes" in result
        assert len(result["lines"]) > 0
        
    def test_parse_hexdump_addresses(self, sample_hexdump_output):
        """Test that addresses are parsed correctly."""
        result = parse_hexdump(sample_hexdump_output)
        
        for line in result["lines"]:
            assert "address" in line
            assert line["address"].startswith("0x")
            
    def test_parse_hexdump_bytes(self, sample_hexdump_output):
        """Test that hex bytes are parsed."""
        result = parse_hexdump(sample_hexdump_output)
        
        for line in result["lines"]:
            assert "hex_bytes" in line
            assert isinstance(line["hex_bytes"], list)


class TestParseTelescope:
    """Tests for telescope parser."""
    
    def test_parse_basic_telescope(self, sample_telescope_output):
        """Test parsing basic telescope output."""
        result = parse_telescope(sample_telescope_output)
        
        assert "entries" in result
        assert "count" in result
        assert result["count"] > 0
        
    def test_parse_telescope_chain(self, sample_telescope_output):
        """Test that pointer chains are parsed."""
        result = parse_telescope(sample_telescope_output)
        
        # First entry should have a chain
        assert len(result["entries"]) > 0
        first = result["entries"][0]
        assert "chain" in first
        
    def test_parse_telescope_registers(self, sample_telescope_output):
        """Test that register indicators are parsed."""
        result = parse_telescope(sample_telescope_output)
        
        # First entry should show rsp
        first = result["entries"][0]
        assert first.get("registers") == "rsp"
