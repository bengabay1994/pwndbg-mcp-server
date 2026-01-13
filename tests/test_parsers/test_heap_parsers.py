"""
Unit tests for heap command parsers.
"""

import pytest
from pwndbg_mcp.parsers.heap import parse_heap


class TestParseHeap:
    """Tests for heap parser."""
    
    def test_parse_basic_heap(self, sample_heap_output):
        """Test parsing basic heap output."""
        result = parse_heap(sample_heap_output)
        
        assert "chunks" in result
        assert "total_chunks" in result
        assert result["total_chunks"] > 0
        
    def test_parse_heap_chunk_states(self, sample_heap_output):
        """Test that chunk states are parsed correctly."""
        result = parse_heap(sample_heap_output)
        
        # Should have both allocated and free chunks
        assert result["allocated"] > 0
        assert result["free"] > 0
        
    def test_parse_heap_chunk_addresses(self, sample_heap_output):
        """Test that chunk addresses are parsed."""
        result = parse_heap(sample_heap_output)
        
        for chunk in result["chunks"]:
            assert "address" in chunk
            assert chunk["address"].startswith("0x")
            
    def test_parse_heap_chunk_sizes(self, sample_heap_output):
        """Test that chunk sizes are parsed."""
        result = parse_heap(sample_heap_output)
        
        for chunk in result["chunks"]:
            if "size" in chunk:
                assert isinstance(chunk["size"], int)
                
    def test_parse_heap_flags(self, sample_heap_output):
        """Test that flags are parsed."""
        result = parse_heap(sample_heap_output)
        
        # Most chunks should have PREV_INUSE flag
        flag_chunks = [c for c in result["chunks"] if "PREV_INUSE" in c.get("flags", [])]
        assert len(flag_chunks) > 0
        
    def test_parse_heap_bin_types(self, sample_heap_output):
        """Test that bin types are detected for free chunks."""
        result = parse_heap(sample_heap_output)
        
        free_chunks = [c for c in result["chunks"] if c.get("state") == "free"]
        
        # At least one should have a bin type
        bin_types = [c.get("bin_type") for c in free_chunks if c.get("bin_type")]
        assert len(bin_types) > 0
