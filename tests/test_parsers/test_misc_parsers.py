"""
Unit tests for miscellaneous command parsers.
"""

import pytest
from pwndbg_mcp.parsers.misc import parse_checksec


class TestParseChecksec:
    """Tests for checksec parser."""
    
    def test_parse_basic_checksec(self, sample_checksec_output):
        """Test parsing basic checksec output."""
        result = parse_checksec(sample_checksec_output)
        
        assert "file" in result
        assert "arch" in result
        
    def test_parse_checksec_security_features(self, sample_checksec_output):
        """Test that security features are parsed."""
        result = parse_checksec(sample_checksec_output)
        
        # These should be booleans
        assert isinstance(result["canary"], bool)
        assert isinstance(result["nx"], bool)
        assert isinstance(result["pie"], bool)
        
    def test_parse_checksec_relro(self, sample_checksec_output):
        """Test RELRO parsing."""
        result = parse_checksec(sample_checksec_output)
        
        assert "relro" in result
        # Should detect Full RELRO
        assert result.get("relro_full") == True
        
    def test_parse_checksec_summary(self, sample_checksec_output):
        """Test that summary is generated."""
        result = parse_checksec(sample_checksec_output)
        
        assert "summary" in result
        assert "weaknesses" in result["summary"]
