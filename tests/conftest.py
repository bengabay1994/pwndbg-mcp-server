"""
Pytest configuration and fixtures for pwndbg-mcp tests.
"""

import pytest
import subprocess
import shutil
from pathlib import Path


@pytest.fixture(scope="session")
def fixtures_dir():
    """Path to the fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def sample_outputs_dir(fixtures_dir):
    """Path to sample outputs directory."""
    return fixtures_dir / "sample_outputs"


@pytest.fixture(scope="session")
def binaries_dir(fixtures_dir):
    """Path to test binaries directory."""
    return fixtures_dir / "binaries"


@pytest.fixture(scope="session")
def compiled_binaries(binaries_dir, tmp_path_factory):
    """
    Compile test binaries and return paths to them.
    
    Note: This requires gcc to be installed.
    """
    build_dir = tmp_path_factory.mktemp("binaries")
    
    # Check if we can compile
    try:
        result = subprocess.run(
            ["make", "-C", str(binaries_dir), f"BUILDDIR={build_dir}", "all"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            pytest.skip(f"Failed to compile test binaries: {result.stderr}")
    except FileNotFoundError:
        pytest.skip("make or gcc not found - skipping integration tests")
    except subprocess.TimeoutExpired:
        pytest.skip("Compilation timed out")
    
    return {
        "simple": build_dir / "simple",
        "heap_test": build_dir / "heap_test",
    }


@pytest.fixture
def simple_binary(compiled_binaries):
    """Path to the simple test binary."""
    return compiled_binaries["simple"]


@pytest.fixture
def heap_test_binary(compiled_binaries):
    """Path to the heap test binary."""
    return compiled_binaries["heap_test"]


# Sample output fixtures for parser testing

@pytest.fixture
def sample_vmmap_output():
    """Sample vmmap command output."""
    return """LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
    0x555555554000     0x555555555000 r--p     1000 0      /bin/ls
    0x555555555000     0x555555570000 r-xp    1b000 1000   /bin/ls
    0x555555570000     0x555555579000 r--p     9000 1c000  /bin/ls
    0x555555579000     0x55555557c000 r--p     3000 24000  /bin/ls
    0x55555557c000     0x55555557d000 rw-p     1000 27000  /bin/ls
    0x55555557d000     0x5555555a0000 rw-p    23000 0      [heap]
    0x7ffff7d00000     0x7ffff7d28000 r--p    28000 0      /lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7d28000     0x7ffff7ebd000 r-xp   195000 28000  /lib/x86_64-linux-gnu/libc.so.6
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]
"""


@pytest.fixture
def sample_regs_output():
    """Sample regs command output."""
    return """*RAX  0x0
*RBX  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2c0 —▸ 0x555555554000 ◂— 0x10102464c457f
 RCX  0x555555555190 (__libc_csu_init) ◂— endbr64 
 RDX  0x7fffffffe4f8 —▸ 0x7fffffffe758 ◂— 'SHELL=/bin/bash'
*RSI  0x7fffffffe4e8 —▸ 0x7fffffffe724 ◂— '/bin/ls'
*RDI  0x1
 RBP  0x0
*RSP  0x7fffffffe3f0 —▸ 0x7fffffffe4e8 —▸ 0x7fffffffe724 ◂— '/bin/ls'
*RIP  0x555555555060 (_start) ◂— endbr64 
"""


@pytest.fixture
def sample_checksec_output():
    """Sample checksec command output."""
    return """File:     /bin/ls
Arch:     amd64
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
RUNPATH:  No RUNPATH
FORTIFY:  Yes
"""


@pytest.fixture
def sample_hexdump_output():
    """Sample hexdump command output."""
    return """+0000 0x7fffffffe3f0  e8 e4 ff ff ff 7f 00 00  24 e7 ff ff ff 7f 00 00  │........│$.......│
+0010 0x7fffffffe400  00 00 00 00 00 00 00 00  60 50 55 55 55 55 00 00  │........│`PUUUU..│
+0020 0x7fffffffe410  00 d0 ff f7 ff 7f 00 00  00 00 00 00 01 00 00 00  │........│........│
+0030 0x7fffffffe420  e8 e4 ff ff ff 7f 00 00  00 80 00 00 01 00 00 00  │........│........│
"""


@pytest.fixture
def sample_telescope_output():
    """Sample telescope command output."""
    return """00:0000│ rsp 0x7fffffffe3f0 —▸ 0x7fffffffe4e8 —▸ 0x7fffffffe724 ◂— '/bin/ls'
01:0008│     0x7fffffffe3f8 —▸ 0x555555555060 (_start) ◂— endbr64 
02:0010│     0x7fffffffe400 —▸ 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2c0
03:0018│     0x7fffffffe408 ◂— 0x0
04:0020│     0x7fffffffe410 ◂— 0x1
"""


@pytest.fixture
def sample_heap_output():
    """Sample heap command output."""
    return """Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x290

Allocated chunk | PREV_INUSE
Addr: 0x555555559290
Size: 0x30

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x5555555592c0
Size: 0x30

Top chunk | PREV_INUSE
Addr: 0x5555555592f0
Size: 0x20d10
"""


# Integration test fixtures

@pytest.fixture(scope="session")
def pwndbg_available():
    """
    Check if pwndbg is available.
    Skip integration tests if not found.
    """
    if not shutil.which("pwndbg") and not shutil.which("gdb"):
        pytest.skip("pwndbg or gdb not found - skipping integration tests")
    return True


@pytest.fixture
def simple_session(simple_binary, pwndbg_available):
    """
    Start a GDB session with the simple binary.
    Automatically closes on teardown.
    """
    from pwndbg_mcp.server import start_session, close_session

    # Start session - access the underlying function from the MCP tool
    result = start_session.fn(binary_path=str(simple_binary))
    assert result["status"] == "started", f"Failed to start session: {result}"

    yield result

    # Cleanup: close session
    try:
        close_session.fn()
    except Exception:
        pass  # Session might already be closed


@pytest.fixture
def heap_session(heap_test_binary, pwndbg_available):
    """
    Start a GDB session with the heap_test binary.
    Automatically closes on teardown.
    """
    from pwndbg_mcp.server import start_session, close_session

    # Start session - access the underlying function from the MCP tool
    result = start_session.fn(binary_path=str(heap_test_binary))
    assert result["status"] == "started", f"Failed to start session: {result}"

    yield result

    # Cleanup
    try:
        close_session.fn()
    except Exception:
        pass
