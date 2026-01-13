# pwndbg-mcp

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An MCP (Model Context Protocol) server that enables LLMs and AI agents to interact with **pwndbg** for exploit development and reverse engineering.

**Disclosure**: This was built 100% by Claude-Code. And was tested to some extent manually by me. Feel free to open an issue if you found a bug (which are likely to exist)

## What is this?

This server allows AI assistants (like Claude, GPT, etc.) to directly control GDB with the pwndbg extension. The AI can:

- Debug binaries and analyze crashes
- Inspect memory, registers, and stack
- Analyze heap structures for exploitation
- Find ROP gadgets and security vulnerabilities
- Perform kernel debugging
- And much more!

## Features

### ✅ Current Features (v0.1.0)

- **Session Management** - Start/stop GDB sessions, attach to processes
- **Execution Control** - Step, continue, breakpoints, run until call/ret/syscall
- **Memory Analysis** - Hexdump, telescope, vmmap, memory search
- **Register Inspection** - Enhanced register display with symbols
- **Heap Analysis** - Full ptmalloc2 heap introspection (chunks, bins, arenas)
- **Binary Security** - checksec, GOT/PLT analysis, canary, PIE base
- **Kernel Debugging** - All 25+ kernel commands (kbase, slab, kdmesg, etc.)
- **Utilities** - Assembler, cyclic patterns, ROP gadget search, memory patching
- **LLM-Friendly Output** - Parsed JSON output instead of terminal formatting

### 🔮 Planned Features

- LLDB support
- Remote debugging (gdbserver, QEMU)
- Multiple concurrent debugging sessions
- Enhanced ROP chain generation
- Exploit template generation

## Prerequisites

- **Python 3.10+**
- **GDB** with pwndbg installed
- **pwndbg** - [Installation instructions](https://pwndbg.re/stable/setup)

## Installation

### Standard Installation (Recommended)

To use this MCP server with tools like Claude Code, Claude Desktop, or Gemini CLI:

```bash
# Clone the repository
git clone https://github.com/bengabay1994/pwndbg-mcp.git
cd pwndbg-mcp

# Install as a global tool (recommended)
uv tool install .
```

This makes the `pwndbg-mcp` command available globally in your PATH.

**Alternative installation methods:**

```bash
# Using pipx
pipx install .

# Using pip
pip install --user .
```

### Verify Installation

```bash
# Check the command is available
which pwndbg-mcp

# Test the server
pwndbg-mcp
```

**Note:** If `pwndbg-mcp` isn't found, ensure `~/.local/bin` is in your PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Getting Started

### Setup claude-code mcp server

#### Using the CLI (Claude Code)

```bash
claude mcp add pwndbg-mcp -- pwndbg-mcp
```

#### Using the CLI (Gemini-CLI)
```bash
gemini mcp add pwndbg-mcp -- pwndbg-mcp
```

### Manual setup


#### Claude Desktop Configuration

Add to your Claude/Gemini/Other mcpServers list:

```json
{
  "mcpServers": {
    "pwndbg": {
      "command": "pwndbg-mcp"
    }
  }
}
```

## Available Tools

### Session Management

| Tool | Description |
|------|-------------|
| `start_session` | Start a new GDB session with an optional binary |
| `attach_process` | Attach to a running process by PID or name |
| `detach_process` | Detach from the current process |
| `close_session` | Close the GDB session |
| `get_session_status` | Get current session state |

### Execution Control

| Tool | Description |
|------|-------------|
| `run_binary` | Run the loaded binary with optional arguments |
| `continue_execution` | Continue until next breakpoint |
| `step_instruction` | Step one instruction (into calls) |
| `step_over` | Step over calls |
| `next_call` | Run until next call instruction |
| `next_ret` | Run until next return |
| `next_syscall` | Run until next syscall |
| `finish_function` | Run until function returns |

### Breakpoints

| Tool | Description |
|------|-------------|
| `set_breakpoint` | Set breakpoint at address or symbol |
| `set_breakpoint_rva` | Set breakpoint at RVA offset (for PIE) |
| `list_breakpoints` | List all breakpoints |
| `delete_breakpoint` | Delete breakpoint(s) |

### Context & Display

| Tool | Description |
|------|-------------|
| `get_context` | Full context: registers, stack, disassembly, backtrace |
| `get_registers` | All register values with symbols |
| `disassemble` | Disassemble at address (nearpc) |
| `get_stack` | Stack contents with dereferencing |

### Memory Examination

| Tool | Description |
|------|-------------|
| `hexdump` | Hexdump memory at address |
| `telescope` | Dereference pointer chain |
| `get_vmmap` | Virtual memory map |
| `search_memory` | Search for patterns in memory |
| `get_xinfo` | Extended info about an address |

### Heap Analysis

| Tool | Description |
|------|-------------|
| `get_heap` | List heap chunks |
| `get_bins` | All bin contents (tcache, fast, small, large, unsorted) |
| `get_fastbins` | Fastbin contents |
| `get_tcachebins` | Tcache bin contents |
| `get_arena` | Arena information |
| `inspect_chunk` | Detailed chunk info |
| `find_fake_fast` | Find fake fastbin candidates |
| `try_free` | Simulate free() behavior |

### Binary Analysis

| Tool | Description |
|------|-------------|
| `checksec` | Security features (RELRO, NX, PIE, canary) |
| `get_got` | Global Offset Table entries |
| `get_plt` | Procedure Linkage Table entries |
| `get_canary` | Stack canary value |
| `get_piebase` | PIE base address |
| `get_elfsections` | ELF section information |
| `get_aslr` | ASLR status |

### Kernel Debugging

| Tool | Description |
|------|-------------|
| `kbase` | Kernel base address |
| `kversion` | Kernel version |
| `kcmdline` | Kernel command line |
| `kdmesg` | Kernel ring buffer |
| `ksyscalls` | Syscall table |
| `ktask` | Kernel tasks |
| `slab_info` | SLUB allocator info |
| `kmod_list` | Loaded kernel modules |
| `kchecksec` | Kernel security options |
| `pagewalk` | Page table walk |

### Utilities

| Tool | Description |
|------|-------------|
| `assemble` | Assemble instructions to bytes |
| `cyclic_pattern` | Generate cyclic pattern |
| `cyclic_find` | Find offset in cyclic pattern |
| `patch_memory` | Patch memory |
| `rop_gadgets` | Search for ROP gadgets |
| `execute_command` | Run any GDB/pwndbg command |


## Architecture

```
┌─────────────────────┐
│   LLM / AI Agent    │
│  (Claude, GPT, etc) │
└──────────┬──────────┘
           │ MCP Protocol
           ▼
┌─────────────────────┐
│   pwndbg-mcp Server │
│  ┌───────────────┐  │
│  │  FastMCP      │  │
│  │  (60+ tools)  │  │
│  └───────┬───────┘  │
│  ┌───────▼───────┐  │
│  │ Session Mgr   │  │
│  │  (pexpect)    │  │
│  └───────┬───────┘  │
│  ┌───────▼───────┐  │
│  │ Output Parsers│  │
│  │ (JSON output) │  │
│  └───────────────┘  │
└──────────┬──────────┘
           │ PTY
           ▼
┌─────────────────────┐
│     GDB + pwndbg    │
└─────────────────────┘
```

## Troubleshooting

### Heap Commands Not Working

**Symptom:** Heap-related tools (`get_heap`, `get_bins`, `get_arena`, etc.) return empty results or error messages like:
```
heap: Fail to resolve the symbol: `mp_`
```

**Cause:** Your system has a newer glibc version (e.g., 2.42+) that pwndbg doesn't have built-in support for yet, and you don't have debug symbols installed.

**Solution:** Install libc debug symbols:
```bash
# Debian/Ubuntu/Kali
sudo apt install libc6-dbg

# Arch Linux
sudo pacman -S glibc-debug

# Fedora/RHEL
sudo dnf debuginfo-install glibc
```

**How to check your glibc version:**
```bash
ldd --version
```
**Note:** The MCP server automatically detects and configures your glibc version, but debug symbols are still required for newer versions.

### pwndbg Not Loading

**Symptom:** Session starts but pwndbg commands are unavailable, or you see:
```
Failed to start GDB with pwndbg loaded
```

**Cause:** pwndbg binary not found in PATH, or not installed correctly.

**Solution:**

1. **Check if pwndbg is installed:**
   ```bash
   which pwndbg
   # OR
   which gdb
   ```

2. **Install pwndbg using the recommended method:**
   ```bash
   curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
   ```

3. **Verify installation:**
   ```bash
   pwndbg
   # You should see pwndbg load with "loaded 212 pwndbg commands"
   ```

### MCP Server Not Connecting

**Symptom:** Claude Code or other MCP clients can't find the pwndbg-mcp server.

**Solution:**

1. **Verify installation:**
   ```bash
   which pwndbg-mcp
   ```

2. **Check PATH includes `~/.local/bin`:**
   ```bash
   echo $PATH | grep .local/bin
   ```

   If not, add to your shell config (`~/.bashrc` or `~/.zshrc`):
   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```

3. **Restart your shell or source the config:**
   ```bash
   source ~/.bashrc  # or ~/.zshrc
   ```

4. **Restart Claude Code completely** for MCP server to reload.

### Testing

The project includes comprehensive test coverage with both unit tests and integration tests.

#### Test Structure

- **Unit Tests** (24 tests): Fast parser tests, no pwndbg required
  - `tests/test_parsers/test_context_parsers.py` - Register parsing
  - `tests/test_parsers/test_heap_parsers.py` - Heap output parsing
  - `tests/test_parsers/test_memory_parsers.py` - Memory inspection parsing
  - `tests/test_parsers/test_misc_parsers.py` - Binary analysis parsing

- **Integration Tests** (5 tests): End-to-end tests with real pwndbg, covers ~40 tools
  - `tests/test_integration_simple.py` - General debugging workflow
  - `tests/test_integration_heap.py` - Heap analysis workflow

#### Running Tests

```bash
# Run all tests (unit + integration)
uv run pytest tests/ -v

# Run only unit tests (fast, ~0.1s, no pwndbg needed)
uv run pytest tests/test_parsers/ -v

# Run only integration tests (~12s, requires pwndbg)
uv run pytest tests/test_integration*.py -v

# Skip integration tests (useful for CI without pwndbg)
uv run pytest tests/ -v -m "not integration"

# Verbose output with detailed progress
uv run pytest tests/test_integration*.py -v -s
```

#### Test Requirements

**For Unit Tests:**
- Python 3.10+
- pytest

**For Integration Tests (automatically skipped if not available):**
- pwndbg or gdb with pwndbg installed
- gcc (for compiling test binaries)
- make

#### Test Coverage

**Tools Tested** (~40 out of ~60 tools, 67% coverage):
- ✅ Session management (start, close, status)
- ✅ Breakpoints (set, list, delete, RVA)
- ✅ Execution control (run, continue, step, next_call, next_ret, next_syscall, finish)
- ✅ Context & registers (get_context, get_registers, disassemble, get_stack)
- ✅ Memory inspection (vmmap, hexdump, telescope, search, xinfo)
- ✅ Heap analysis (get_heap, bins, fastbins, tcache, arena, inspect_chunk, find_fake_fast, try_free)
- ✅ Binary analysis (checksec, GOT, PLT, PIE base, ELF sections, ASLR)

**No Automated Tests** (can be tested manually):
- Kernel debugging tools (kbase, kversion, kdmesg, ksyscalls, etc.)
- Process attachment (attach_process, detach_process)
- Utilities (assemble, cyclic patterns, patch_memory, ROP gadgets)

#### Test Execution Times

- **Unit tests**: ~0.1 seconds
- **Integration tests**: ~12 seconds
- **Total**: ~12 seconds for all 29 tests

#### Test Results

All tests are currently passing:
```
============================= 29 passed in 12.28s ==============================

Unit Tests:        24 tests ✅
Integration Tests:  5 tests ✅
Success Rate:      100% (29/29)
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgements

- [pwndbg](https://github.com/pwndbg/pwndbg) - The amazing GDB/LLDB plugin this server wraps
- [FastMCP](https://github.com/jlowin/fastmcp) - The MCP server framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - The protocol specification