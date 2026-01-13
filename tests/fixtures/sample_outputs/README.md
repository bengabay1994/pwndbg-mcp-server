# Sample pwndbg outputs for testing

This directory contains sample outputs from pwndbg commands used for parser testing.

## Placeholder Status

The current outputs in `conftest.py` are placeholders/synthetic data that approximate pwndbg's output format. 

To get real outputs:

1. Start GDB with pwndbg
2. Load a test binary
3. Run various commands
4. Copy the output to update the fixtures in `conftest.py`

## Commands to capture

```
context
regs
nearpc
telescope $rsp 10
hexdump $rsp 64
vmmap
heap
bins
checksec
got
```
