# Test Binaries

This directory contains source code for test binaries used in pwndbg-mcp testing.

## Building

```bash
make all
```

This will compile all test binaries with debug symbols and common security features disabled for testing purposes.

## Binaries

### simple
A minimal test binary for basic debugging operations.

### heap_test
A program that performs various heap operations for testing heap analysis features.

## Cleaning

```bash
make clean
```

## Note

These binaries are intentionally compiled with security features disabled (`-fno-stack-protector -no-pie`) to facilitate testing of exploit development features. **Do not use these compilation flags in production code.**
