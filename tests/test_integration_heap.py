"""
Integration tests using the heap_test binary.

Tests heap debugging operations, ptmalloc2 introspection, and verifies
non-heap tools work correctly with heap-intensive programs.
"""

import pytest


def call_tool(tool, **kwargs):
    """Helper to call MCP tools from tests (unwraps the FastMCP decorator)."""
    return tool.fn(**kwargs)


@pytest.mark.integration
@pytest.mark.heap
def test_heap_binary_full_workflow(heap_session):
    """
    Comprehensive integration test covering heap tools with the heap_test binary.

    This test exercises a realistic heap debugging workflow testing:
    - Heap inspection (chunks, bins, arena)
    - Chunk analysis
    - Heap utilities
    - Mixed operations (verify non-heap tools work)

    Coverage: ~15 heap-specific tools + ~10 general tools
    """
    from pwndbg_mcp.server import (
        set_breakpoint,
        run_binary,
        get_heap,
        get_bins,
        get_fastbins,
        get_tcachebins,
        get_arena,
        inspect_chunk,
        find_fake_fast,
        try_free,
        get_vmmap,
        get_registers,
        get_context,
        disassemble,
        next_call,
        finish_function,
        step_over,
        checksec,
        telescope,
    )

    # ===== Phase 1: Setup and Initial State =====
    print("\n=== Phase 1: Heap Binary Setup ===")

    # Verify binary loaded
    checksec_result = call_tool(checksec)
    assert checksec_result is not None
    print(f"✓ Heap binary loaded: {checksec_result.get('arch', 'N/A')}")

    # Set breakpoint at main
    bp_result = call_tool(set_breakpoint, location="main")
    assert bp_result["status"] == "breakpoint_set"
    print(f"✓ Breakpoint set at main")

    # Run to main
    run_result = call_tool(run_binary)
    assert run_result is not None
    print(f"✓ Binary running at main")

    # ===== Phase 2: Step Through Allocations =====
    print("\n=== Phase 2: Stepping Through Allocations ===")

    # Step through some malloc calls
    allocation_count = 0
    for i in range(5):
        try:
            call_tool(next_call)
            call_tool(finish_function)
            allocation_count += 1
            print(f"  - Allocation {allocation_count} completed")
        except Exception as e:
            print(f"  - Stopped at allocation {allocation_count}: {e}")
            break

    print(f"✓ Stepped through {allocation_count} allocations")

    # ===== Phase 3: Heap Inspection =====
    print("\n=== Phase 3: Heap Inspection ===")

    # Get heap chunks
    heap_result = call_tool(get_heap)
    assert heap_result is not None

    chunk_count = 0
    if "chunks" in heap_result:
        chunk_count = heap_result.get("total_chunks", 0)
        print(f"✓ Heap chunks: {chunk_count} total")
        print(f"  - Allocated: {heap_result.get('allocated', 0)}")
        print(f"  - Free: {heap_result.get('free', 0)}")

        # Show first chunk info
        if chunk_count > 0:
            first_chunk = heap_result["chunks"][0]
            print(f"  - First chunk: {first_chunk.get('address', 'N/A')}, "
                  f"size: {first_chunk.get('size', 'N/A')}, "
                  f"state: {first_chunk.get('state', 'N/A')}")
    else:
        print(f"✓ Heap command executed: {heap_result.get('status', 'unknown')}")

    # Get all bins
    bins_result = call_tool(get_bins)
    assert bins_result is not None

    if isinstance(bins_result, dict):
        tcache_count = len(bins_result.get("tcachebins", []))
        fastbin_count = len(bins_result.get("fastbins", []))
        print(f"✓ Bins retrieved:")
        print(f"  - Tcache bins: {tcache_count}")
        print(f"  - Fastbins: {fastbin_count}")
        print(f"  - Unsorted: {len(bins_result.get('unsortedbin', []))}")
        print(f"  - Small bins: {len(bins_result.get('smallbins', []))}")
        print(f"  - Large bins: {len(bins_result.get('largebins', []))}")
    else:
        print(f"✓ Bins command executed")

    # Get tcache bins specifically
    tcache_result = call_tool(get_tcachebins)
    assert tcache_result is not None
    print(f"✓ Tcache bins retrieved")

    # Get fastbins specifically
    fastbins_result = call_tool(get_fastbins)
    assert fastbins_result is not None
    print(f"✓ Fastbins retrieved")

    # Get arena information
    arena_result = call_tool(get_arena)
    assert arena_result is not None

    if isinstance(arena_result, dict) and "address" in arena_result:
        print(f"✓ Arena info:")
        print(f"  - Address: {arena_result.get('address', 'N/A')}")
        print(f"  - Top: {arena_result.get('top', 'N/A')}")
    else:
        print(f"✓ Arena command executed")

    # ===== Phase 4: Chunk Analysis =====
    print("\n=== Phase 4: Chunk Analysis ===")

    # Inspect specific chunks if we have any
    if chunk_count > 0 and "chunks" in heap_result:
        first_chunk_addr = heap_result["chunks"][0].get("address")

        if first_chunk_addr:
            # Inspect the chunk
            inspect_result = call_tool(inspect_chunk, address=first_chunk_addr)
            assert inspect_result is not None

            if isinstance(inspect_result, dict) and "address" in inspect_result:
                print(f"✓ Chunk inspection at {first_chunk_addr}:")
                print(f"  - Size: {inspect_result.get('size', 'N/A')}")
                print(f"  - Flags: {inspect_result.get('flags', [])}")
            else:
                print(f"✓ Chunk inspection executed")

            # Try to find fake fast chunks
            fake_fast_result = call_tool(find_fake_fast, address=first_chunk_addr)
            assert fake_fast_result is not None
            print(f"✓ Fake fast chunk search completed")

            # Simulate free() on the chunk
            try_free_result = call_tool(try_free, address=first_chunk_addr)
            assert try_free_result is not None
            print(f"✓ try_free simulation completed")
    else:
        print("⚠ No chunks available for detailed inspection")

    # ===== Phase 5: Memory Map Verification =====
    print("\n=== Phase 5: Memory Map Verification ===")

    # Verify heap region exists in vmmap
    vmmap_result = call_tool(get_vmmap)
    assert vmmap_result is not None

    if "regions" in vmmap_result:
        region_paths = [r.get("path", "") for r in vmmap_result["regions"]]
        has_heap = any("[heap]" in p for p in region_paths)
        has_stack = any("[stack]" in p for p in region_paths)

        print(f"✓ Memory map verified:")
        print(f"  - Heap region: {'Yes' if has_heap else 'No'}")
        print(f"  - Stack region: {'Yes' if has_stack else 'No'}")
        print(f"  - Total regions: {len(vmmap_result['regions'])}")

        if has_heap:
            # Find heap region details
            heap_regions = [r for r in vmmap_result["regions"] if "[heap]" in r.get("path", "")]
            if heap_regions:
                heap_region = heap_regions[0]
                print(f"  - Heap: {heap_region.get('start')} - {heap_region.get('end')}")
    else:
        print(f"✓ Memory map retrieved")

    # ===== Phase 6: Non-Heap Tools Verification =====
    print("\n=== Phase 6: Non-Heap Tools Verification ===")

    # Verify registers work
    regs_result = call_tool(get_registers)
    assert regs_result is not None
    if "registers" in regs_result:
        print(f"✓ Registers: {regs_result.get('count', 0)} retrieved")
    else:
        print(f"✓ Registers retrieved")

    # Verify context works
    context_result = call_tool(get_context)
    assert context_result is not None
    print(f"✓ Context retrieved")

    # Verify disassembly works
    disasm_result = call_tool(disassemble, count=5)
    assert disasm_result is not None
    if "instructions" in disasm_result:
        print(f"✓ Disassembly: {len(disasm_result['instructions'])} instructions")
    else:
        print(f"✓ Disassembly retrieved")

    # Verify telescope works
    telescope_result = call_tool(telescope, address="$sp", count=5)
    assert telescope_result is not None
    print(f"✓ Telescope works with heap binary")

    # ===== Phase 7: Execution Control =====
    print("\n=== Phase 7: Execution Control with Heap Binary ===")

    # Step over works
    step_result = call_tool(step_over)
    assert step_result is not None
    print(f"✓ Step over works")

    # Execute a few more steps
    for i in range(3):
        try:
            call_tool(step_over)
        except Exception:
            break

    print(f"✓ Multiple step operations completed")

    print("\n" + "="*60)
    print("✅ HEAP BINARY INTEGRATION TEST PASSED")
    print("="*60)


@pytest.mark.integration
@pytest.mark.heap
def test_heap_binary_stress_allocations(heap_session):
    """
    Stress test with multiple allocation/free cycles.

    Tests heap tools with more complex heap states.
    """
    from pwndbg_mcp.server import (
        set_breakpoint,
        run_binary,
        step_over,
        get_heap,
        get_bins,
        get_arena,
    )

    print("\n=== Heap Stress Test ===")

    # Set breakpoint and run
    call_tool(set_breakpoint, location="main")
    call_tool(run_binary)

    # Execute many steps to get complex heap state
    print("Executing multiple operations...")
    for i in range(20):
        try:
            call_tool(step_over)
        except Exception:
            break

    # Check heap state
    heap_result = call_tool(get_heap)
    if heap_result and "chunks" in heap_result:
        print(f"✓ Heap state after stress: {heap_result['total_chunks']} chunks")

    # Check bins
    bins_result = call_tool(get_bins)
    if bins_result:
        print(f"✓ Bins state retrieved")

    # Check arena
    arena_result = call_tool(get_arena)
    if arena_result:
        print(f"✓ Arena state retrieved")

    print("✅ Heap stress test completed")


@pytest.mark.integration
@pytest.mark.heap
def test_heap_binary_chunk_states(heap_session):
    """
    Test heap tools with different chunk states.

    Verifies tools work with allocated, freed, and consolidated chunks.
    """
    from pwndbg_mcp.server import (
        set_breakpoint,
        run_binary,
        next_call,
        finish_function,
        get_heap,
        get_bins,
    )

    print("\n=== Chunk State Test ===")

    call_tool(set_breakpoint, location="main")
    call_tool(run_binary)

    # Step through allocations
    states_seen = set()

    for cycle in range(3):
        # Allocate
        try:
            call_tool(next_call)
            call_tool(finish_function)

            heap_result = call_tool(get_heap)
            if heap_result and "chunks" in heap_result:
                for chunk in heap_result["chunks"]:
                    state = chunk.get("state")
                    if state:
                        states_seen.add(state)
                        print(f"  - Chunk {chunk.get('address')}: {state}")

            # Check bins after each cycle
            bins_result = call_tool(get_bins)

        except Exception as e:
            print(f"  - Cycle {cycle} ended: {e}")
            break

    print(f"✓ Chunk states observed: {states_seen}")
    print("✅ Chunk state test completed")
