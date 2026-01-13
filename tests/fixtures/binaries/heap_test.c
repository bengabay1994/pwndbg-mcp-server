/**
 * heap_test.c - Heap operations test binary for pwndbg-mcp testing
 *
 * This binary performs various heap operations to test heap analysis features.
 *
 * Compile with: gcc -g -O0 -fno-stack-protector -no-pie -o heap_test
 * heap_test.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHUNK_COUNT 10

void *chunks[CHUNK_COUNT];

void allocate_chunks(void) {
  printf("=== Allocating chunks ===\n");

  // Various sizes to hit different bins
  size_t sizes[] = {
      0x20,   // tcache/fastbin
      0x30,   // tcache/fastbin
      0x40,   // tcache/fastbin
      0x80,   // tcache/fastbin
      0x100,  // smallbin
      0x200,  // smallbin
      0x400,  // smallbin
      0x800,  // largebin
      0x1000, // largebin
      0x2000, // largebin
  };

  for (int i = 0; i < CHUNK_COUNT; i++) {
    chunks[i] = malloc(sizes[i]);
    printf("Chunk[%d] size=0x%lx at %p\n", i, sizes[i], chunks[i]);

    // Write pattern to chunk
    memset(chunks[i], 'A' + i, sizes[i]);
  }
}

void free_some_chunks(void) {
  printf("\n=== Freeing chunks (creating bins) ===\n");

  // Free every other chunk to create interesting bin states
  for (int i = 0; i < CHUNK_COUNT; i += 2) {
    printf("Freeing chunk[%d] at %p\n", i, chunks[i]);
    free(chunks[i]);
    chunks[i] = NULL;
  }
}

void show_heap_state(void) {
  printf("\n=== Current heap state ===\n");
  for (int i = 0; i < CHUNK_COUNT; i++) {
    if (chunks[i]) {
      printf("Chunk[%d]: %p (allocated)\n", i, chunks[i]);
    } else {
      printf("Chunk[%d]: (freed)\n", i);
    }
  }
}

void reallocate_chunks(void) {
  printf("\n=== Reallocating freed chunks ===\n");

  // Reallocate some chunks - should come from bins
  for (int i = 0; i < CHUNK_COUNT; i += 2) {
    size_t size = 0x20 + (i * 0x10);
    chunks[i] = malloc(size);
    printf("Reallocated chunk[%d] size=0x%lx at %p\n", i, size, chunks[i]);
  }
}

void consolidation_test(void) {
  printf("\n=== Consolidation test ===\n");

  // Allocate adjacent chunks
  void *adj1 = malloc(0x80);
  void *adj2 = malloc(0x80);
  void *adj3 = malloc(0x80);
  void *guard = malloc(0x20); // Prevent consolidation with top

  printf("Adjacent chunks: %p, %p, %p\n", adj1, adj2, adj3);
  printf("Guard chunk: %p\n", guard);

  // Free middle chunk first
  printf("Freeing middle chunk...\n");
  free(adj2);

  // Free first chunk - should consolidate backward
  printf("Freeing first chunk...\n");
  free(adj1);

  // Free third chunk - should consolidate forward
  printf("Freeing third chunk...\n");
  free(adj3);

  free(guard);
}

void tcache_test(void) {
  printf("\n=== Tcache test ===\n");

  void *tc_chunks[8];

  // Fill tcache for a specific size
  printf("Filling tcache (0x30 size)...\n");
  for (int i = 0; i < 8; i++) {
    tc_chunks[i] = malloc(0x28);
  }

  // Free all - should fill tcache
  for (int i = 0; i < 7; i++) {
    free(tc_chunks[i]);
  }

  // The 8th free should go to fastbin
  printf("Freed 7 to tcache, 1 should go to fastbin\n");
  free(tc_chunks[7]);
}

void cleanup(void) {
  printf("\n=== Cleanup ===\n");
  for (int i = 0; i < CHUNK_COUNT; i++) {
    if (chunks[i]) {
      free(chunks[i]);
      chunks[i] = NULL;
    }
  }
  printf("All chunks freed\n");
}

void breakpoint_here(void) {
  // Convenient function to set breakpoint on
  printf("\n>>> Breakpoint location <<<\n");
}

int main(int argc, char *argv[]) {
  printf("=== pwndbg-mcp Heap Test Binary ===\n");
  printf("PID: %d\n\n", getpid());

  breakpoint_here();

  allocate_chunks();
  breakpoint_here();

  free_some_chunks();
  breakpoint_here();

  show_heap_state();

  reallocate_chunks();
  breakpoint_here();

  tcache_test();
  breakpoint_here();

  consolidation_test();
  breakpoint_here();

  cleanup();

  printf("\n=== Test complete ===\n");
  return 0;
}
