/**
 * simple.c - Basic test binary for pwndbg-mcp testing
 *
 * Compile with: gcc -g -O0 -fno-stack-protector -no-pie -o simple simple.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global variables for testing
int global_int = 0x41424344;
char global_string[] = "Hello, pwndbg-mcp!";

void inner_function(int x) {
    printf("Inner function called with: %d\n", x);
}

void target_function(void) {
    printf("Target function reached!\n");
    inner_function(42);
}

int vulnerable_function(char *input) {
    char buffer[64];
    
    // Intentionally vulnerable - for testing only!
    strcpy(buffer, input);
    
    printf("Buffer contents: %s\n", buffer);
    printf("Buffer at: %p\n", (void*)buffer);
    
    return strlen(buffer);
}

void heap_operations(void) {
    // Simple heap allocations for basic heap testing
    void *chunk1 = malloc(32);
    void *chunk2 = malloc(64);
    void *chunk3 = malloc(128);
    
    printf("Chunk 1: %p\n", chunk1);
    printf("Chunk 2: %p\n", chunk2);
    printf("Chunk 3: %p\n", chunk3);
    
    // Write some data
    memset(chunk1, 'A', 32);
    memset(chunk2, 'B', 64);
    memset(chunk3, 'C', 128);
    
    // Free in different order
    free(chunk2);
    free(chunk1);
    
    // Allocate again
    void *chunk4 = malloc(32);
    printf("Chunk 4: %p\n", chunk4);
    
    free(chunk3);
    free(chunk4);
}

int main(int argc, char *argv[]) {
    printf("=== pwndbg-mcp Test Binary ===\n");
    printf("PID: %d\n", getpid());
    printf("Global int: 0x%x\n", global_int);
    printf("Global string: %s\n", global_string);
    printf("\n");
    
    // Call target function
    target_function();
    
    // Do some heap operations
    heap_operations();
    
    // If argument provided, call vulnerable function
    if (argc > 1) {
        printf("\nCalling vulnerable function with input...\n");
        int len = vulnerable_function(argv[1]);
        printf("Input length: %d\n", len);
    }
    
    printf("\nDone!\n");
    return 0;
}
