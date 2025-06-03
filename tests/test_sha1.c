#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SHA1_BLOCK_SIZE 20

/* Function implemented in sha1.c */
void sha1_buffer(const unsigned char *buffer, const size_t buffer_size, unsigned char output[SHA1_BLOCK_SIZE]);

int main(void) {
    const char *input = "abc";
    unsigned char hash[SHA1_BLOCK_SIZE];

    sha1_buffer((const unsigned char *)input, strlen(input), hash);

    const char *expected = "a9993e364706816aba3e25717850c26c9cd0d89d";
    char result[SHA1_BLOCK_SIZE * 2 + 1];
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) {
        sprintf(result + i * 2, "%02x", hash[i]);
    }
    result[SHA1_BLOCK_SIZE * 2] = '\0';

    if (strcmp(result, expected) != 0) {
        fprintf(stderr, "Test failed\nExpected: %s\nGot: %s\n", expected, result);
        return 1;
    }

    printf("Test passed\n");
    return 0;
}

/*
Compile and run the test with:
    gcc -o test_sha1 tests/test_sha1.c sha1.c && ./test_sha1
*/
