#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#if defined(_WIN32)
#include <windows.h>
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

// SHA1 20-byte hash
#define SHA1_BLOCK_SIZE 20

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

DLL_EXPORT void sha1_file(const char *filename, unsigned char output[SHA1_BLOCK_SIZE]);
DLL_EXPORT void sha1_buffer(const unsigned char *buffer, const size_t buffer_size, unsigned char output[SHA1_BLOCK_SIZE]);

#define ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

void SHA1Init(SHA1_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]) {
    uint32_t a, b, c, d, e;
    uint32_t temp;
    uint32_t w[80];
    int t;

    for (t = 0; t < 16; t++) {
        w[t] = ((uint32_t)buffer[t*4+0] << 24) | ((uint32_t)buffer[t*4+1] << 16) | ((uint32_t)buffer[t*4+2] << 8) | ((uint32_t)buffer[t*4+3]);
    }

    for (t = 16; t < 80; t++) {
        w[t] = ROL(w[t-3]^w[t-8]^w[t-14]^w[t-16], 1);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (t = 0; t < 80; t++) {
        if (t < 20)
            temp = (ROL(a, 5) + ((b & c) | ((~b) & d)) + e + w[t] + 0x5A827999);
        else if (t < 40)
            temp = (ROL(a, 5) + (b ^ c ^ d) + e + w[t] + 0x6ED9EBA1);
        else if (t < 60)
            temp = (ROL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[t] + 0x8F1BBCDC);
        else
            temp = (ROL(a, 5) + (b ^ c ^ d) + e + w[t] + 0xCA62C1D6);
        
        e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void SHA1Update(SHA1_CTX *context, const unsigned char *data, uint32_t len) {
    uint32_t i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);

    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else
        i = 0;

    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(unsigned char digest[SHA1_BLOCK_SIZE], SHA1_CTX *context) {
    unsigned char finalcount[8];
    unsigned char c;

    for (int i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i&3))*8)) & 255);
    }

    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0000;
        SHA1Update(context, &c, 1);
    }

    SHA1Update(context, finalcount, 8);
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) {
        digest[i] = (unsigned char)((context->state[i>>2] >> ((3 - (i&3))*8)) & 255);
    }
}

void sha1_file(const char *filename, unsigned char output[SHA1_BLOCK_SIZE]) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    SHA1_CTX context;
    unsigned char buffer[1024];
    size_t len;

    SHA1Init(&context);
    while ((len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA1Update(&context, buffer, (uint32_t)len);
    }
    fclose(file);

    SHA1Final(output, &context);
}

void sha1_buffer(const unsigned char *buffer, const size_t buffer_size, unsigned char output[SHA1_BLOCK_SIZE]) {
    SHA1_CTX context;
    SHA1Init(&context);
    SHA1Update(&context, buffer, (uint32_t)buffer_size);
    SHA1Final(output, &context);
}