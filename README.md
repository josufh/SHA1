# SHA1 Algorithm Implementation in C for files and buffers

## Usage

Intended to use as dll

To compile the file:

```shell
gcc -shared -o sha1.dll sha1.c
```

To use in other C code:

```C
#include <windows.h>
#define SHA1_BLOCK_SIZE 20
typedef void (__cdecl *SHA1FileFunc)(const char *filename, unsigned char output[SHA1_BLOCK_SIZE]);
typedef void (__cdecl *SHA1BufferFunc)(const unsigned char *buffer, const size_t buffer_size, unsigned char output[SHA1_BLOCK_SIZE]);

int main() {
  HINSTANCE hDll = LoadLibrary("sha1.dll");

  // To hash a file
  SHA1FileFunc sha1_file = (SHA1FileFunc)GetProcAddress(hDll, "sha1_file");
  unsigned char file_hash[SHA1_BLOCK_SIZE];
  sha1_file("path/to/example.file", file_hash);
  
  // To hash a buffer
  SHA1BufferFunc sha1_buffer = (SHA1BufferFunc)GetProcAddress(hDll, "sha1_buffer");
  unsigned char buffer_hash[SHA1_BLOCK_SIZE];
  unsigned char *buffer;
  size_t buffer_size;
  sha1_buffer(buffer, buffer_size, hash, buffer_hash);
  // ...
  FreeLibrary(hDll);
  return 0;
}
```

## Source

[SHA1 pseudocode (Wikipedia)](https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode)
