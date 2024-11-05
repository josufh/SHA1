# SHA1 Algorithm Implementation in C for files

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

int main() {
  HINSTANCE hDll = LoadLibrary("sha1.dll");
  SHA1FileFunc sha1_file = (SHA1FileFunc)GetProcAddress(hDll, "sha1_file");
  unsigned char hash[SHA1_BLOCK_SIZE];
  sha1_file("path/to/example.file", hash);
  // ...
  FreeLibrary(hDll);
  return 0;    
}
```

## Source

[SHA1 pseudocode (Wikipedia)](https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode)
