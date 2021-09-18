#pragma once
#include <stdio.h>

FILE* __cdecl fopenhook(const char* filename,const char* mode);
size_t __cdecl fwritehook(const void* buffer, size_t size, size_t count, FILE* stream);