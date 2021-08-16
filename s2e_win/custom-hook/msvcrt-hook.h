#pragma once
#include <stdio.h>

FILE* fopenhook(const char* filename,const char* mode);
size_t fwritehook(const void* buffer, size_t size, size_t count, FILE* stream);