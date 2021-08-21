#include "msvcrt-hook.h"
#include "utils.h"
#include <string>
#include <set>

/// Keep track of sockets 
static std::set<FILE*> dummyHandles;

FILE* fopenhook(
	const char* filename,
	const char* mode
) {
	std::string fileName(filename);
	std::string fileMode(mode);

	Message("[W] fopen(%s, %s)\n", filename, mode);

	// Check try to open it
	if (FILE* fhandle = fopen(filename, mode)) {
		return fhandle;
	}
	// If open file failed with read mode, create the file first
	else if (fileMode.find("r") == 0) {
		if (FILE* fwhandle = fopen(filename, "w")) {
			fclose(fwhandle);
			FILE* fhandle = fopen(filename, mode);
			return fhandle;
		}
	}
	else {
		Message("[W] ERROR fopen(%s, %s)\n", filename, mode);
		FILE* fhandle = (FILE*)malloc(sizeof(FILE*));
		dummyHandles.insert(fhandle);
		return fhandle;
	}
}

size_t fwritehook(
	const void* buffer,
	size_t size,
	size_t count,
	FILE* stream
) {
	Message("[W] fwrite(%s, %p)\n", buffer, stream);

	std::set<FILE*>::iterator it = dummyHandles.find(stream);

	if (it == dummyHandles.end()) {
		return fwrite(buffer, size, count, stream);
	}
	else {
		free(*it);
		dummyHandles.erase(it);
		return size;
	}
}