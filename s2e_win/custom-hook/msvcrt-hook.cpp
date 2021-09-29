#include "msvcrt-hook.h"
#include "utils.h"
#include <string>
#include <set>

/// Keep track of sockets 
static std::set<FILE*> dummyHandles;
static std::map<FILE*, std::string> fileMap;

FILE* __cdecl fopenhook(
	const char* filename,
	const char* mode
) {
	if (checkCaller("fopen")) {
		std::string fileName(filename);
		std::string fileMode(mode);


		// Check try to open it
		if (FILE* fhandle = fopen(filename, mode)) {
			Message("[W] fopen (%s, %s), Ret: %p\n", filename, mode, fhandle);
			fileMap[fhandle] = filename;
			return fhandle;
		}
		// If open file failed with read mode, create the file first
		else if (fileMode.find("r") == 0) {
			if (FILE* fwhandle = fopen(filename, "w")) {
				fclose(fwhandle);
				FILE* fhandle = fopen(filename, mode);
			}
			Message("[W] fopen (%s, %s), Ret: %p\n", filename, mode, fhandle);
			fileMap[fhandle] = filename;
			return fhandle;
		}
		else {
			FILE* fhandle = (FILE*)malloc(sizeof(FILE*));
			dummyHandles.insert(fhandle);
			Message("[W] fopen (%s, %s), Ret: %p\n", filename, mode, fhandle);
			fileMap[fhandle] = filename;
			return fhandle;
		}
	}
	else {
		return fopen(filename, mode);
	}
}

size_t __cdecl freadhook(
	void* ptr,
	size_t size,
	size_t count,
	FILE* stream
) {
	std::string tagIn = "";
	//Try to get the fileName
	if (fileMap.find(stream) != fileMap.end() && taintFile.find(fileMap[stream]) != taintFile.end()) {
		std::string tagIn = taintFile[fileMap[stream]];
	}
	std::string tag = GetTag("fread");

	if (tagIn.length() > 0) {
		Message("[W] fread (%p, %i, %i, %p) -> tag_in: %s tag_out: %s\n", ptr, size, count, stream, tagIn.c_str(), tag.c_str());
	}
	else {
		Message("[W] fread (%p, %i, %i, %p) -> tag_out: %s\n", ptr, size, count, stream, tag.c_str());
	}
	std::set<FILE*>::iterator it = dummyHandles.find(stream);
	if (it == dummyHandles.end()) {
		if (fread(ptr, size, count, stream) && count != NULL) {
			S2EMakeSymbolic(ptr, min(count, DEFAULT_MEM_LEN), tag.c_str());
		}
		else {
			S2EMakeSymbolic(ptr, DEFAULT_MEM_LEN, tag.c_str());
		}
	}
	else {
		S2EMakeSymbolic(ptr, min(count, DEFAULT_MEM_LEN), tag.c_str());
		S2EMakeSymbolic((PVOID)count, sizeof(DWORD), tag.c_str());
	}
	return count;
}

int __cdecl fclosehook(FILE* fp)
{
	Message("[W] fclose (%p)\n", fp);

	std::set<FILE*>::iterator it = dummyHandles.find(fp);

	if (it == dummyHandles.end()) {
		return fclose(fp);
	}
	else {
		// The handle is a dummy handle. Free it
		free(*it);
		dummyHandles.erase(it);
		return 0;
	}
}

size_t __cdecl fwritehook(
	const void* buffer,
	size_t size,
	size_t count,
	FILE* stream
) {

	std::set<FILE*>::iterator it = dummyHandles.find(stream);

	if (it == dummyHandles.end()) {
		return fwrite(buffer, size, count, stream);
	}
	else {
		std::string tag = ReadTag((PVOID)buffer);
		if (tag != "") {
			if (fileMap.find(stream) != fileMap.end())
			{
				std::string fileName = fileMap[stream];
				taintFile[fileName] = tag;
			}
			Message("[W] fwrite (%s, %i, %i,  %p) -> tag_in: %s\n", buffer, size, count, stream, tag.c_str());
			return count;
		}
		else {
			Message("[W] fwrite (%s, %i, %i,  %p)\n", buffer, size, count, stream);
			return count;
		}
	}
	return count;
}