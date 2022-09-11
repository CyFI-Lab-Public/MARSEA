#include "msvcrt-hook.h"
#include "utils.h"
#include "commands.h"
#include <string>
#include <set>
#include <unordered_map>
#include <shlwapi.h>

/// Keep track of sockets 
static std::set<FILE*> dummyHandles;
static std::map<FILE*, std::string> fileMap;
static std::unordered_map<FILE*, DWORD> perHandleBytesToRead;
static std::unordered_map<FILE*, int> perHandleCounter;


FILE* __cdecl fopenhook(
	const char* filename,
	const char* mode
) {
	if (checkCaller("fopen")) {

		std::string tag_in = ReadTag((PVOID)filename);

		if (tag_in != "") {
			concretizeAll((PVOID)filename);
		}

		std::string fileName(filename);
		std::string fileMode(mode);


		// Check try to open it
		if (FILE* fhandle = fopen(filename, mode)) {
			Message("[W] fopen (%s [|] %s) ret:%p tag_in:%s\n", filename, mode, fhandle, tag_in.c_str());
			fileMap[fhandle] = PathFindFileNameA(filename);
			return fhandle;
		}
		// If open file failed with read mode, create the file first
		else if (fileMode.find("r") == 0) {
			if (FILE* fwhandle = fopen(filename, "w")) {
				fclose(fwhandle);
				FILE* fhandle = fopen(filename, mode);
			}
			Message("[W] fopen (%s [|] %s) ret:%p tag_in:%s\n", filename, mode, fhandle, tag_in.c_str());
			fileMap[fhandle] = PathFindFileNameA(filename);
			return fhandle;
		}
		else {
			FILE* fhandle = (FILE*)malloc(sizeof(FILE*));
			dummyHandles.insert(fhandle);
			Message("[W] fopen (%s [|] %s) ret:%p tag_in:%s\n", filename, mode, fhandle, tag_in.c_str());
			fileMap[fhandle] = PathFindFileNameA(filename);
			return fhandle;
		}
	}
	return fopen(filename, mode);
}

size_t __cdecl freadhook(
	void* ptr,
	size_t size,
	size_t count,
	FILE* stream
) {
	if (checkCaller("fread")) {



		auto iit = perHandleCounter.find(stream);
		if (iit == perHandleCounter.end()) {
			perHandleCounter[stream] = 0;
			iit = perHandleCounter.find(stream);
		}


		std::string tagIn = "";
		//Try to get the fileName
		if (fileMap.find(stream) != fileMap.end() && taintFile.find(fileMap[stream]) != taintFile.end()) {
			std::string tagIn = taintFile[fileMap[stream]];
		}
		std::string tag = GetTag("fread");
		taintFile[fileMap[stream]] = tag;

		if (tagIn.length() > 0) {
			Message("[W] fread (%p [|] %i [|] %i [|] %p) tag_in:%s tag_out:%s\n", ptr, size, count, stream, tagIn.c_str(), tag.c_str());
		}
		else {
			Message("[W] fread (%p [|] %i [|] %i [|] %p) tag_out:%s\n", ptr, size, count, stream, tag.c_str());
		}

		std::set<FILE*>::iterator it = dummyHandles.find(stream);
		size_t readBytes = 0;
		if (it == dummyHandles.end()) {
			readBytes = fread(ptr, size, count, stream);
			if (readBytes) {
				cyfiTaint(ptr, readBytes, tag.c_str());
			}
		}
		else {
			if (iit->second < 3) {
				perHandleCounter[stream] = iit->second + 1;

				auto phbr = perHandleBytesToRead.find(stream);
				if (phbr == perHandleBytesToRead.end()) {
					perHandleBytesToRead[stream] = count;
					phbr = perHandleBytesToRead.find(stream);
				}
				DWORD bytes_left = phbr->second;
				DWORD bytes_read = bytes_left < count ? bytes_left : count;
				phbr->second -= bytes_read;
				readBytes = bytes_read;
				S2EMakeSymbolic(ptr, readBytes, tag.c_str());
			}
			else {
				readBytes = 0;
			}
		}
		return readBytes;
	}
	return fread(ptr, size, count, stream);
}

int __cdecl fseekhook(
	FILE* stream,
	long int offset,
	int origin
) {
	perHandleBytesToRead.erase(stream);

	Message("[W] fseek (%p [|] %ld [|] %i)\n", stream, offset, origin);
	int ret = fseek(stream, offset, origin);
	return 0; //successful
}


size_t __cdecl fwritehook(
	const void* buffer,
	size_t size,
	size_t count,
	FILE* stream
) {
	if (checkCaller("fwrite")) {
		std::set<FILE*>::iterator it = dummyHandles.find(stream);

		if (it == dummyHandles.end()) {
			size_t ret = fwrite(buffer, size, count, stream);
		}

		std::string tag = ReadTag((PVOID)buffer);
		if (tag != "") {
			if (fileMap.find(stream) != fileMap.end())
			{
				std::string fileName = fileMap[stream];
				taintFile[fileName] = tag;
			}
			Message("[W] fwrite (%p [|] %i [|] %i [|] %p) tag_in:%s\n", buffer, size, count, stream, tag.c_str());
		}
		else {
			Message("[W] fwrite (%p [|] %i [|] %i [|] %p)\n", buffer, size, count, stream);
		}
		return count;
	}
	return fwrite(buffer, size, count, stream);
}

int __cdecl fclosehook(FILE* fp)
{
	if (checkCaller("fclose")) {
		Message("[W] fclose (%p)\n", fp);

		perHandleBytesToRead.erase(fp);
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
	return fclose(fp);
}

int randhook(void) {
	if (checkCaller("rand")) {
		std::string tag_out = GetTag("rand");
		int ran = rand();
		return S2ESymbolicInt(tag_out.c_str(), ran);
	}
	return rand();
}
