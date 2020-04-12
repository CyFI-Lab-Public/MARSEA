///
/// Copyright (C) 2018, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#pragma once

#include <windows.h>

#pragma warning(push)
#pragma warning(disable:4189)
#pragma warning(disable:4091)
#include <imagehlp.h>
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable:4003)
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#pragma warning(pop)

#include <string>
#include <unordered_set>
#include <unordered_map>


VOID DumpLineInfo(HANDLE hProcess, ULONG64 Base);
std::string JsonEscapeString(const std::string String);
VOID AddrToLine(HANDLE Process, const std::string &AddressesStr);

using SymbolAddressToName = std::unordered_map<UINT64, std::string>;
using SymbolNameToAddress = std::unordered_map<std::string, UINT64>;

struct SymbolInfo
{
    SymbolAddressToName ByAddress;
    SymbolNameToAddress ByName;
};

static BOOL GetSymbolAddress(const SymbolInfo &Symbols, const std::string &Name, UINT64 &Address)
{
    auto it = Symbols.ByName.find(Name);
    if (it == Symbols.ByName.end()) {
        return FALSE;
    }
    Address = (*it).second;
    return TRUE;
}

BOOL GetSymbolMap(SymbolInfo &Symbols, HANDLE Process, ULONG64 ModuleBase);
void DumpSymbolMapAsJson(const SymbolInfo &Symbols, rapidjson::Document &Doc);

struct symbol_t
{
    unsigned offset;
    ULONG64 length;
    unsigned child_id;
    unsigned type_id;
    std::string name;
};

typedef std::vector<symbol_t> TypeMembers;
typedef std::vector<std::string> TypePath;
using TypeNames = std::unordered_set<std::string>;

VOID EnumerateTypes(HANDLE Process, ULONG64 ModuleBase, TypeNames &Types);
void DumpTypesAsJson(rapidjson::Document &Doc, HANDLE Process, UINT64 ModuleBase);

BOOL OurGetFileSize(const char *pFileName, DWORD *pFileSize);

_Success_(return)
BOOL GetImageInfo(
    _In_ const char *FileName,
    _Out_ ULONG64 *LoadBase,
    _Out_ DWORD *CheckSum,
    _Out_ bool *Is64
);

template <typename T>
bool ReadPe(PLOADED_IMAGE Image, UINT64 NativeLoadBase, UINT64 NativeAddress, T *ret)
{
    for (unsigned i = 0; i < Image->NumberOfSections; ++i) {
        DWORD SVA = Image->Sections[i].VirtualAddress;
        DWORD SSize = Image->Sections[i].SizeOfRawData;
        if (NativeAddress >= SVA + NativeLoadBase && NativeAddress + sizeof(T) <= SVA + NativeLoadBase + SSize) {
            DWORD Offset = (DWORD)((NativeAddress - NativeLoadBase) - Image->Sections[i].VirtualAddress);
            Offset += Image->Sections[i].PointerToRawData;
            *ret = *(T*)(Image->MappedAddress + Offset);
            return true;
        }
    }

    return false;
}

void DumpSyscalls(
    const SymbolInfo &Symbols, HANDLE Process,
    const std::string &ImagePath, ULONG64 ModuleBase,
    UINT64 NativeLoadBase, bool Is64
);
