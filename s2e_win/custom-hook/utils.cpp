#include <stdio.h>
#include <iostream>
#include <string>
#include <type_traits>

#include "utils.h"
#include "commands.h"

#include <time.h>
#include<iostream>
#include <sstream>
#include <shlwapi.h>

// Global tag number
static uint64_t tag_number = 0;

//////////////////////
// Helper functions //
//////////////////////

///
/// Write a message to the S2E log (or stdout).
///
void Message(LPCSTR fmt, ...) {
    CHAR message[S2E_MSG_LEN];
    va_list args;

    va_start(args, fmt);
    vsnprintf(message, S2E_MSG_LEN, fmt, args);
    va_end(args);

    if (s2eVersion) {
        S2ECyfiMessageFmt("[0x%x|malware-hook] %s", GetCurrentProcessId(),
                message);
    }
    else {
        printf("[0x%x|malware-hook] %s", GetCurrentProcessId(), message);
    }
}


///
/// Generate unique tag for each symbolic expression
/// 
std::string GetTag(PCSTR funcName) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    //Command.Command = TAG_COUNTER;
    //S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    //std::string tag = "CyFi_" + std::string(funcName) + std::to_string(Command.TagCounter.counter);
    std::string tag = "CyFi_" + std::string(funcName) + std::to_string(tag_number);
    tag_number += 1;
    return tag;
}

std::string ReadTag(PVOID Buffer) {

    if (Buffer == NULL || Buffer == nullptr) {
        std::string res = "";
        return res;
    }

    CHAR symbTag[50] = { 0 };

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = READ_TAG;
    Command.ReadTag.buffer = (uint64_t)Buffer;
    Command.ReadTag.symbTag = (uint64_t)symbTag;

    __s2e_touch_buffer((PCSTR)(UINT_PTR)Command.ReadTag.symbTag, 51);
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    return std::string((PCSTR)Command.ReadTag.symbTag);
}

bool IsTainted(PVOID Buffer) {
    std::string tag = ReadTag(Buffer);

    if (tag.find("_taint") != std::string::npos) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

void concretizeAll(PVOID Buffer) {
    if (Buffer == NULL || Buffer == nullptr) {
        return;
    }

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = CONCRETIZE_ALL;
    Command.concretizeAll.buffer = (uint64_t)Buffer;
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    return;
}

void cyfiTaint(PVOID Buffer, UINT32 Size, PCSTR Name, bool remove) {
    if (Buffer == NULL || Buffer == nullptr) {
        return;
    }

    std::string tag = std::string(Name);

    tag.append("_taint");

    Name = tag.c_str();

    __s2e_touch_string(Name);
    __s2e_touch_buffer(Buffer, Size);

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = TAINT;
    Command.cyfiTaint.buffer = (uint64_t)Buffer;
    Command.cyfiTaint.size = (uint64_t)Size;
    Command.cyfiTaint.tag = (uint64_t)Name;
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    return;
}

void cyfiPrintMemory(PVOID Buffer, size_t Size) {
    if (Buffer == NULL || Buffer == nullptr) {
        return;
    }

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = PRINT_MEM;
    Command.cyfiPrintMem.buffer = (uint64_t)Buffer;
    Command.cyfiPrintMem.size = (uint64_t)Size;
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    return;
}

size_t cyfiwcslen(wchar_t* Buffer) {
    S2EDisableForking();
    size_t size = wcslen(Buffer);
    S2EEnableForking();
    return size;
}

size_t cyfistrlen(char* Buffer) {
    S2EDisableForking();
    size_t size = strlen(Buffer);
    S2EEnableForking();
    return size;
}

bool checkCaller(std::string funcName) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = CHECK_CALLER;
    Command.CheckCaller.funcName = (uint64_t)funcName.c_str();
    //std::string symbTag = "";
    //Command.CheckCaller.symbTag = (uint64_t)symbTag.c_str();

    //__s2e_touch_string((PCSTR)(UINT_PTR)Command.CheckCaller.symbTag);

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    //Message("Tag is: %s\n", Command.CheckCaller.symbTag);

    return Command.CheckCaller.isTargetModule;
}

void killAnalysis(std::string funcName) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = KILL_ANALYSIS;
    Command.KillAnalysis.funcName = (uint64_t)funcName.c_str();
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
}

std::string getFileTag(LPCSTR buffer) {
    if (buffer == NULL || buffer[0] == 0) {return std::string("");}

    std::string file_string(buffer);

    for (auto i = taintFile.begin(); i != taintFile.end(); i++) {
        std::string taint_file_name = i->first;
        std::string tag = i->second;

        if (file_string.find(taint_file_name) != std::string::npos) {
            return tag;
        }
    }

    return std::string("");

}

std::string getFileTag(LPCWSTR buffer) {
    if (buffer == NULL || buffer[0] == 0) { return std::string(""); }
    std::string file_string = lpcwstrToString(buffer);

    for (auto i = taintFile.begin(); i != taintFile.end(); i++) {
        std::string taint_file_name = i->first;
        std::string tag = i->second;

        if (file_string.find(taint_file_name) != std::string::npos) {
            return tag;
        }
    }

    return std::string("");

}

std::string lpcstrToString(LPCSTR name) {
    //https://docs.microsoft.com/en-us/cpp/text/how-to-convert-between-various-string-types?redirectedfrom=MSDN&view=msvc-160
    CHAR message[S2E_MSG_LEN];
    sprintf_s(message, S2E_MSG_LEN, "%s", name);
    return std::string(message);
}

std::string lpcwstrToString(LPCWSTR name) {
    CHAR message[S2E_MSG_LEN];
    sprintf_s(message, S2E_MSG_LEN, "%ls", name);
    return std::string(message);
}

bool cyFiDumpFile(char* lpStrFilePath, std::string tag) {

    Message("Malware dumps file to %s", lpStrFilePath);

    srand((unsigned)time(NULL));
    /*std::ostringstream s;
    s << rand();*/
    int random_number = rand();
    std::string random_string = std::to_string(random_number);

    char buffer_1[MAX_PATH] = "";
    char* lpStr1;
    lpStr1 = buffer_1;

    char buffer_3[] = "C:\\s2e\\";
    char* lpStr3;
    lpStr3 = buffer_3;

    if (tag != "") {
        random_string = tag + "_" + random_string;
    }

    LPSTR dest_path_res = PathCombineA(lpStr1, lpStr3, random_string.c_str());

    Message("Copy from %s to %s", lpStrFilePath, dest_path_res);

    BOOL res = CopyFileA(lpStrFilePath, dest_path_res, FALSE);

    if (!res) {
        Message("Copy File Failed. Error Code: 0x%x\n", GetLastError());
        return FALSE;
    }
    else {
        Message("Copy File Succeed!\n");

        HINSTANCE run_res = ShellExecuteA(NULL, "open", "C:\\s2e\\s2eput.exe", random_string.c_str(), NULL, NULL);
        if (int(run_res) <= 32) {
            Message("Failed run s2eput with code 0x%x", int(run_res));
            return FALSE;
        }
        else {
            Message("Write file %s to the host side\n", random_string.c_str());
            return TRUE;
        }
    }
}

bool cyFiCopyFile(HANDLE hFile) {
    //Dump the file to the host
    char Path[MAX_PATH];
    char* lpStrFilePath;
    lpStrFilePath = Path;
    DWORD dwRet;
    dwRet = GetFinalPathNameByHandleA(hFile, lpStrFilePath, MAX_PATH, VOLUME_NAME_DOS);

    std::string tag = getFileTag(PathFindFileNameA(lpStrFilePath));

    if (dwRet <= MAX_PATH && dwRet != 0) {
        cyFiDumpFile(lpStrFilePath, tag);
    }
    
    if (dwRet == 0) {
        Message("GetFinalPathNameByHandle failed: 0x%x", GetLastError());
        return FALSE;
    }

    if (dwRet > MAX_PATH) {
        Message("GetFinalPathNameByHandle failed becaue of small buffer\n");
        return FALSE;
    }

    return FALSE;
}
