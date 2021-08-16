#pragma once

// We need this header file to make things symbolic and to write to the S2E log
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}

#include <Windows.h>
#include <string>

/// Maximum timeout to wait for child processes to terminate (in milliseconds).
/// Can also be set to INFINITE.
#define CHILD_PROCESS_TIMEOUT 10 * 1000

/// Maximum message length to write to S2E debug log
#define S2E_MSG_LEN 512

/// Maximum path length
#define MAX_PATH_LEN 256

/// Default mem length
#define DEFAULT_MEM_LEN 512

/// S2E version number, or 0 if not running in S2E mode
extern INT s2eVersion;

void Message(LPCSTR fmt, ...);

std::string GetTag(PCSTR funcName);
