///
/// Copyright (C) 2018, Adrian Herrera
/// All rights reserved.
///

#include <stdio.h>

#include <Windows.h>

void ddos(LPCSTR target) {
    // DDOS code goes here :)
    printf("DDOS'ing %s\n", target);
}

int main() {
    // The following code is adapted from the paper "Automatically Identifying
    // Trigger-based Behaviour in Malware" by Brumley et al.
    SYSTEMTIME systime;
    LPCSTR site = "www.usenix.org";

    GetLocalTime(&systime);

    if (9 == systime.wDay) {
        if (10 == systime.wHour) {
            if (11 == systime.wMonth) {
                if (6 == systime.wMinute) {
                    ddos(site);
                }
            }
        }
    }

    return 0;
}
