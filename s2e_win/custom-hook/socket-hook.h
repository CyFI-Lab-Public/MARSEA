#pragma once
#include <winsock2.h>

SOCKET WSAAPI sockethook(int af, int type, int protocol);
INT WSAAPI connecthook(SOCKET s, const sockaddr* name, int namelen);
INT WSAAPI closesockethook(SOCKET s);
INT WSAAPI recvhook(SOCKET s, char* buf, int len, int flags);
INT WSAAPI accepthook(SOCKET s, sockaddr* addr, int* addrlen);
INT WSAAPI selecthook(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const timeval* timeout);
INT WSAAPI sendhook(SOCKET s, const char* buf, int len, int flags);
INT WSAAPI sendtohook(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);
