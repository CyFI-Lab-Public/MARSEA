#pragma once
#include <winsock2.h>

SOCKET WSAAPI sockethook(int af, int type, int protocol);
INT WSAAPI connecthook(SOCKET s, const sockaddr* name, int namelen);
INT WSAAPI closesockethook(SOCKET s);
INT WSAAPI recvhook(SOCKET s, char* buf, int len, int flags);
SOCKET WSAAPI accepthook(SOCKET s, sockaddr* addr, int* addrlen);
INT WSAAPI selecthook(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const timeval* timeout);
INT WSAAPI sendhook(SOCKET s, const char* buf, int len, int flags);
INT WSAAPI sendtohook(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);
INT WSAAPI getaddrinfohook(
    PCSTR           pNodeName,
    PCSTR           pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA* ppResult
);
int WSAAPI getsocknamehook(
    SOCKET   s,
    sockaddr* name,
    int* namelen
);
u_short WSAAPI ntohshook(
    u_short netshort
);
int WSAAPI getpeernamehook(
    SOCKET   s,
    sockaddr* name,
    int* namelen
);
INT WSAAPI bindhook(
    SOCKET s,
    const sockaddr* addr,
    int namelen
);
hostent* WSAAPI gethostbynamehook(
    const char* name
);

char* WSAAPI inet_ntoahook(
    in_addr in
);

PCSTR WSAAPI inet_ntophook(
    INT        Family,
    const VOID* pAddr,
    PSTR       pStringBuf,
    size_t     StringBufSize
);
