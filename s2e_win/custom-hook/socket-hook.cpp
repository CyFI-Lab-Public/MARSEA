#include "socket-hook.h"
#include "utils.h"
#include <set>

#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")

////////////////////////////////////////////////////////////////////
//// WINSOCK
////////////////////////////////////////////////////////////////////

/// Keep track of sockets 
static std::set<SOCKET> dummySockets;

SOCKET WSAAPI sockethook(
    int af,
    int type,
    int protocol
) {
    UINT8 retSocket = S2ESymbolicChar("socket", 1);
    if (retSocket) {
        SOCKET rSocket = (SOCKET)malloc(sizeof(SOCKET));
        dummySockets.insert(rSocket);
        Message("[HLOG] socket(%i, %i, %i) Ret: %i\n",
            af, type, protocol, rSocket);

        return rSocket;
    }
    else {
        return NULL;
    }
}

INT WSAAPI connecthook(
    SOCKET         s,
    const sockaddr* name,
    int            namelen
) {
    Message("[HLOG] connect(%p)\n", s);
    return 0;
}

INT WSAAPI closesockethook(
    SOCKET s
) {
    Message("[HLOG] closesocket(%p)\n", s);

    std::set<SOCKET>::iterator it = dummySockets.find(s);

    if (it == dummySockets.end()) {
        // The socket is not one of our dummy sockets, so call the original
        // closesocket function
        return closesocket(*it);
    }
    else {
        // The socket is a dummy handle. Free it
        //free(*it);
        dummySockets.erase(it);

        return TRUE;
    }
}

INT WSAAPI recvhook(
    SOCKET s,
    char* buf,
    int len,
    int flags
) {
    Message("[HLOG] recv(%p)\n", s);

    PCSTR tag = GetTag("recv");

    UINT32 bytesToRead = min(len, DEFAULT_MEM_LEN);

    S2EMakeSymbolic(buf, bytesToRead, tag);

    // Symbolic return
    INT bytesRead = S2ESymbolicInt(tag, bytesToRead);

    return bytesRead;

}

INT WSAAPI accepthook(
    SOCKET   s,
    sockaddr* addr,
    int* addrlen
) {
    SOCKET acceptSocket = (SOCKET)malloc(sizeof(SOCKET));
    dummySockets.insert(acceptSocket);

    return acceptSocket;
}

INT WSAAPI selecthook(
    int           nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    const timeval* timeout
) {
    INT ret = S2ESymbolicInt(GetTag("select"), 1);
    return ret;
}

INT WSAAPI sendhook(
    SOCKET     s,
    const char* buf,
    int        len,
    int        flags
) {
    Message("[HLOG] send(%p, A\"%ls\", %i, %i)\n",
        s, buf, len, flags);
    INT ret = S2ESymbolicInt(GetTag("send"), len);
    return ret;
}

INT WSAAPI sendtohook(
    SOCKET         s,
    const char* buf,
    int            len,
    int            flags,
    const sockaddr* to,
    int            tolen
) {
    Message("[HLOG] sendto(%p, A\"%ls\", %i, %i, A\"%ls\", %i)\n",
        s, buf, len, flags, to, tolen);
    INT ret = S2ESymbolicInt(GetTag("sendto"), len);
    return ret;
}