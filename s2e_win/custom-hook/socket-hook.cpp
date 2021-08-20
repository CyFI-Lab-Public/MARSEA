#include "socket-hook.h"
#include "utils.h"
#include <set>
#include <string> 

#include <ws2tcpip.h>
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

        char* prot = "";
        if (af == 23)
        {
            prot = "IPv6";
        }
        else if (af == 2)
        {
            prot = "IPv4";
        }
        Message("[W] socket(%s, %i, %i), Ret: 0x%x\n",
            prot, type, protocol, rSocket);

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
    char *buf = "";
    if (name->sa_family == AF_INET)
    {
        inet_ntop(
            AF_INET, 
            &(((struct sockaddr_in*)name)->sin_addr), 
            buf, 
            sizeof(s)
        );
    }
    else if (name->sa_family == AF_INET6)
    {
        inet_ntop(
            AF_INET6,
            &(((struct sockaddr_in6*)name)->sin6_addr),
            buf,
            sizeof(s)
        );
    }
    Message("[W] connect (%p, %s)\n", s, buf);
    return 0;
}

INT WSAAPI closesockethook(
    SOCKET s
) {
    Message("[W] closesocket(%p)\n", s);

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
    std::string tag = GetTag("recv");
    UINT32 bytesToRead = min(len, DEFAULT_MEM_LEN);
    S2EMakeSymbolic(buf, bytesToRead, tag.c_str());
    // Symbolic return
    INT bytesRead = S2ESymbolicInt(tag.c_str(), bytesToRead);
    Message("[W] recv(%p) -> tag_out: %s\n", s, tag.c_str());

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
    std::string tag = GetTag("select");
    INT ret = S2ESymbolicInt(tag.c_str(), 1);
    return ret;
}

INT WSAAPI sendhook(
    SOCKET     s,
    const char* buf,
    int        len,
    int        flags
) {
    std::string tag = GetTag("send");
    INT ret = S2ESymbolicInt(tag.c_str(), len);
    Message("[W] send(%p, A\"%ls\", %i, %i) -> tag_out: %s\n",
        s, buf, len, flags, tag.c_str());
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

    std::string tag = GetTag("sendto");
    INT ret = S2ESymbolicInt(tag.c_str(), len);
    Message("[W] sendto(%p, A\"%ls\", %i, %i, A\"%ls\", %i) -> tag_out: %s\n",
        s, buf, len, flags, to, tolen, tag.c_str());
    return ret;
}