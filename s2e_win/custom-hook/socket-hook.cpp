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
    if (checkCaller("socket")) {
        UINT8 retSocket = socket(af, type, protocol);
        
        if (retSocket == INVALID_SOCKET) {
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

        return retSocket;
    }

    return socket(af, type, protocol);
}

INT WSAAPI connecthook(
    SOCKET         s,
    const sockaddr* name,
    int            namelen
) {
    if (checkCaller("connect")) {
        PSTR buf = "";
        if (name->sa_family == AF_INET)
        {
            PCSTR ret = inet_ntop(
                AF_INET,
                &(((struct sockaddr_in*)name)->sin_addr),
                buf,
                sizeof(s)
            );
            std::string tag_in = ReadTag((PVOID)ret);
            if (tag_in.length() > 0) {
                Message("[W] connect (%p, A\"%s\") tag_in: %s \n", s, buf, tag_in.c_str());
            }
            else {
                tag_in = ReadTag((PVOID) & (((struct sockaddr_in*)name)->sin_addr));
                if (tag_in.length() > 0) {
                    Message("[W] connect (%p, A\"%s\") tag_in: %s, DDR\n", s, buf, tag_in.c_str());
                }
                else {
                    Message("[W] connect (%p, A\"%s\")\n", s, buf);
                }
            }

        }
        else if (name->sa_family == AF_INET6)
        {
            PCSTR ret = inet_ntop(
                AF_INET6,
                &(((struct sockaddr_in6*)name)->sin6_addr),
                buf,
                sizeof(s)
            );
            std::string tag_in = ReadTag((PVOID)ret);
            if (tag_in.length() > 0) {
                Message("[W] connect (%p, A\"%s\") tag_in: %s \n", s, buf, tag_in.c_str());
            }
            else {
                tag_in = ReadTag((PVOID) & (((struct sockaddr_in6*)name)->sin6_addr));
                if (tag_in.length() > 0) {
                    Message("[W] connect (%p, A\"%s\") tag_in: %s\n", s, buf, tag_in.c_str());
                }
                else {
                    Message("[W] connect (%p, A\"%s\")\n", s, buf);
                }
            }
        }
        return 0;
    }

    return connect(s, name, namelen);
}

INT WSAAPI closesockethook(
    SOCKET s
) {

    if (checkCaller("closesocket")) {
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
    return closesocket(s);
}

INT WSAAPI recvhook(
    SOCKET s,
    char* buf,
    int len,
    int flags
) {
    if (checkCaller("recv")) {
        std::string tag = GetTag("recv");
        UINT32 bytesToRead = min(len, DEFAULT_MEM_LEN);
        S2EMakeSymbolic(buf, bytesToRead, tag.c_str());
        // Symbolic return
        INT bytesRead = S2ESymbolicInt(tag.c_str(), bytesToRead);
        Message("[W] recv(%p) -> tag_out: %s\n", s, tag.c_str());

        return bytesRead;
    }

    return recv(s, buf, len, flags);

}

INT WSAAPI accepthook(
    SOCKET   s,
    sockaddr* addr,
    int* addrlen
) {
    if (checkCaller("accept")) {
        SOCKET acceptSocket = (SOCKET)malloc(sizeof(SOCKET));
        dummySockets.insert(acceptSocket);

        return acceptSocket;
    }
    return accept(s, addr, addrlen);
}

INT WSAAPI selecthook(
    int           nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    const timeval* timeout
) {

    if (checkCaller("select")) {
        std::string tag = GetTag("select");
        INT ret = S2ESymbolicInt(tag.c_str(), 1);
        return ret;
    }

    return select(nfds, readfds, writefds, exceptfds, timeout);
}

INT WSAAPI sendhook(
    SOCKET     s,
    const char* buf,
    int        len,
    int        flags
) {
    if (checkCaller("send")) {
        std::string tag = GetTag("send");
        INT ret = S2ESymbolicInt(tag.c_str(), len);
        Message("[W] send(%p, A\"%ls\", %i, %i) -> tag_out: %s\n",
            s, buf, len, flags, tag.c_str());
        return ret;
    }

    return send(s, buf, len, flags);
}

INT WSAAPI sendtohook(
    SOCKET         s,
    const char* buf,
    int            len,
    int            flags,
    const sockaddr* to,
    int            tolen
) {

    if (checkCaller("sendto")) {

        std::string tag = GetTag("sendto");
        INT ret = S2ESymbolicInt(tag.c_str(), len);
        Message("[W] sendto(%p, A\"%ls\", %i, %i, A\"%ls\", %i) -> tag_out: %s\n",
            s, buf, len, flags, to, tolen, tag.c_str());
        return ret;
    }

    return sendto(s, buf, len, flags, to, tolen);
}