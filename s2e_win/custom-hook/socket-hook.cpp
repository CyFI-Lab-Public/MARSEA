#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "socket-hook.h"
#include "utils.h"
#include <set>
#include <string> 

#include <unordered_map>

#include <ws2tcpip.h>
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")

////////////////////////////////////////////////////////////////////
//// WINSOCK
////////////////////////////////////////////////////////////////////

/// Keep track of sockets 
static std::set<SOCKET> dummySockets;
static std::unordered_map<SOCKET, int> perSocketBytesToRead;

SOCKET WSAAPI sockethook(
    int af,
    int type,
    int protocol
) {
    if (checkCaller("socket")) {
        UINT8 retSocket = socket(af, type, protocol);            
        
        char* prot = "";
        if (af == 23)
        {
            prot = "IPv6";
        }
        else if (af == 2)
        {
            prot = "IPv4";
        }
        if (retSocket == INVALID_SOCKET) {
            SOCKET rSocket = (SOCKET)malloc(sizeof(SOCKET));
            dummySockets.insert(rSocket);
           
            Message("[W] socket(%s, %i, %i), Ret: 0x%x\n",
                prot, type, protocol, rSocket);

            return rSocket;
        }
        Message("[W] socket(%s, %i, %i), Ret: 0x%x\n",
            prot, type, protocol, retSocket);
        return retSocket;
    }

    return socket(af, type, protocol);
}

INT WSAAPI connecthook(
    SOCKET         s,
    const sockaddr* name,
    int            namelen
) {

    if (!checkCaller("connect")) {
        char ip[INET6_ADDRSTRLEN] = { 0 };
        sockaddr* sa = new sockaddr();
        switch (name->sa_family) {
            case AF_INET: {
                sockaddr_in* sin = (sockaddr_in*)name;
                inet_ntop(AF_INET, &sin->sin_addr, ip, INET6_ADDRSTRLEN);
                std::string tag_in = ReadTag((PVOID)ip);
                if (tag_in.length() > 0) {
                    Message("[W] connect (%p, A\"%s\") tag_in: %s \n", s, ip, tag_in.c_str());
                }
                else {
                    tag_in = ReadTag((PVOID) & (((struct sockaddr_in*)name)->sin_addr));
                    if (tag_in.length() > 0) {
                        Message("[W] connect (%p, A\"%s\") tag_in: %s, DDR\n", s, ip, tag_in.c_str());
                    }
                    else {
                        Message("[W] connect (%p, A\"%s\")\n", s, ip);
                    }
                }
                break;
            }
            case AF_INET6: {
                sockaddr_in6* sin = (sockaddr_in6*)name;
                inet_ntop(AF_INET6, &sin->sin6_addr, ip, INET6_ADDRSTRLEN);
                std::string tag_in = ReadTag((PVOID)ip);
                if (tag_in.length() > 0) {
                    Message("[W] connect (%p, A\"%s\") tag_in: %s \n", s, ip, tag_in.c_str());
                }
                else {
                    tag_in = ReadTag((PVOID) & (((struct sockaddr_in6*)name)->sin6_addr));
                    if (tag_in.length() > 0) {
                        Message("[W] connect (%p, A\"%s\") tag_in: %s\n", s, ip, tag_in.c_str());
                    }
                    else {
                        Message("[W] connect (%p, A\"%s\")\n", s, ip);
                    }
                }
                break;
            }
            default: {
                Message("[W] connect - Family=%i\n", name->sa_family);
            }
        }
        return 0;
    }
    Message("[W] connect - elsewhere\n");
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
    if (!checkCaller("recv")) {

        auto it = perSocketBytesToRead.find(s);
        if (it == perSocketBytesToRead.end()) {
            perSocketBytesToRead[s] = DEFAULT_MEM_LEN;
            it = perSocketBytesToRead.find(s);
        }
        int bytes_left = it->second;
        int bytes_read = bytes_left < len ? bytes_left : len;
        it->second -= bytes_read;
        len = bytes_read;


        std::string tag = GetTag("recv");
        UINT32 bytesToRead = min(len, DEFAULT_MEM_LEN);
        S2EMakeSymbolic(buf, bytesToRead, tag.c_str());
        // Symbolic return
        INT bytesRead = 0;//S2ESymbolicInt(tag.c_str(), bytesToRead);
        Message("[W] recv (%p, %s, %i, %i), ret: %i, -> tag_out: %s\n", s, buf, len, flags, bytesRead, tag.c_str());

        return bytesRead;
    }
    Message("[W] recv (%p) elsewhere\n", s);
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

    if (!checkCaller("select")) {
        std::string tag = GetTag("select");
        INT ret = S2ESymbolicInt(tag.c_str(), 1);
        Message("[W] select(%i, %p, %p, %p, %i)\n", nfds, readfds, writefds, exceptfds, timeout);
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
    if (!checkCaller("send")) {
        std::string tag = GetTag("send");
        //INT ret = S2ESymbolicInt(tag.c_str(), len);
        //Message("[W] send (%p, A\"%s\", %i, %i) -> tag_out: %s\n",
        //    s, buf, len, flags, tag.c_str());
        //return ret;
        Message("[W] send (%p, A\"%s\", %i, %i)\n",
                s, buf, len, flags);
        return len;
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

u_short WSAAPI ntohshook(
    u_short netshort
) {
    u_short ret = ntohs(netshort);
    Message("[W] ntohs (%u), ret: %u\n", netshort, ret);
    return ret;
}

int WSAAPI getsocknamehook(
    SOCKET   s,
    sockaddr* name,
    int* namelen
) {
    int ret = getsockname(s, name, namelen);
    Message("[W] getsockname (%p, %p, %i), ret: %i\n", s, name, namelen, ret);
    return ret;
}

int WSAAPI getpeernamehook(
    SOCKET   s,
    sockaddr* name,
    int* namelen
)
{
    char addr[11] = "8.8.8.8";
    sockaddr_in *fake = new sockaddr_in();
    fake->sin_family = AF_INET;
    fake->sin_port = htons(80);
    inet_pton(AF_INET, addr, &fake->sin_addr);
    name = (sockaddr*)&fake;
    *namelen = sizeof(name);

    Message("[W] getpeername (%p, %p, %i), Ip:%s, port=%d\n", s, name, namelen, inet_ntoa(fake->sin_addr), (int)ntohs(fake->sin_port));
    return 0;
}

INT WSAAPI getaddrinfohook(
    PCSTR           pNodeName,
    PCSTR           pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA* ppResult
) {
    char addr[11] = "8.8.8.8";
    char addr6[21] = "2001:4860:4860::8888";
    addrinfo* res = new addrinfo();
    char ip[INET6_ADDRSTRLEN] = { 0 };

    switch (pHints->ai_family) {
        case AF_INET: {
            sockaddr_in* ipv4 = new sockaddr_in();
            ipv4->sin_family = AF_INET;
            ipv4->sin_port = htons(80);
            inet_pton(AF_INET, addr, &ipv4->sin_addr);
            inet_ntop(AF_INET, &ipv4->sin_addr, ip, INET6_ADDRSTRLEN);
            res->ai_addr = (sockaddr*)&ipv4;
            res->ai_next = NULL;
            break;
        }
        case AF_INET6: {
            sockaddr_in6* ipv6 = new sockaddr_in6();
            ipv6->sin6_family = AF_INET6;
            ipv6->sin6_port = htons(80);
            inet_pton(AF_INET6, addr6, &ipv6->sin6_addr);
            inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, INET6_ADDRSTRLEN);
            res->ai_addr = (sockaddr*)&ipv6;
            res->ai_next = NULL;
            break;
        }
    }
    *ppResult = res;
    Message("[W] getaddrinfo (%s, %s, %p %p) Ip: %p=%s\n", pNodeName, pServiceName, pHints, ppResult, ip, ip);
    return 0;
}

