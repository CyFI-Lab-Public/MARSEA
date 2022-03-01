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
static std::set<SOCKET> socketTracker;

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
           
            Message("[W] socket(%s [|] %i [|] %i) ret:%p\n",
                prot, type, protocol, rSocket);

            return rSocket;
        }
        Message("[W] socket(%s [|] %i [|] %i) ret:%p\n",
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

    if (checkCaller("connect")) {
        char ip[INET6_ADDRSTRLEN] = { 0 };
        sockaddr* sa = new sockaddr();
        switch (name->sa_family) {
            case AF_INET: {
                sockaddr_in* sin = (sockaddr_in*)name;
                inet_ntop(AF_INET, &sin->sin_addr, ip, INET6_ADDRSTRLEN);
                std::string tag_in = ReadTag((PVOID)ip);
                if (tag_in.length() > 0) {
                    Message("[W] connect (%p [|] %s) tag_in:%s\n", s, ip, tag_in.c_str());
                }
                else {
                    tag_in = ReadTag((PVOID) & (((struct sockaddr_in*)name)->sin_addr));
                    if (tag_in.length() > 0) {
                        Message("[W] connect (%p [|] %s) tag_in:%s\n", s, ip, tag_in.c_str());
                    }
                    else {
                        Message("[W] connect (%p [|] %s)\n", s, ip);
                    }
                }
                break;
            }
            case AF_INET6: {
                sockaddr_in6* sin = (sockaddr_in6*)name;
                inet_ntop(AF_INET6, &sin->sin6_addr, ip, INET6_ADDRSTRLEN);
                std::string tag_in = ReadTag((PVOID)ip);
                if (tag_in.length() > 0) {
                    Message("[W] connect (%p [|] %s) tag_in:%s\n", s, ip, tag_in.c_str());
                }
                else {
                    tag_in = ReadTag((PVOID) & (((struct sockaddr_in6*)name)->sin6_addr));
                    if (tag_in.length() > 0) {
                        Message("[W] connect (%p [|] %s) tag_in:%s\n", s, ip, tag_in.c_str());
                    }
                    else {
                        Message("[W] connect (%p [|] %s)\n", s, ip);
                    }
                }
                break;
            }
            default: {
                Message("connect - Family=%i\n", name->sa_family);
            }
        }
        return 0;
    }
    return connect(s, name, namelen);
}

INT WSAAPI bindhook(
    SOCKET s,
    const sockaddr* addr,
    int namelen
) {
    if (checkCaller("bind")) {
        Message("bind \n");
        return 0;
    }

    return bind(s, addr, namelen);
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

            return 0;
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

        std::string data_read = "(url)f237769666e6f636f2336313e28393e2039313e2838313f2f2a307474786(/url)";
        memcpy(buf, data_read.c_str(), data_read.size());
        
        Message("[W] recv (%p [|] %p [|] %i [|] %i) ret:%i tag_out:%s\n", s, buf, len, flags, data_read.size(), tag.c_str());

        int ret = data_read.size();//S2ESymbolicInt(tag.c_str(), data_read.size());
        S2EMakeSymbolic(buf, data_read.size(), tag.c_str());
        return ret;

        /*UINT32 bytesToRead = min(len, DEFAULT_MEM_LEN);
        Message("[W] recv (%p, %p, %i [|] %i), ret:%i [|] -> tag_out:%s\n", s, buf, len, flags, bytesToRead, tag.c_str());
        S2EMakeSymbolic(buf, bytesToRead, tag.c_str());
        // Symbolic return
        //INT bytesRead = S2ESymbolicInt(tag.c_str(), bytesToRead);
        return bytesToRead;//bytesRead;*/
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

        int socketCount = readfds->fd_count;
        if (socketCount > 0) {
            for (int i = 0; i < readfds->fd_count; i++) {
                SOCKET s = readfds->fd_array[i];
                std::set<SOCKET>::iterator it = socketTracker.find(s);
                if (it == socketTracker.end()) {
                    socketTracker.insert(s);
                }
                else {
                    socketTracker.erase(it);
                    socketCount--;
                }
            }
            Message("[W] select(%i [|] %i [|] %i [|] %p [|] %p) ret:%i\n", nfds, readfds->fd_count, writefds->fd_count, exceptfds, timeout, socketCount);
            return socketCount;
        }
        return 0;

        /*std::string tag = GetTag("select");
        INT ret = S2ESymbolicInt(tag.c_str(), 1);
        Message("[W] count: %i \n", readfds->fd_count);

        Message("[W] select(%i, %p, %p, %p, %i)\n", nfds, readfds, writefds, exceptfds, timeout);
        return 0;*/
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
        Message("[W] send (%p [|] %s [|] %i [|] %i)\n",
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
        Message("[W] sendto(%p [|] %s [|] %i [|] %i [|] %p [|] %i) tag_out:%s\n",
            s, buf, len, flags, to, tolen, tag.c_str());
        return ret;
    }

    return sendto(s, buf, len, flags, to, tolen);
}

u_short WSAAPI ntohshook(
    u_short netshort
) {
    u_short ret = ntohs(netshort);
    Message("[W] ntohs (%u) ret:%u\n", netshort, ret);
    return ret;
}

int WSAAPI getsocknamehook(
    SOCKET   s,
    sockaddr* name,
    int* namelen
) {
    int ret = getsockname(s, name, namelen);
    Message("[W] getsockname (%p [|] %p [|] %p) ret:%i\n", s, name, namelen, ret);
    return ret;
}

int WSAAPI getpeernamehook(
    SOCKET   s,
    sockaddr* name,
    int* namelen
)
{
    if (checkCaller("getpeername")) {
        char addr[11] = "8.8.8.8";
        sockaddr_in* fake = new sockaddr_in();
        fake->sin_family = AF_INET;
        fake->sin_port = htons(80);
        inet_pton(AF_INET, addr, &fake->sin_addr);
        name = (sockaddr*)&fake;
        *namelen = sizeof(name);

        Message("[W] getpeername (%p [|] %p [|] %p [|] %s [|] %d)\n", s, name, namelen, inet_ntoa(fake->sin_addr), (int)ntohs(fake->sin_port));
        return 0;
    }

    return getpeername(s, name, namelen);
}

INT WSAAPI getaddrinfohook(
    PCSTR           pNodeName,
    PCSTR           pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA* ppResult
) {
    if (checkCaller("getaddrinfo")) {
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
        Message("[W] getaddrinfo (%s [|] %s [|] %p [|] %p) ret:%s\n", pNodeName, pServiceName, pHints, ppResult, ip);
        return 0;
    }

    return getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

