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
        
        if (retSocket == INVALID_SOCKET) {
            SOCKET rSocket = (SOCKET)malloc(sizeof(SOCKET));
            dummySockets.insert(rSocket);
           
            Message("[W] socket(%i [|] %i [|] %i) ret:%p\n",
                af, type, protocol, rSocket);

            return rSocket;
        }
        Message("[W] socket(%i [|] %i [|] %i) ret:%p\n",
            af, type, protocol, retSocket);
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

        std::string tagin = ReadTag((PVOID)name->sa_data);

        S2EDisableForking();

        Message("[W] connect(%p [|] %p [|] %d) tag_in:%s", s, name, namelen, tagin.c_str());

        std::set<SOCKET>::iterator it = dummySockets.find(s);

        if (it == dummySockets.end()) {
            connect(s, name, namelen);
        }

        S2EEnableForking();
        return 0;
    }
    return connect(s, name, namelen);
}

hostent* WSAAPI gethostbynamehook(
    const char* name
) {
    if (checkCaller("gethostbyname")) {

        std::string tagin = ReadTag((PVOID)name);
        bool isTaint = IsTainted((PVOID)name);

        if (tagin != "") {

            std::string tagout = GetTag("gethostbyname");

            S2EDisableForking();

            Message("[W] gethostbyname (%s) tag_in:%s tag_out:%s", name, tagin.c_str(), tagout.c_str());

            struct hostent* remoteHost;

            remoteHost = gethostbyname(name);

            if (remoteHost == NULL) {
                remoteHost = gethostbyname("www.google.com");
            }

            if (remoteHost) {
                int i = 0;
                while (remoteHost->h_addr_list[i] != 0) {
                    cyfiTaint(remoteHost->h_addr_list[i], strlen(remoteHost->h_addr_list[i]), tagout.c_str());
                    i++;
                }
            }

            S2EEnableForking();

            return remoteHost;
        }

        else {
            Message("[W] gethostbyname (%s)", name);

            struct hostent* remoteHost;

            remoteHost = gethostbyname(name);

            if (remoteHost == NULL) {
                remoteHost = gethostbyname("www.google.com");
            }
            return remoteHost;
        }
    }
    else {
        return gethostbyname(name);
    }
}

INT WSAAPI bindhook(
    SOCKET s,
    const sockaddr* addr,
    int namelen
) {
    if (checkCaller("bind")) {
        S2EDisableForking();
        Message("[W] bind (%p, %p, %d)", s, addr, namelen);

        std::set<SOCKET>::iterator it = dummySockets.find(s);

        if (it == dummySockets.end()) {
            INT ret = bind(s, addr, namelen);
        }
        
        S2EEnableForking();
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

        std::set<SOCKET>::iterator it = dummySockets.find(s);

        int success = 0;

        if (it == dummySockets.end()) {
            success = recv(s, buf, len, flags);
        }

        if (success != SOCKET_ERROR) {
            cyfiTaint(buf, success, tag.c_str());
            Message("[W] recv (%p [|] %p [|] %i [|] %i) ret:%i tag_out:%s\n", s, buf, len, flags, success, tag.c_str());
            return success;
        }
        else {
            UINT32 bytesToRead = min(len, DEFAULT_MEM_LEN);
            Message("[W] recv (%p [|] %p [|] %i [|] %i) ret:%i tag_out:%s\n", s, buf, len, flags, bytesToRead, tag.c_str());
            S2EMakeSymbolic(buf, bytesToRead, tag.c_str());
            // Symbolic return
            //INT bytesRead = S2ESymbolicInt(tag.c_str(), bytesToRead);
            return bytesToRead;//bytesRead;
        }
        
    }

    return recv(s, buf, len, flags);
}

SOCKET WSAAPI accepthook(
    SOCKET   s,
    sockaddr* addr,
    int* addrlen
) {
    if (checkCaller("accept")) {

        std::set<SOCKET>::iterator it = dummySockets.find(s);

        SOCKET acceptSocket;

        if (it == dummySockets.end()) {
            acceptSocket = accept(s, addr, addrlen);

            if (acceptSocket == INVALID_SOCKET) {
                acceptSocket = (SOCKET)malloc(sizeof(SOCKET));
                dummySockets.insert(acceptSocket);
            }
        }
        else {

            SOCKET acceptSocket = (SOCKET)malloc(sizeof(SOCKET));
            dummySockets.insert(acceptSocket);
        }

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
            Message("[W] select (%i [|] %i [|] %i [|] %p [|] %p) ret:%i\n", nfds, readfds->fd_count, writefds->fd_count, exceptfds, timeout, socketCount);
            return socketCount;
        }
        return 0;
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

        INT ret = len;
        std::string tagin = ReadTag((PVOID)buf);

        S2EDisableForking();

        Message("[W] send (%p [|] %s [|] %i [|] %i) tag_in:%s\n",
                s, buf, len, flags, tagin.c_str());

        std::set<SOCKET>::iterator it = dummySockets.find(s);

        if (it == dummySockets.end()) {
            ret = send(s, buf, len, flags);
            if (ret == SOCKET_ERROR) {
                ret = len;
            }
        }

        S2EEnableForking();
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
        std::string target_tag_in = ReadTag((PVOID)to->sa_data);
        std::string content_tag_in = ReadTag((PVOID)buf);
        
        S2EDisableForking();
        INT ret = len;
        Message("[W] sendto(%p [|] %s [|] %i [|] %i [|] %p [|] %i) tag_in:%s %s tag_out:%s\n",
            s, buf, len, flags, to, tolen, target_tag_in.c_str(), content_tag_in.c_str(), tag.c_str());

        std::set<SOCKET>::iterator it = dummySockets.find(s);

        if (it == dummySockets.end()) {
            ret = sendto(s, buf, len, flags, to, tolen);
            if (ret == SOCKET_ERROR) {
                ret = len;
            }
        }

        S2EEnableForking();
        return ret;
    }

    return sendto(s, buf, len, flags, to, tolen);
}

u_short WSAAPI ntohshook(
    u_short netshort
) {
    if (checkCaller("ntohs")) {
        u_short ret = ntohs(netshort);
        Message("[W] ntohs (%u) ret:%u\n", netshort, ret);
        return ret;
    }
    else {
        return ntohs(netshort);
    }
}

int WSAAPI getsocknamehook(
    SOCKET   s,
    sockaddr* name,
    int* namelen
) {
    if (checkCaller("getsockname")) {
        int ret = getsockname(s, name, namelen);
        Message("[W] getsockname (%p [|] %p [|] %p) ret:%i\n", s, name, namelen, ret);
        return 0;
    }

    return getsockname(s, name, namelen);
    
}

int WSAAPI getpeernamehook(
    SOCKET   s,
    sockaddr* name,
    int* namelen
)
{
    if (checkCaller("getpeername")) {

        S2EDisableForking();

        int concrete_res = getpeername(s, name, namelen);

        if (concrete_res == 0) {
            Message("[W] getpeername (%p [|] %p [|] %p)\n", s, name, namelen);
            S2EEnableForking();
            return 0;
        }
        else {
            char addr[11] = "8.8.8.8";
            sockaddr_in* fake = new sockaddr_in();
            fake->sin_family = AF_INET;
            fake->sin_port = htons(80);
            inet_pton(AF_INET, addr, &fake->sin_addr);
            name = (sockaddr*)&fake;
            *namelen = sizeof(name);

            Message("[W] getpeername (%p [|] %p [|] %p [|] %s [|] %d)\n", s, name, namelen, inet_ntoa(fake->sin_addr), (int)ntohs(fake->sin_port));
            S2EEnableForking();
            return 0;
        }
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
        std::string nodetag = "";
        std::string servicetag = "";

        if (pNodeName != NULL) {
            nodetag = ReadTag((PVOID)pNodeName);
        }

        if (pServiceName != NULL) {
            servicetag = ReadTag((PVOID)pServiceName);
        }
        
        std::string tag = GetTag("getaddrinfo");

        S2EDisableForking();

        if (nodetag != "" || servicetag != "") {

            if (pNodeName != NULL && pServiceName != NULL) {
                Message("[W] getaddrinfo (%s [|] %s [|] %p [|] %p) tag_in: %s %s tag_out: %s", pNodeName, pServiceName, pHints, ppResult, nodetag.c_str(), servicetag.c_str(), tag.c_str());
            }

            else if (pNodeName == NULL && pServiceName != NULL) {
                Message("[W] getaddrinfo (%p [|] %s [|] %p [|] %p) tag_in: %s %s tag_out: %s", pNodeName, pServiceName, pHints, ppResult, nodetag.c_str(), servicetag.c_str(), tag.c_str());
            }

            else if (pNodeName != NULL && pServiceName == NULL) {
                Message("[W] getaddrinfo (%s [|] %p [|] %p [|] %p) tag_in: %s %s tag_out: %s", pNodeName, pServiceName, pHints, ppResult, nodetag.c_str(), servicetag.c_str(), tag.c_str());
            }

            else {
                Message("[W] getaddrinfo (%p [|] %p [|] %p [|] %p) tag_in: %s %s tag_out: %s", pNodeName, pServiceName, pHints, ppResult, nodetag.c_str(), servicetag.c_str(), tag.c_str());
            }

        }

        int conres = getaddrinfo(pNodeName, pServiceName, pHints, ppResult);

        if (conres != 0) {
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
        }

        if (ppResult && (*ppResult)->ai_addr) {
            cyfiTaint((*ppResult)->ai_addr->sa_data, strlen((*ppResult)->ai_addr->sa_data), tag.c_str());

        }

        S2EEnableForking();
        
        return 0;
        
    }

    return getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

char* WSAAPI inet_ntoahook(
    in_addr in
) {
    if (checkCaller("inet_ntoa")) {
        std::string tagin = ReadTag((PVOID)&in);
        std::string tagout = "";
        if (tagin != "") {
            tagout = GetTag("inet_ntoa");
        }
        S2EDisableForking();

        char* res = inet_ntoa(in);

        if (res == NULL) {
            res = "8.8.8.8";
        }

        if (tagin != "") {
            cyfiTaint(res, strlen(res), tagout.c_str());
        }

        Message("[M] inot_ntoa tag_in:%s tag_out:%s", tagin.c_str(), tagout.c_str());

        S2EEnableForking();

        return res;

    }
    else {
        return inet_ntoa(in);
    }
}

PCSTR WSAAPI inet_ntophook(
    INT        Family,
    const VOID* pAddr,
    PSTR       pStringBuf,
    size_t     StringBufSize
) {
    if (checkCaller("inet_ntop")) {

        S2EDisableForking();

        std::string tagin = "";
        std::string tagout = "";
        if (pAddr) {
            std::string tagin = ReadTag((PVOID)pAddr);
            if (tagin != "") {
                std::string tagout = GetTag("inet_ntop");
            }
        }
        PCSTR res = inet_ntop(Family, (PVOID)pAddr, pStringBuf, StringBufSize);

        if (res == NULL) {
            res = "8.8.8.8";
            strcpy(pStringBuf, res);
        }

        if (tagout != "") {
            cyfiTaint(pStringBuf, strlen(pStringBuf), tagout.c_str());
        }

        Message("[W] inet_ntop () tag_in:%s, tag_out:%s", tagin.c_str(), tagout.c_str());

        S2EEnableForking();

        return res;
    }

    return inet_ntop(Family, (PVOID)pAddr, pStringBuf, StringBufSize);
}

