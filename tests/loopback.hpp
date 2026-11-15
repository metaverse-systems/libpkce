#pragma once

// Helpers for the callback server tests: loopback clients and a few checks.
// POSIX sockets only; the programs skip (exit 77) on Windows.

#ifdef _WIN32
#define LOOPBACK_UNAVAILABLE 1
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

#include <libpkce/CallbackServer.hpp>

#define CHECK_TRUE(cond)                                                          \
    do {                                                                          \
        if (!(cond)) {                                                            \
            std::fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
            std::exit(1);                                                         \
        }                                                                         \
    } while (0)

namespace loopback
{
    // A port unlikely to be taken, derived from the pid so parallel runs differ.
    inline int PortFor(int offset) { return 20000 + (getpid() % 20000) + offset; }

    inline int Connect(int port)
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(static_cast<uint16_t>(port));
        if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
            ::close(fd);
            return -1;
        }
        return fd;
    }

    inline void Write(int fd, const std::string &s) { (void)::send(fd, s.data(), s.size(), MSG_NOSIGNAL); }

    inline std::string Redirect(const std::string &code = "abc")
    {
        return "GET /?code=" + code + "&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n";
    }

    // Sends a full redirect on a fresh connection and reads until the peer closes.
    inline void SendRedirect(int port, const std::string &code = "abc")
    {
        int fd = Connect(port);
        if (fd < 0) return;
        Write(fd, Redirect(code));
        char buf[512];
        while (::recv(fd, buf, sizeof(buf), 0) > 0) {}
        ::close(fd);
    }

    inline long long MsSince(std::chrono::steady_clock::time_point t)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t).count();
    }

    inline void Sleep(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }
}
#endif
