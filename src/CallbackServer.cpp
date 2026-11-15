// Minimal raw-socket HTTP callback server.
// Replaces cpp-httplib which relies on WSAPoll/WSAAccept — both broken under Wine.
// This server only needs to accept ONE HTTP GET with an OAuth2 authorization code.
//
// listen() is synchronous (create, bind, listen) and reports a fixed,
// credential-free reason on failure; serve() is the accept loop. The listener
// binds 127.0.0.1 only: on Windows the exclusive address use keeps another
// process from sharing the port, on POSIX SO_REUSEADDR avoids TIME_WAIT
// failures on a quick retry.

#include <libpkce/CallbackServer.hpp>
#include <sstream>
#include <string>
#include <cstring>
#include <atomic>
#include <list>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET socket_t;
  #define CLOSE_SOCKET(s) closesocket(s)
  static constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <cerrno>
  typedef int socket_t;
  #define CLOSE_SOCKET(s) ::close(s)
  static constexpr socket_t INVALID_SOCK = -1;
#endif

// ── helpers ──────────────────────────────────────────────────────────────────

// Extract the value of a query-string parameter (e.g. "code") from a URI path.
static std::string get_query_param(const std::string &path, const std::string &key)
{
    std::string search = key + "=";
    auto pos = path.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();
    auto end = path.find('&', pos);
    return (end == std::string::npos) ? path.substr(pos) : path.substr(pos, end - pos);
}

// Extract the request path from the first line of an HTTP request.
// e.g. "GET /?code=abc HTTP/1.1\r\n..." → "/?code=abc"
static std::string extract_request_path(const std::string &raw)
{
    auto start = raw.find(' ');
    if (start == std::string::npos) return {};
    start++; // skip space after method
    auto end = raw.find(' ', start);
    if (end == std::string::npos) return {};
    return raw.substr(start, end - start);
}

// The fixed failure phrases, chosen from the failing step and the errno class.
// They never carry request data or a port number.
static const char *const kCouldNotCreateSocket = "could not create socket";
static const char *const kAddressInUse = "address already in use";
static const char *const kPermissionDenied = "permission denied";

static std::string classify_bind_error(int err)
{
#ifdef _WIN32
    if (err == WSAEADDRINUSE) return kAddressInUse;
    if (err == WSAEACCES) return kPermissionDenied;
#else
    if (err == EADDRINUSE) return kAddressInUse;
    if (err == EACCES) return kPermissionDenied;
#endif
    return kCouldNotCreateSocket;
}

// ── Impl ─────────────────────────────────────────────────────────────────────

struct CallbackServer::Impl
{
    int port;
    std::string auth_code;
    std::atomic<bool> code_received{false};
    std::atomic<bool> error_received{false};
    std::string failure_reason;
    socket_t listen_sock = INVALID_SOCK;
    std::atomic<bool> should_stop{false};
    int receive_timeout_ms;

    static constexpr size_t kMaxLiveConnections = 8;

    // One handler thread per accepted connection; `done` lets the accept loop reap it.
    struct Handler
    {
        std::thread thread;
        std::atomic<bool> done{false};
    };

    std::mutex lock;                  // guards listen_sock, live_connections, auth_code
    std::set<socket_t> live_connections;
    std::list<Handler> handlers;      // touched by the serving thread only

    Impl(int p, int timeout_ms) : port(p), receive_timeout_ms(timeout_ms > 0 ? timeout_ms : 2000)
    {
#ifdef _WIN32
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    }

    ~Impl()
    {
        close_listen();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    void close_listen()
    {
        std::lock_guard<std::mutex> guard(lock);
        if (listen_sock != INVALID_SOCK) {
#ifdef _WIN32
            ::shutdown(listen_sock, SD_BOTH);
#else
            ::shutdown(listen_sock, SHUT_RDWR);
#endif
            CLOSE_SOCKET(listen_sock);
            listen_sock = INVALID_SOCK;
        }
    }

    // Unblocks every handler parked in recv(); each handler closes its own socket.
    void shutdown_connections()
    {
        std::lock_guard<std::mutex> guard(lock);
        for (socket_t c : live_connections) {
#ifdef _WIN32
            ::shutdown(c, SD_BOTH);
#else
            ::shutdown(c, SHUT_RDWR);
#endif
        }
    }

    void set_receive_timeout(socket_t client) const
    {
#ifdef _WIN32
        DWORD tv = static_cast<DWORD>(receive_timeout_ms);
        ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        struct timeval tv{};
        tv.tv_sec = receive_timeout_ms / 1000;
        tv.tv_usec = (receive_timeout_ms % 1000) * 1000;
        ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

    // Reads one request (up to the blank line, 4 KiB at most). False on a timeout,
    // a close or a stop with the request incomplete.
    bool read_request(socket_t client, std::string &request) const
    {
        char buf[4096];
        while (request.size() < sizeof(buf)) {
            if (should_stop) return false;
            int n = ::recv(client, buf, static_cast<int>(sizeof(buf) - request.size()), 0);
            if (n <= 0) return false;
            request.append(buf, static_cast<size_t>(n));
            if (request.find("\r\n\r\n") != std::string::npos) return true;
        }
        return true;
    }

    // Answers one connection. Returns true when it carried the authorization code.
    void handle(socket_t client)
    {
        set_receive_timeout(client);
        {
            std::lock_guard<std::mutex> guard(lock);
            live_connections.insert(client);
        }
        handle_request(client);
        {
            std::lock_guard<std::mutex> guard(lock);
            live_connections.erase(client);
        }
        CLOSE_SOCKET(client);
    }

    void handle_request(socket_t client)
    {
        std::string request;
        if (!read_request(client, request)) {
            return; // silent, partial or stopped: dropped
        }
        std::string path = extract_request_path(request);

        std::string error = get_query_param(path, "error");
        if (!error.empty()) {
            // A return with error=: report the fixed flag (never the provider's
            // text) and keep accepting; the callback is not complete.
            error_received = true;
            std::string desc = get_query_param(path, "error_description");
            std::string body = "Authentication failed: " + error +
                               (desc.empty() ? "" : " - " + desc);
            send_response(client, 200, "OK", "text/html", body);
            return;
        }

        std::string code = get_query_param(path, "code");
        if (code.empty()) {
            error_received = true;
            send_response(client, 200, "OK", "text/html", "No authorization code received");
            return;
        }

        send_response(client, 200, "OK", "text/html", success_html(code));
        {
            std::lock_guard<std::mutex> guard(lock);
            if (code_received) return; // the first code wins
            auth_code = code;
            code_received = true;
            error_received = false;
        }
        // One successful callback is all we need: end the accept loop.
        should_stop = true;
        std::lock_guard<std::mutex> guard(lock);
        if (listen_sock != INVALID_SOCK) {
#ifdef _WIN32
            ::shutdown(listen_sock, SD_BOTH);
#else
            ::shutdown(listen_sock, SHUT_RDWR);
#endif
        }
    }

    void reap_finished()
    {
        for (auto it = handlers.begin(); it != handlers.end();) {
            if (it->done) {
                it->thread.join();
                it = handlers.erase(it);
            } else {
                ++it;
            }
        }
    }

    void join_all()
    {
        should_stop = true;
        shutdown_connections();
        for (auto &h : handlers) {
            if (h.thread.joinable()) h.thread.join();
        }
        handlers.clear();
    }

    // Build the HTML response body for a given auth code.
    static std::string success_html(const std::string &code)
    {
        return R"(<!DOCTYPE html>
<html>
<head>
    <title>Authentication Success</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .success { color: green; }
        .code { background: #f0f0f0; padding: 10px; margin: 20px; word-break: break-all; }
    </style>
</head>
<body>
    <h1 class="success">Authentication Successful!</h1>
    <p>Authorization code received:</p>
    <div class="code">)" + code + R"(</div>
    <p>You can close this window.</p>
</body>
</html>)";
    }

    // Format & send a complete HTTP/1.1 response, then close the client socket.
    static void send_response(socket_t client, int status,
                              const std::string &status_text,
                              const std::string &content_type,
                              const std::string &body)
    {
        std::ostringstream resp;
        resp << "HTTP/1.1 " << status << " " << status_text << "\r\n"
             << "Content-Type: " << content_type << "\r\n"
             << "Content-Length: " << body.size() << "\r\n"
             << "Connection: close\r\n"
             << "\r\n"
             << body;
        std::string data = resp.str();
        ::send(client, data.c_str(), static_cast<int>(data.size()), 0);
    }
};

// ── public API ───────────────────────────────────────────────────────────────

CallbackServer::CallbackServer(int port, int receive_timeout_ms)
    : pImpl(std::make_unique<Impl>(port, receive_timeout_ms)) {}
CallbackServer::~CallbackServer() = default;
CallbackServer::CallbackServer(CallbackServer&&) noexcept = default;
CallbackServer& CallbackServer::operator=(CallbackServer&&) noexcept = default;

bool CallbackServer::listen() noexcept
{
    try
    {
        // ── create listen socket ────────────────────────────────────────────────
        pImpl->listen_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (pImpl->listen_sock == INVALID_SOCK) {
            pImpl->failure_reason = kCouldNotCreateSocket;
            return false;
        }

        int opt = 1;
#ifdef _WIN32
        // Exclusive address use: a second process cannot bind the same port
        // (SO_REUSEADDR would let it receive this login).
        ::setsockopt(pImpl->listen_sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
        // SO_REUSEADDR on POSIX does not permit two listeners; it only avoids
        // TIME_WAIT failures on a quick retry.
        ::setsockopt(pImpl->listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only
        addr.sin_port        = htons(static_cast<uint16_t>(pImpl->port));

        if (::bind(pImpl->listen_sock, reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)) != 0) {
            pImpl->failure_reason = classify_bind_error(
#ifdef _WIN32
                WSAGetLastError()
#else
                errno
#endif
            );
            pImpl->close_listen();
            return false;
        }

        if (::listen(pImpl->listen_sock, 32) != 0) {
            pImpl->failure_reason = kCouldNotCreateSocket;
            pImpl->close_listen();
            return false;
        }

        return true;
    }
    catch (...)
    {
        pImpl->close_listen();
        return false;
    }
}

void CallbackServer::serve()
{
    socket_t sock;
    {
        std::lock_guard<std::mutex> guard(pImpl->lock);
        sock = pImpl->listen_sock;
    }
    // A failed listen() has no socket: return at once.
    if (sock == INVALID_SOCK) {
        return;
    }

    // Accept loop: each connection gets its own handler thread so a silent one
    // cannot hold up the real redirect.
    while (!pImpl->should_stop) {
        struct sockaddr_in client_addr{};
#ifdef _WIN32
        int client_len = sizeof(client_addr);
#else
        socklen_t client_len = sizeof(client_addr);
#endif
        socket_t client = ::accept(sock,
                                   reinterpret_cast<struct sockaddr*>(&client_addr),
                                   &client_len);
        if (client == INVALID_SOCK) {
            // accept() fails when stop() closes the listen socket: that's normal.
            break;
        }
        pImpl->reap_finished();
        if (pImpl->should_stop || pImpl->handlers.size() >= Impl::kMaxLiveConnections) {
            CLOSE_SOCKET(client);
            continue;
        }
        pImpl->handlers.emplace_back();
        Impl::Handler &h = pImpl->handlers.back();
        Impl *impl = pImpl.get();
        try {
            h.thread = std::thread([impl, client, &h]() {
                impl->handle(client);
                h.done = true;
            });
        } catch (...) {
            pImpl->handlers.pop_back();
            CLOSE_SOCKET(client);
        }
    }
    pImpl->join_all();
}

void CallbackServer::stop()
{
    pImpl->should_stop = true;
    // shutdown() reliably unblocks a thread parked in accept(); close() alone
    // does not (the open file description stays alive under the blocked call).
    pImpl->close_listen();
    pImpl->shutdown_connections();
}

std::string CallbackServer::failure_reason() const
{
    return pImpl->failure_reason;
}

std::string CallbackServer::get_auth_code() const
{
    std::lock_guard<std::mutex> guard(pImpl->lock);
    return pImpl->auth_code;
}

bool CallbackServer::is_code_received() const
{
    return pImpl->code_received;
}

bool CallbackServer::error_received() const
{
    return pImpl->error_received;
}
