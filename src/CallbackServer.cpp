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

    explicit Impl(int p) : port(p)
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
        if (listen_sock != INVALID_SOCK) {
            CLOSE_SOCKET(listen_sock);
            listen_sock = INVALID_SOCK;
        }
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

CallbackServer::CallbackServer(int port) : pImpl(std::make_unique<Impl>(port)) {}
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

        if (::listen(pImpl->listen_sock, 1) != 0) {
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
    // A failed listen() has no socket: return at once.
    if (pImpl->listen_sock == INVALID_SOCK) {
        return;
    }
    // A local copy: stop() closes and invalidates the member from another
    // thread; a stale fd just makes accept() fail and the loop ends.
    const socket_t sock = pImpl->listen_sock;

    // ── accept loop — blocks on accept(), no WSAPoll needed ─────────────────
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
            // accept() fails when stop() closes the listen socket — that's normal.
            break;
        }

        // Read the HTTP request (4 KiB is more than enough for a redirect GET)
        char buf[4096] = {};
        int n = ::recv(client, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
            CLOSE_SOCKET(client);
            continue;
        }
        buf[n] = '\0';
        std::string request(buf, static_cast<size_t>(n));

        std::string path = extract_request_path(request);

        // Parse query parameters
        std::string error = get_query_param(path, "error");
        if (!error.empty()) {
            // A return with error=: report the fixed flag (never the provider's
            // text) and keep accepting — the callback is not complete.
            pImpl->error_received = true;
            std::string desc = get_query_param(path, "error_description");
            std::string body = "Authentication failed: " + error +
                               (desc.empty() ? "" : " - " + desc);
            Impl::send_response(client, 200, "OK", "text/html", body);
            CLOSE_SOCKET(client);
            continue;
        }

        std::string code = get_query_param(path, "code");
        if (code.empty()) {
            // A return without a code: the same fixed flag, and the loop goes on.
            pImpl->error_received = true;
            Impl::send_response(client, 200, "OK", "text/html",
                                "No authorization code received");
            CLOSE_SOCKET(client);
            continue;
        }

        // ── success ────────────────────────────────────────────────────────
        Impl::send_response(client, 200, "OK", "text/html",
                            Impl::success_html(code));
        CLOSE_SOCKET(client);

        pImpl->auth_code     = code;
        pImpl->code_received = true;
        pImpl->error_received = false;
        break; // one successful callback is all we need
    }
}

void CallbackServer::stop()
{
    pImpl->should_stop = true;
    // shutdown() reliably unblocks a thread parked in accept(); close() alone
    // does not (the open file description stays alive under the blocked call).
    if (pImpl->listen_sock != INVALID_SOCK) {
#ifdef _WIN32
        ::shutdown(pImpl->listen_sock, SD_BOTH);
#else
        ::shutdown(pImpl->listen_sock, SHUT_RDWR);
#endif
    }
    pImpl->close_listen();
}

std::string CallbackServer::failure_reason() const
{
    return pImpl->failure_reason;
}

std::string CallbackServer::get_auth_code() const
{
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
