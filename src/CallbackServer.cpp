// Minimal raw-socket HTTP callback server.
// Replaces cpp-httplib which relies on WSAPoll/WSAAccept — both broken under Wine.
// This server only needs to accept ONE HTTP GET with an OAuth2 authorization code.

#include <libpkce/CallbackServer.hpp>
#include <iostream>
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

// ── Impl ─────────────────────────────────────────────────────────────────────

struct CallbackServer::Impl
{
    int port;
    std::string auth_code;
    std::atomic<bool> code_received{false};
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

void CallbackServer::start()
{
    // ── create listen socket ────────────────────────────────────────────────
    pImpl->listen_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (pImpl->listen_sock == INVALID_SOCK) {
        std::cerr << "ERROR: Failed to create socket" << std::endl;
        return;
    }

    // Allow port reuse so restarts don't fail with "address in use"
    int opt = 1;
#ifdef _WIN32
    ::setsockopt(pImpl->listen_sock, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    ::setsockopt(pImpl->listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;   // bind to 0.0.0.0
    addr.sin_port        = htons(static_cast<uint16_t>(pImpl->port));

    if (::bind(pImpl->listen_sock, reinterpret_cast<struct sockaddr*>(&addr),
               sizeof(addr)) != 0) {
        std::cerr << "ERROR: Failed to bind to port " << pImpl->port << std::endl;
        pImpl->close_listen();
        return;
    }

    if (::listen(pImpl->listen_sock, 1) != 0) {
        std::cerr << "ERROR: listen() failed on port " << pImpl->port << std::endl;
        pImpl->close_listen();
        return;
    }

    // ── accept loop — blocks on accept(), no WSAPoll needed ─────────────────
    while (!pImpl->should_stop) {
        struct sockaddr_in client_addr{};
#ifdef _WIN32
        int client_len = sizeof(client_addr);
#else
        socklen_t client_len = sizeof(client_addr);
#endif
        socket_t client = ::accept(pImpl->listen_sock,
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
            std::string desc = get_query_param(path, "error_description");
            std::string body = "Authentication failed: " + error +
                               (desc.empty() ? "" : " - " + desc);
            Impl::send_response(client, 200, "OK", "text/html", body);
            CLOSE_SOCKET(client);
            continue;
        }

        std::string code = get_query_param(path, "code");
        if (code.empty()) {
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
        break; // one successful callback is all we need
    }
}

void CallbackServer::stop()
{
    pImpl->should_stop = true;
    pImpl->close_listen();     // unblocks the accept() call
}

std::string CallbackServer::get_auth_code() const
{
    return pImpl->auth_code;
}

bool CallbackServer::is_code_received() const
{
    return pImpl->code_received;
}
