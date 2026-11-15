// A request delivered in two writes, closer together than the timeout, completes.

#include "loopback.hpp"

#ifdef LOOPBACK_UNAVAILABLE
int main() { return 77; }
#else
int main()
{
    int port = loopback::PortFor(100);
    CallbackServer server(port, 1000);
    CHECK_TRUE(server.listen());
    std::thread client([port]() {
        int fd = loopback::Connect(port);
        if (fd < 0) return;
        std::string full = loopback::Redirect("split");
        loopback::Write(fd, full.substr(0, 12));
        loopback::Sleep(100);
        loopback::Write(fd, full.substr(12));
        char buf[512];
        while (::recv(fd, buf, sizeof(buf), 0) > 0) {}
        ::close(fd);
    });
    server.serve();
    client.join();
    CHECK_TRUE(server.is_code_received());
    CHECK_TRUE(server.get_auth_code() == "split");
    return 0;
}
#endif
