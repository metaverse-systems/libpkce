// stop() ends a serve() parked in recv() at once, and is safe to repeat or call early.

#include "loopback.hpp"

#ifdef LOOPBACK_UNAVAILABLE
int main() { return 77; }
#else
int main()
{
    int port = loopback::PortFor(200);
    {
        CallbackServer early(port, 30000);
        early.stop(); // before listen()
        early.stop();
    }
    CallbackServer server(port, 30000); // a timeout far longer than the test
    CHECK_TRUE(server.listen());
    int fd = loopback::Connect(port);
    CHECK_TRUE(fd >= 0);
    std::thread serving([&server]() { server.serve(); });
    loopback::Sleep(150); // the connection is now parked in recv
    auto start = std::chrono::steady_clock::now();
    server.stop();
    server.stop();
    serving.join();
    CHECK_TRUE(loopback::MsSince(start) < 500);
    CHECK_TRUE(!server.is_code_received());
    ::close(fd);
    return 0;
}
#endif
