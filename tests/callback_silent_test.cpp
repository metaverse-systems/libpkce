// Silent and partial connections never block the real redirect.

#include "loopback.hpp"

#ifdef LOOPBACK_UNAVAILABLE
int main() { return 77; }
#else
#include <atomic>
#include <vector>

namespace
{
    // Opens `silent` silent connections, then delivers the real redirect from another
    // thread; serve() must return the code within the bound.
    void RunWithSilent(int port, int silent, bool halfSent)
    {
        CallbackServer server(port, 200);
        CHECK_TRUE(server.listen());
        std::vector<int> fds;
        for (int i = 0; i < silent; ++i) {
            int fd = loopback::Connect(port);
            CHECK_TRUE(fd >= 0);
            if (halfSent) loopback::Write(fd, "GET /?code=nope");
            fds.push_back(fd);
        }
        auto start = std::chrono::steady_clock::now();
        // A connection beyond the cap is closed at once, so the real sender tries again
        // until the silent ones have timed out and the redirect is taken.
        std::atomic<bool> finished{false};
        std::thread real([port, &finished]() {
            loopback::Sleep(50);
            while (!finished) { loopback::SendRedirect(port, "good"); loopback::Sleep(50); }
        });
        server.serve();
        finished = true;
        real.join();
        CHECK_TRUE(loopback::MsSince(start) < 5000);
        CHECK_TRUE(server.is_code_received());
        CHECK_TRUE(server.get_auth_code() == "good");
        for (int fd : fds) ::close(fd);
    }
}

int main()
{
    int port = loopback::PortFor(0);
    RunWithSilent(port++, 1, false);   // one silent connection
    RunWithSilent(port++, 8, false);   // up to the cap
    RunWithSilent(port++, 20, false);  // more than the cap
    RunWithSilent(port++, 1, true);    // half a request, then silence
    return 0;
}
#endif
