#pragma once

#include <memory>
#include <string>

class CallbackServer
{
  private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;

  public:
    // receive_timeout_ms bounds how long one accepted connection may stay silent or
    // incomplete before it is dropped; a non-positive value means the default (2000 ms).
    explicit CallbackServer(int port, int receive_timeout_ms = 2000);
    ~CallbackServer();
    CallbackServer(CallbackServer&&) noexcept;
    CallbackServer& operator=(CallbackServer&&) noexcept;

    // Create, bind (127.0.0.1 only) and listen. Synchronous and never blocking:
    // it returns true when the listener is up, false when the port is occupied
    // (or the socket could not be created), with the reason in failure_reason().
    bool listen() noexcept;
    // The accept loop. Blocks until a code arrives or stop(); call after a
    // true listen(). Returns at once after a failed listen(). Connections are served
    // concurrently (at most 8 live; a connection beyond that is closed at once), each
    // with its own receive timeout, so a silent connection never blocks the real redirect.
    void serve();
    // Non-blocking: closes the listen socket and every live connection so a serve()
    // parked in accept() or recv() returns at once. Safe from any thread, twice, or
    // before listen().
    void stop();
    // Empty unless listen() returned false. A fixed phrase chosen from the
    // failing step and the errno class; it never carries request data.
    std::string failure_reason() const;
    std::string get_auth_code() const;
    bool is_code_received() const;
    // True when a return carried error= or no code (a code return clears it).
    // A fixed flag: never the provider's text.
    bool error_received() const;
};
