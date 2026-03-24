#pragma once

#include <memory>
#include <string>

class CallbackServer
{
  private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;

  public:
    CallbackServer(int port);
    ~CallbackServer();
    CallbackServer(CallbackServer&&) noexcept;
    CallbackServer& operator=(CallbackServer&&) noexcept;

    void start();
    void stop();
    std::string get_auth_code() const;
    bool is_code_received() const;
};