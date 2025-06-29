#include "openssl_compat.h"
#include <string>
#include "httplib.h"

class CallbackServer
{
  private:
    int port;
    httplib::Server svr;
    std::string auth_code;
    bool code_received = false;
    
  public:
    CallbackServer(int port);
    void start();
    void stop();
    std::string get_auth_code() const;
    bool is_code_received() const;
};