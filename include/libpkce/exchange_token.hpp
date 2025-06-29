#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <string>
#include "httplib.h"

struct TokenResponse {
    std::string access_token;
    std::string id_token;
    std::string refresh_token;
    int expires_in;
    std::string token_type;
    std::string scope;
};

void dump_token_response(const TokenResponse &token_response);

bool exchange_token(const std::string &token_url,
                    const std::string &client_id,
                    const std::string &code,
                    const std::string &redirect_uri,
                    const std::string &code_verifier,
                    TokenResponse &token_response);