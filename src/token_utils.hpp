#include <string>

std::string base64url_decode(const std::string &input);
void dump_token(std::string token);
bool verify_jwt_signature(const std::string &token, const std::string &jwks_url);