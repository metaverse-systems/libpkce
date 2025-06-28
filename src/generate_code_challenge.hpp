#include <string>

std::string base64url_encode(const unsigned char *data, size_t len);
std::string generate_code_challenge(const std::string &verifier);