#include <random>
#include "generate_code_verifier.hpp"

std::string generate_code_verifier(size_t length)
{
    static const std::string chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    std::random_device rd;
    std::mt19937 engine(rd());
    std::uniform_int_distribution<> dist(0, chars.size() - 1);

    std::string verifier;
    for (size_t i = 0; i < length; ++i) {
        verifier += chars[dist(engine)];
    }
    return verifier;
}