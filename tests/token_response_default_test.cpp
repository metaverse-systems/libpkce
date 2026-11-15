// A default-constructed TokenResponse reads as zero and empty.

#include <libpkce/exchange_token.hpp>

int main()
{
    TokenResponse r{};
    if (r.expires_in != 0) return 1;
    if (!r.access_token.empty() || !r.refresh_token.empty() || !r.id_token.empty()) return 1;
    TokenResponse d;
    return d.expires_in == 0 ? 0 : 1;
}
