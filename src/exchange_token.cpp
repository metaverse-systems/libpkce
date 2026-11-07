#include <libpkce/exchange_token.hpp>
#include <libpkce/json.hpp>

#include <utility>

namespace
{
    // Split the host part of a URL into the hostname and the port. When the
    // host carries a port (host:port) it is returned; otherwise the default
    // port for https (443) is. This lets the client reach a token endpoint on
    // a non-default port (a loopback test server, or a local endpoint).
    std::pair<std::string, int> ParseHostPort(const std::string &host)
    {
        size_t colon = host.rfind(':');
        if (colon != std::string::npos)
        {
            std::string port_str = host.substr(colon + 1);
            bool all_digits = !port_str.empty();
            for (char c : port_str)
            {
                if (c < '0' || c > '9')
                {
                    all_digits = false;
                    break;
                }
            }
            if (all_digits)
            {
                return {host.substr(0, colon), std::stoi(port_str)};
            }
        }
        return {host, 443};
    }
}

void dump_token_response(const TokenResponse &token_response)
{
    std::cout << "Access token: " << token_response.access_token << std::endl;
    std::cout << "ID token: " << token_response.id_token << std::endl;
    std::cout << "Refresh token: " << token_response.refresh_token << std::endl;
    std::cout << "Expires in: " << token_response.expires_in << std::endl;
    std::cout << "Token type: " << token_response.token_type << std::endl;
    std::cout << "Scope: " << token_response.scope << std::endl;
}

bool exchange_token(const std::string &token_url,
                    const std::string &client_id,
                    const std::string &code,
                    const std::string &redirect_uri,
                    const std::string &code_verifier,
                    TokenResponse &token_response)
{
    // Extract hostname and path from the token_url
    std::string hostname;
    std::string path;
    
    if (token_url.find("https://") == 0) {
        std::string url_without_scheme = token_url.substr(8); // Remove "https://"
        size_t slash_pos = url_without_scheme.find('/');
        if (slash_pos != std::string::npos) {
            hostname = url_without_scheme.substr(0, slash_pos);
            path = url_without_scheme.substr(slash_pos);
        } else {
            hostname = url_without_scheme;
            path = "/";
        }
    } else {
        hostname = token_url;
        path = "/";
    }
    
    // Use the path directly from the token_url (no need to append anything)
    std::string endpoint_path = path;

    // The host may carry a port (host:port); the default is 443. The timeouts
    // are bounded so a hanging endpoint ends the call within a bounded time
    // (connection 10 s, read and write 30 s) instead of waiting indefinitely.
    auto host_and_port = ParseHostPort(hostname);
    httplib::SSLClient cli(host_and_port.first, host_and_port.second);
    cli.set_connection_timeout(10, 0); // 10 seconds timeout
    cli.set_read_timeout(30, 0);
    cli.set_write_timeout(30, 0);
    
    httplib::Params params;
    params.emplace("client_id", client_id);
    params.emplace("grant_type", "authorization_code");
    params.emplace("code", code);
    params.emplace("redirect_uri", redirect_uri);
    params.emplace("code_verifier", code_verifier);

    httplib::Headers headers = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Accept", "application/json"}
    };

    auto res = cli.Post(endpoint_path, headers, params);

    if (res && res->status == 200) {
        try {
            // Parse JSON response
            auto json = nlohmann::json::parse(res->body);
            token_response.access_token = json.value("access_token", "");
            token_response.id_token = json.value("id_token", "");
            token_response.refresh_token = json.value("refresh_token", "");
            token_response.expires_in = json.value("expires_in", 0);
            token_response.token_type = json.value("token_type", "");
            token_response.scope = json.value("scope", "");
            return true;
        } catch (const std::exception& e) {
            std::cerr << "JSON parsing error: " << e.what() << std::endl;
            std::cerr << "Response body: " << res->body << std::endl;
            return false;
        }
    } else {
        if (res) {
            std::cerr << "Token exchange failed. HTTP status: " << res->status << std::endl;
            std::cerr << "Response body: " << res->body << std::endl;
        } else {
            std::cerr << "Token exchange failed. No response received (network error)" << std::endl;
        }
        return false;
    }
}

bool refresh_token(const std::string &token_url,
                   const std::string &client_id,
                   const std::string &refresh_token,
                   TokenResponse &token_response)
{
    // Extract hostname and path from the token_url
    std::string hostname;
    std::string path;
    
    if (token_url.find("https://") == 0) {
        std::string url_without_scheme = token_url.substr(8); // Remove "https://"
        size_t slash_pos = url_without_scheme.find('/');
        if (slash_pos != std::string::npos) {
            hostname = url_without_scheme.substr(0, slash_pos);
            path = url_without_scheme.substr(slash_pos);
        } else {
            hostname = url_without_scheme;
            path = "/";
        }
    } else {
        hostname = token_url;
        path = "/";
    }
    
    // Use the path directly from the token_url (no need to append anything)
    std::string endpoint_path = path;

    // The host may carry a port (host:port); the default is 443. The timeouts
    // are bounded so a hanging endpoint ends the call within a bounded time
    // (connection 10 s, read and write 30 s) instead of waiting indefinitely.
    auto host_and_port = ParseHostPort(hostname);
    httplib::SSLClient cli(host_and_port.first, host_and_port.second);
    cli.set_connection_timeout(10, 0); // 10 seconds timeout
    cli.set_read_timeout(30, 0);
    cli.set_write_timeout(30, 0);
    
    httplib::Params params;
    params.emplace("client_id", client_id);
    params.emplace("grant_type", "refresh_token");
    params.emplace("refresh_token", refresh_token);

    httplib::Headers headers = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Accept", "application/json"}
    };

    auto res = cli.Post(endpoint_path, headers, params);

    if (res && res->status == 200) {
        try {
            // Parse JSON response
            auto json = nlohmann::json::parse(res->body);
            token_response.access_token = json.value("access_token", "");
            token_response.id_token = json.value("id_token", "");
            token_response.refresh_token = json.value("refresh_token", "");
            token_response.expires_in = json.value("expires_in", 0);
            token_response.token_type = json.value("token_type", "");
            token_response.scope = json.value("scope", "");
            return true;
        } catch (const std::exception& e) {
            std::cerr << "JSON parsing error: " << e.what() << std::endl;
            std::cerr << "Response body: " << res->body << std::endl;
            return false;
        }
    } else {
        if (res) {
            std::cerr << "Token refresh failed. HTTP status: " << res->status << std::endl;
            std::cerr << "Response body: " << res->body << std::endl;
        } else {
            std::cerr << "Token refresh failed. No response received (network error)" << std::endl;
        }
        return false;
    }
}