#include <iostream>
#include <thread>
#include <chrono>
#include <fstream>
#include <libpkce/generate_code_verifier.hpp>
#include <libpkce/generate_code_challenge.hpp>
#include <libpkce/CallbackServer.hpp>
#include <libpkce/exchange_token.hpp>
#include <libpkce/json.hpp>
#include <libpkce/httplib.h>
#include <libpkce/token_utils.hpp>
#include <jwt-cpp/jwt.h>
#include "Config.hpp"

int main(int argc, char *argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config.json>" << std::endl;
        std::cerr << "Example config.json format:" << std::endl;
        std::cerr << "{" << std::endl;
        std::cerr << "  \"tenant_id\": \"your-tenant-id\"," << std::endl;
        std::cerr << "  \"client_id\": \"your-client-id\"," << std::endl;
        std::cerr << "  \"login_url\": \"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&response_mode=query&code_challenge={code_challenge}&code_challenge_method=S256\"," << std::endl;
        std::cerr << "  \"token_url\": \"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token\"," << std::endl;
        std::cerr << "  \"jwks_url\":  \"https://login.microsoftonline.com/{tenant_id}/discovery/keys\"," << std::endl;
        std::cerr << "  \"redirect_uri\": \"http://localhost:5999\"," << std::endl;
        std::cerr << "  \"scope\": \"openid profile offline_access\"," << std::endl;
        std::cerr << "  \"server_port\": 5999," << std::endl;
        std::cerr << "  \"timeout_seconds\": 300" << std::endl;
        std::cerr << "}" << std::endl;
        return 1;
    }

    std::string code_verifier = generate_code_verifier();
    std::string code_challenge = generate_code_challenge(code_verifier);

    Config config(argv[1], code_challenge);
    
    CallbackServer svr(config.server_port);
   
    std::cout << "PKCE OAuth2 Flow Started" << std::endl;
    std::cout << "========================" << std::endl;
    std::cout << "Config file: " << argv[1] << std::endl;
    std::cout << std::endl;
    std::cout << "Opening login URL:" << std::endl;
    std::cout << config.login_url << std::endl;
    std::cout << std::endl;

    std::string command;
    #ifdef _WIN32
        // Check if running under Wine
        if (getenv("WINEPREFIX") != nullptr || getenv("WINEDEBUG") != nullptr) {
            // Running under Wine, use winebrowser
            command = "winebrowser \"" + config.login_url + "\"";
        } else {
            // Native Windows
            command = "start \"" + config.login_url + "\"";
        }
    #elif __APPLE__
        command = "open \"" + config.login_url + "\"";
    #else // Assume Linux or Unix
        command = "xdg-open \"" + config.login_url + "\"";
    #endif
    std::system(command.c_str());
    
    // Start server in a separate thread
    std::thread server_thread([&svr]() {
        svr.start();
    });
    
    std::cout << "Waiting for authentication callback..." << std::endl;
    
    // Wait for code to be received (with timeout)
    int elapsed = 0;
    
    while (!svr.is_code_received() && elapsed < config.timeout_seconds) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        elapsed++;
        
        if (elapsed % 30 == 0) {
            std::cout << "Still waiting... (" << elapsed << "s elapsed)" << std::endl;
        }
    }
    
    if (svr.is_code_received()) {
        std::cout << std::endl;
        std::cout << "SUCCESS! Authorization code received." << std::endl;
        std::cout << "Code: " << svr.get_auth_code() << std::endl;
        std::cout << "Code Verifier (for token exchange): " << code_verifier << std::endl;
    } else {
        std::cout << std::endl;
        std::cout << "Timeout: No authorization code received within " << config.timeout_seconds << " seconds." << std::endl;
        return 1;
    }

    std::string auth_code = svr.get_auth_code();
    
    // Stop the server
    svr.stop();
    
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    TokenResponse token_response;
    if (!exchange_token(config.token_url, config.client_id, auth_code, config.redirect_uri, code_verifier, token_response))
    {
        std::cout << std::endl;
        std::cout << "Token exchange failed." << std::endl;
        return 1;
    }

    std::cout << std::endl;
    std::cout << "Token exchange successful!" << std::endl;
    dump_token_response(token_response);
    
    std::cout << std::endl;
    if(verify_jwt_signature(token_response.id_token, config.jwks_url))
    {
        std::cout << "Decoded ID Token:" << std::endl;
        dump_token(token_response.id_token);
    }
    else
    {
        std::cout << "ID Token signature verification failed!" << std::endl;
    }

    std::cout << std::endl;
    if(verify_jwt_signature(token_response.access_token, config.jwks_url))
    {
        std::cout << "Decoded Access Token:" << std::endl;
        dump_token(token_response.access_token);
    }
    else
    {
        return 1;
    }

    return 0;
}

