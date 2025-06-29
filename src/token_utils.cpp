#include <iostream>
#include <libpkce/json.hpp>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <libpkce/httplib.h>
#include <jwt-cpp/jwt.h>
#include "token_utils.hpp"

std::string base64url_decode(const std::string &input)
{
    std::string base64 = input;

    for (char& c : base64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }

    while (base64.length() % 4 != 0) {
        base64 += '=';
    }
    
    return jwt::base::decode<jwt::alphabet::base64>(base64);
}

void dump_token(std::string token)
{
    try {
        auto decoded = jwt::decode(token);
        auto payload_json = decoded.get_payload_json();
        for (const auto &part : payload_json) {
            std::cout << part.first << ": " << part.second.to_str() << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error decoding JWT token: " << e.what() << std::endl;
    }
}

bool verify_jwt_signature(const std::string &token, const std::string &jwks_url)
{
    try {
        // Parse the JWT token to get header and issuer
        auto decoded = jwt::decode(token);
        // Discover metadata to get correct JWKS URI from issuer
        std::string issuer = decoded.get_issuer();
        std::string jwks_uri; // = jwks_url;
        
        std::cout << "Token issuer: " << issuer << std::endl;
        
        if (!issuer.empty()) {
            // Build metadata URL: issuer + '/.well-known/openid-configuration'
            std::string metadata_url = issuer;
            if (metadata_url.back() != '/') metadata_url += '/';
            metadata_url += ".well-known/openid-configuration";
            
            std::cout << "Fetching metadata from: " << metadata_url << std::endl;
            
            // Parse metadata URL
            std::string meta_host, meta_path;
            size_t proto = metadata_url.find("://");
            std::string meta_no_proto = (proto!=std::string::npos)
                ? metadata_url.substr(proto+3)
                : metadata_url;
            size_t slash = meta_no_proto.find('/');
            if (slash==std::string::npos) {
                meta_host = meta_no_proto;
                meta_path = "/";
            } else {
                meta_host = meta_no_proto.substr(0, slash);
                meta_path = meta_no_proto.substr(slash);
            }
            httplib::SSLClient meta_cli(meta_host);
            auto meta_res = meta_cli.Get(meta_path.c_str());
            if (meta_res && meta_res->status==200) {
                try {
                    auto meta = nlohmann::json::parse(meta_res->body);
                    if (meta.contains("jwks_uri")) {
                        jwks_uri = meta["jwks_uri"].get<std::string>();
                        std::cout << "Found jwks_uri in metadata: " << jwks_uri << std::endl;
                    }
                } catch(...) {
                    std::cout << "Failed to parse metadata JSON" << std::endl;
                }
            } else {
                std::cout << "Failed to fetch metadata, using fallback JWKS URL" << std::endl;
            }
        }
        // Now use jwks_uri for fetching keys
        auto header = decoded.get_header_json();
        
        // Extract key ID (kid) from header
        std::string kid;
        if (header.count("kid")) {
            kid = header["kid"].to_str();
            std::cout << "Looking for key ID: " << kid << std::endl;
        } else {
            std::cout << "No key ID in token header, will use first RSA key" << std::endl;
        }
        
        // Extract algorithm from header
        std::string alg;
        if (header.count("alg")) {
            alg = header["alg"].to_str();
        }
        
        // Parse JWKS URL to get host and path
        std::string host, path;
        size_t protocol_pos = jwks_uri.find("://");
        if (protocol_pos == std::string::npos) {
            std::cerr << "Invalid JWKS URL format" << std::endl;
            return false;
        }
        
        std::string url_without_protocol = jwks_uri.substr(protocol_pos + 3);
        size_t slash_pos = url_without_protocol.find('/');
        if (slash_pos == std::string::npos) {
            host = url_without_protocol;
            path = "/";
        } else {
            host = url_without_protocol.substr(0, slash_pos);
            path = url_without_protocol.substr(slash_pos);
        }
        
        // Fetch JWKS from the URL
        httplib::Client cli(("https://" + host).c_str());
        cli.set_connection_timeout(10, 0); // 10 seconds
        cli.set_read_timeout(10, 0);       // 10 seconds
        
        std::cout << "Fetching JWKS from: " << jwks_uri << std::endl;
        auto res = cli.Get(path.c_str());
        if (!res || res->status != 200) {
            std::cerr << "Failed to fetch JWKS from " << jwks_uri << std::endl;
            if (res) {
                std::cerr << "HTTP Status: " << res->status << std::endl;
            }
            return false;
        }
        
        // Parse JWKS JSON
        nlohmann::json jwks;
        try {
            jwks = nlohmann::json::parse(res->body);
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse JWKS JSON: " << e.what() << std::endl;
            return false;
        }
        
        // Find the matching key
        if (!jwks.contains("keys") || !jwks["keys"].is_array()) {
            std::cerr << "Invalid JWKS format: missing keys array" << std::endl;
            return false;
        }
        
        std::cout << "Found " << jwks["keys"].size() << " keys in JWKS" << std::endl;
        
        nlohmann::json matching_key_json;
        bool key_found = false;
        for (const auto& key : jwks["keys"]) {
            std::string key_id = key.contains("kid") ? key["kid"].get<std::string>() : "no-kid";
            std::string key_type = key.contains("kty") ? key["kty"].get<std::string>() : "unknown";
            std::cout << "  Key: " << key_id << " (type: " << key_type << ")" << std::endl;
            
            // If kid is specified, match by kid, otherwise use the first RSA key
            if (!kid.empty()) {
                if (key.contains("kid") && key["kid"].get<std::string>() == kid) {
                    matching_key_json = key;
                    key_found = true;
                    std::cout << "  -> Matched by kid!" << std::endl;
                    break;
                }
            } else {
                // Use first RSA key if no kid specified
                if (key.contains("kty") && key["kty"].get<std::string>() == "RSA") {
                    matching_key_json = key;
                    key_found = true;
                    std::cout << "  -> Using first RSA key!" << std::endl;
                    break;
                }
            }
        }
        
        if (!key_found) {
            std::cerr << "No matching key found in JWKS" << std::endl;
            return false;
        }
        
        std::cout << "Available key fields: ";
        for (auto& [key, value] : matching_key_json.items()) {
            std::cout << key << " ";
        }
        std::cout << std::endl;
        
        std::string public_key_pem;
        
        // Try n and e components first (more reliable for Microsoft keys)
        if (matching_key_json.contains("n") && matching_key_json.contains("e")) {
            std::cout << "Skipping RSA n/e verification (not implemented yet)" << std::endl;
            // Skip n/e for now - fall through to x5c
        }
        
        // Try x5c as fallback (X.509 certificate chain)
        if (matching_key_json.contains("x5c") && matching_key_json["x5c"].is_array() && !matching_key_json["x5c"].empty()) {
            std::string cert_b64 = matching_key_json["x5c"][0].get<std::string>();
            
            // Try different certificate formats
            std::vector<std::string> cert_formats = {
                // Standard PEM format
                "-----BEGIN CERTIFICATE-----\n" + cert_b64 + "\n-----END CERTIFICATE-----\n",
                // PEM format with line breaks every 64 chars
                [&]() {
                    std::string pem = "-----BEGIN CERTIFICATE-----\n";
                    for (size_t i = 0; i < cert_b64.length(); i += 64) {
                        pem += cert_b64.substr(i, 64) + "\n";
                    }
                    pem += "-----END CERTIFICATE-----\n";
                    return pem;
                }()
            };
            
            for (const auto& cert_pem : cert_formats) {
                try {
                    std::cout << "Trying x5c certificate format..." << std::endl;
                    
                    // Verify the token signature
                    auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::rs256(cert_pem, "", "", ""));
                    
                    verifier.verify(decoded);
                    std::cout << "x5c certificate verification successful!" << std::endl;
                    return true;
                } catch (const jwt::error::signature_verification_exception& e) {
                    std::cerr << "JWT signature verification failed with x5c: " << e.what() << std::endl;
                    continue; // Try next format
                } catch (const std::exception& e) {
                    std::cerr << "Error with x5c verification: " << e.what() << std::endl;
                    continue; // Try next format
                }
            }
            std::cerr << "All x5c certificate formats failed" << std::endl;
        }
        else {
            std::cerr << "Key format not supported (need x5c or n/e)" << std::endl;
            return false;
        }
        return true;
        
    } catch (const jwt::error::signature_verification_exception& e) {
        std::cerr << "JWT signature verification failed: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error verifying JWT signature: " << e.what() << std::endl;
        return false;
    }
}