#include <string>
#include <regex>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <libpkce/json.hpp>

class Config
{
public:
    std::string login_url;
    std::string token_url;
    std::string jwks_url;
    std::string tenant_id;
    std::string client_id;
    std::string redirect_uri;
    std::string scope;
    int server_port;
    int timeout_seconds;
    Config(const std::string &config_file, std::string code_challenge)
    {
        std::ifstream file(config_file);
        if (!file.is_open())
        {
            throw std::runtime_error("Could not open config file: " + config_file);
        }

        file >> this->json;
        this->json["code_challenge"] = code_challenge;

        this->login_url = this->json.value("login_url", "");
        this->token_url = this->json.value("token_url", "");
        this->jwks_url = this->json.value("jwks_url", "");
        this->tenant_id = this->json.value("tenant_id", "");
        this->client_id = this->json.value("client_id", "");
        this->redirect_uri = this->json.value("redirect_uri", "http://localhost:5999");
        this->scope = this->json.value("scope", "openid profile offline_access");
        this->server_port = this->json.value("server_port", 5999);
        this->timeout_seconds = this->json.value("timeout_seconds", 300);
        this->merge();

        // Validate required fields
        if (this->tenant_id.empty())
        {
            throw std::runtime_error("tenant_id is required in config file");
        }
        if (this->client_id.empty())
        {
            throw std::runtime_error("client_id is required in config file");
        }
    }
    void dump_config()
    {
        std::cout << "Config:" << std::endl;
        for(auto it = this->json.begin(); it != this->json.end(); ++it)
        {
            std::cout << "  " << it.key() << ": " << it.value() << std::endl;
        }
    }

private:
    nlohmann::json json;
    void merge()
    {
        this->merge_setting(this->login_url);
        this->merge_setting(this->token_url);
        this->merge_setting(this->jwks_url);
    }
    
    void merge_setting(std::string &setting)
    {
        for (auto it = this->json.begin(); it != this->json.end(); ++it)
        {
            std::string key = it.key();
            std::string value;
            
            // Convert JSON value to string based on its type
            if (it.value().is_string()) {
                value = it.value();
            } else if (it.value().is_number()) {
                value = std::to_string(it.value().get<double>());
            } else if (it.value().is_boolean()) {
                value = it.value().get<bool>() ? "true" : "false";
            } else {
                // For other types, convert to string representation
                value = it.value().dump();
            }
            
            std::string placeholder = "\\{" + key + "\\}";
            setting = std::regex_replace(setting, std::regex(placeholder), value);
        }
    }
};