#include <libpkce/CallbackServer.hpp>

CallbackServer::CallbackServer(int port) : port(port)
{
    svr.set_exception_handler([](const httplib::Request &req, httplib::Response &res, std::exception_ptr ep) {
        res.status = 500;
        res.set_content("Internal Server Error", "text/plain");
    });
}

void CallbackServer::start()
{
    svr.Get("/", [this](const httplib::Request &req, httplib::Response &res)
    {
        std::string code = req.get_param_value("code");
        std::string error = req.get_param_value("error");
        
        if (!error.empty()) {
            std::string error_description = req.get_param_value("error_description");
            res.set_content("Authentication failed: " + error + 
                          (error_description.empty() ? "" : " - " + error_description), 
                          "text/html");
            return;
        }
        
        if (code.empty()) {
            res.set_content("No authorization code received", "text/html");
            return;
        }
        
        // Success response
        std::string html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Success</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .success { color: green; }
        .code { background: #f0f0f0; padding: 10px; margin: 20px; word-break: break-all; }
    </style>
</head>
<body>
    <h1 class="success">Authentication Successful!</h1>
    <p>Authorization code received:</p>
    <div class="code">)" + code + R"(</div>
    <p>You can close this window.</p>
</body>
</html>
        )";
        
        res.set_content(html, "text/html");
        
        // Store the code for retrieval
        auth_code = code;
        code_received = true;
        
        std::cout << "Authorization code received: " << code << std::endl;
    });
    
    std::cout << "Starting server on port " << port << "..." << std::endl;
    svr.listen("localhost", port);
}

void CallbackServer::stop()
{
    svr.stop();
}

std::string CallbackServer::get_auth_code() const
{
    return auth_code;
}

bool CallbackServer::is_code_received() const
{
    return code_received;
}