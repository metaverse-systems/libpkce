# PKCE OAuth2 Configuration

The `pkce` program accepts a JSON configuration file as its first argument. This allows you to customize various parameters of the OAuth2 flow.

## Usage

```bash
./pkce config.json
```

## Configuration File Format

The JSON configuration file should contain the following fields:

- **`login_url`**: The OAuth2 authorization URL template with placeholders
- **`tenant_id`**: Your OAuth2 provider's tenant ID (GUID format)
- **`client_id`**: Your OAuth2 application's client ID (GUID format)
- **`redirect_uri`**: The redirect URI for OAuth callbacks (default: `"http://localhost:5999"`)
- **`scope`**: The OAuth2 scopes to request (default: `"openid profile offline_access"`)
- **`server_port`**: The port number for the local callback server (default: `5999`)
- **`timeout_seconds`**: How long to wait for the user to complete authentication (default: `300` seconds)

## Example Configurations

### Microsoft Azure AD / Entra ID
```json
{
  "login_url": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&response_mode=query&code_challenge={code_challenge}&code_challenge_method=S256",
  "tenant_id": "your-azure-tenant-id",
  "client_id": "your-azure-client-id",
  "redirect_uri": "http://localhost:5999",
  "scope": "openid profile offline_access",
  "server_port": 5999,
  "timeout_seconds": 300
}
```

### Google OAuth 2.0
```json
{
  "login_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&code_challenge={code_challenge}&code_challenge_method=S256",
  "tenant_id": "",
  "client_id": "your-google-client-id.apps.googleusercontent.com",
  "redirect_uri": "http://localhost:5999",
  "scope": "openid profile email",
  "server_port": 5999,
  "timeout_seconds": 300
}
```

### GitHub OAuth
```json
{
  "login_url": "https://github.com/login/oauth/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&code_challenge={code_challenge}&code_challenge_method=S256",
  "tenant_id": "",
  "client_id": "your-github-client-id",
  "redirect_uri": "http://localhost:5999",
  "scope": "read:user user:email",
  "server_port": 5999,
  "timeout_seconds": 300
}
```

### Auth0
```json
{
  "login_url": "https://your-domain.auth0.com/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&code_challenge={code_challenge}&code_challenge_method=S256",
  "tenant_id": "",
  "client_id": "your-auth0-client-id",
  "redirect_uri": "http://localhost:5999",
  "scope": "openid profile email",
  "server_port": 5999,
  "timeout_seconds": 300
}
```

## Field Descriptions

- **`tenant_id`**: This identifies your OAuth2 provider's tenant. For Microsoft Azure AD, this is required. For other providers like Google, GitHub, or Auth0, this field can be left empty ("") as they don't use tenant-based URLs.

- **`client_id`**: This is the Application (client) ID of your app registration with your OAuth2 provider. Each provider has different formats:
  - **Azure AD**: GUID format (e.g., "12345678-1234-1234-1234-123456789abc")
  - **Google**: Ends with ".apps.googleusercontent.com"
  - **GitHub**: Alphanumeric string
  - **Auth0**: Alphanumeric string

- **`login_url`**: The OAuth2 authorization URL template with placeholders that will be automatically replaced:
  - `{tenant_id}`: Replaced with the tenant_id value
  - `{client_id}`: Replaced with the client_id value
  - `{redirect_uri}`: Replaced with the redirect_uri value
  - `{scope}`: Replaced with the scope value
  - `{code_challenge}`: Replaced with the generated PKCE code challenge
  
  If not provided, you'll need to manually construct the authorization URL. The template should follow your OAuth2 provider's authorization endpoint format.

- **`redirect_uri`**: Must match one of the redirect URIs configured in your app registration with your OAuth2 provider. The local server will listen on this URI's port.

- **`scope`**: Controls what permissions your application requests. Scopes vary by provider:
  - **Azure AD**: `openid profile offline_access`, `User.Read`, `Mail.Read`, etc.
  - **Google**: `openid profile email`, `https://www.googleapis.com/auth/userinfo.profile`, etc.
  - **GitHub**: `read:user user:email`, `repo`, `public_repo`, etc.
  - **Auth0**: `openid profile email`, custom scopes defined in your Auth0 tenant

- **`server_port`**: The port where the local HTTP server will listen for the OAuth callback. Make sure this matches the port in your `redirect_uri`.

- **`timeout_seconds`**: How long the program will wait for the user to complete the authentication flow in their browser before timing out.

## Login URL Template

The `login_url` field supports template placeholders that are automatically replaced at runtime:

- `{tenant_id}` → Your OAuth2 provider's tenant ID
- `{client_id}` → Your OAuth2 client ID  
- `{redirect_uri}` → URL-encoded redirect URI
- `{scope}` → URL-encoded scope string
- `{code_challenge}` → Generated PKCE code challenge

This allows you to define a reusable URL template that works across different environments. The program will automatically replace these placeholders with the actual values from your configuration and the generated PKCE parameters.

### Provider-Specific OAuth2 Templates

Different OAuth2 providers use different endpoint formats. Here are common patterns:

#### Microsoft Azure AD / Entra ID
```
https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&response_mode=query&code_challenge={code_challenge}&code_challenge_method=S256
```

#### Google OAuth 2.0
```
https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&code_challenge={code_challenge}&code_challenge_method=S256
```

#### GitHub OAuth
```
https://github.com/login/oauth/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&code_challenge={code_challenge}&code_challenge_method=S256
```

#### Auth0
```
https://your-domain.auth0.com/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&code_challenge={code_challenge}&code_challenge_method=S256
```

#### Generic OAuth2 Provider
```
https://your-oauth-provider.com/oauth2/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&code_challenge={code_challenge}&code_challenge_method=S256
```

## Error Handling

The program will display helpful error messages if:
- The configuration file cannot be found or read
- Required fields (`tenant_id`, `client_id`) are missing
- The JSON format is invalid
- The `login_url` template contains invalid placeholders
- Network errors occur during token exchange
