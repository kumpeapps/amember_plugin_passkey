# Passkey Login Example

This directory contains example implementations demonstrating how to integrate with the aMember Passkey Plugin API.

## Files

### `passkey_login_example.html`

A complete HTML page with JavaScript that demonstrates:

- WebAuthn/FIDO2 passkey authentication
- Integration with the secure API proxy
- Proper credential formatting and API communication
- User-friendly interface with status messages

### `api_proxy.php`

A secure PHP proxy script that:

- Handles API key authentication with aMember
- Forwards passkey verification requests
- Provides CORS support for frontend integration
- Includes proper error handling and security measures

### `config.example.php`

Configuration template for:

- aMember installation URL
- API key storage
- CORS and security settings
- Copy to `config.php` for actual use

## Setup Instructions

1. **Copy Configuration**: Copy `config.example.php` to `config.php`:
   ```bash
   cp config.example.php config.php
   ```

2. **Update Configuration**: Edit `config.php` with your actual values:
   ```php
   'amember_base_url' => 'https://your-amember-site.com',
   'api_key' => 'your-actual-api-key',
   'cors_origin' => 'https://yourdomain.com', // Your frontend domain
   ```

3. **Get API Key**: Generate an API key in aMember:
   - Login to aMember admin
   - Go to Setup/Configuration → API
   - Generate a new API key

4. **Deploy Files**: Upload both PHP files to your web server

5. **Update Frontend**: The HTML file should automatically work with the proxy

6. **Test Authentication**: Open the example page and click "Sign in with Passkey"

## Security Features

### API Key Protection

- API key stored in separate config file
- Config file should be outside web root or protected by .htaccess
- Never expose API key in frontend code

### CORS Configuration

- Configurable CORS origins for production security
- Set `cors_origin` to your specific domain in production

### SSL/TLS

- Configurable SSL verification
- Use `verify_ssl: true` in production
- Only disable for development with self-signed certificates

3. **Register Passkeys**: Users must first register passkeys through your aMember site using the passkey plugin

4. **Test Authentication**: Open the example page and click "Sign in with Passkey"

## API Integration

The example demonstrates the complete flow:

1. **Client Side**: Uses WebAuthn API to get authentication credential
2. **API Call**: Sends credential to `/api/check-access/by-passkey` endpoint
3. **Server Response**: Receives user information and access status

### Request Format
```json
{
  "credential": {
    "id": "credential_id",
    "rawId": "base64url_encoded_raw_id",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64url_encoded_client_data",
      "authenticatorData": "base64url_encoded_authenticator_data",
      "signature": "base64url_encoded_signature",
      "userHandle": "base64url_encoded_user_handle"
    },
    "challenge": "base64url_encoded_challenge"
  }
}
```

### Response Format
```json
{
  "ok": true,
  "user_id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "access": true,
  "error": null
}
```

## Browser Requirements

- Modern browser with WebAuthn support
- HTTPS connection (required for WebAuthn)
- Registered passkey for the user

## Security Notes

- Always use HTTPS in production
- Validate all API responses
- Handle authentication errors gracefully
- Consider implementing rate limiting
- Store user session securely after successful authentication

## Integration Tips

1. **Error Handling**: The example includes comprehensive error handling for common WebAuthn issues
2. **Base64URL Encoding**: Proper encoding/decoding utilities are included for credential data
3. **User Experience**: Status messages guide users through the authentication process
4. **Responsive Design**: The interface works on both desktop and mobile devices

## Customization

You can customize the example by:
- Modifying the CSS for your brand colors and styling
- Adding additional user information display
- Implementing session management
- Adding logout functionality
- Integrating with your existing authentication system
