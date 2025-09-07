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

### test_api_proxy.html

Simple test to verify the API proxy is accessible and responds correctly.

### test_direct_plugin.html

Direct test of aMember endpoints without the proxy - useful for debugging plugin integration.

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
   - **Important**: Enable the "by-login-pass" permission (passkey auth uses the same permission as password auth)

4. **Deploy Files**: Upload both PHP files to your web server

5. **Update Frontend**: The HTML file should automatically work with the proxy

6. **Test Authentication**: Open the example page and click "Sign in with Passkey"

## Troubleshooting

### 404 Error on api_proxy.php

If you get a 404 error:

1. **Check File Location**: Ensure `api_proxy.php` is in the same directory as your HTML file
2. **Test Directly**: Open `test_api_proxy.html` in your browser to verify the proxy is accessible
3. **Check Web Server**: Make sure your web server serves PHP files correctly
4. **File Permissions**: Ensure the PHP file has proper read permissions

### Missing API Permission

If you get "API Error 10001 - no [key] specified" or "Access denied":

1. **Enable Plugin**: Make sure the passkey plugin is enabled in aMember admin
2. **Check API Key**: Ensure your API key is correct and active
3. **Enable Permission**: In aMember API settings, enable the **"by-login-pass"** permission for your API key
4. **No Custom Permission Needed**: Passkey auth uses the same permission as password-based auth for security consistency

### Configuration Issues

1. **Copy config.example.php**: Make sure you copied it to `config.php`
2. **Update Values**: Verify all configuration values are correct
3. **API Key**: Generate a new API key in aMember if needed
4. **HTTPS**: Ensure both aMember and your proxy use HTTPS

### Debugging Steps

1. **Test API Proxy**: Open `test_api_proxy.html` to verify proxy accessibility
2. **Test Direct Plugin**: Open `test_direct_plugin.html` to test aMember integration directly
3. **Check aMember Logs**: Look in aMember error logs for plugin errors
4. **Verify Plugin**: Ensure passkey plugin is enabled in aMember admin
5. **API Key Permissions**: Make sure your API key has the correct permissions

### Alternative Solutions

If the API endpoint issues persist:

1. **Use Alternative Endpoints**: The proxy now tries multiple endpoint patterns
2. **Check Plugin Version**: Ensure you have the latest plugin version
3. **Manual Testing**: Use the direct test files to identify which endpoints work
4. **Contact Support**: If all tests fail, the plugin may need updates for your aMember version

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
