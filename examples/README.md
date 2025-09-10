# Simple Passkey Authentication System

A step-by-step implementation of WebAuthn passkey authentication in PHP.

## Setup Instructions

### 1. Database Setup
1. Create a MySQL database
2. Run the SQL in `setup.sql` to create the required tables
3. Update `config.php` with your database credentials

### 2. Configure Settings
Edit `config.php`:
- Set your database connection details
- For local development, keep `rp_id` as `localhost`
- For production, change `rp_id` to your actual domain

### 3. Run the Application
For local development:
```bash
cd examples
php -S localhost:8080
```

Then open: http://localhost:8080

## Development Steps

### Step 1: Basic Same-Domain Authentication ✅
- Simple user registration with passkeys
- Login with passkeys 
- Session management
- Works on localhost or single domain

### Step 2: Production Domain (Next)
- Deploy to actual domain
- Test with real HTTPS
- Verify domain-specific functionality

### Step 3: Cross-Domain (Final)
- Implement Related Origins
- Set up .well-known/webauthn
- Test cross-domain authentication

## Current Status
- ✅ Database schema created
- ✅ Basic WebAuthn server implementation
- ✅ Frontend with registration/login
- 🔄 Ready for testing

## Testing Checklist
1. Register a new user with passkey
2. Logout and login again with passkey
3. Verify session persistence
4. Test with different browsers
5. Test error handling

## Next Steps
Once basic functionality works:
1. Deploy to production domain
2. Add proper signature verification
3. Implement cross-domain support
4. Integrate with aMember
