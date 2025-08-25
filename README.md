
# aMember Passkey Authentication Plugin

A modern, passwordless authentication plugin for aMember Pro that enables users to log in using **passkeys** (WebAuthn/FIDO2) with biometrics, security keys, or device authentication.

## ✨ Features

- **🔐 Passwordless Authentication** - Users log in with TouchID, FaceID, Windows Hello, or security keys
- **🚀 Plug-and-Play Installation** - Automatic dependency management, no manual setup required
- **🛡️ Enhanced Security** - WebAuthn/FIDO2 standard with phishing-resistant authentication
- **📱 Cross-Platform Support** - Works on desktop, mobile, and all modern browsers
- **⚙️ Admin Configuration** - Comprehensive settings for timeout, user verification, and authenticator preferences
- **👤 User-Friendly Management** - Users can register multiple passkeys and manage them from their profile

## 🚀 Quick Installation

### Simple 3-Step Setup:

1. **📁 Upload Plugin**
   ```
   Create directory: /amember/application/default/plugins/misc/passkey/
   Upload all files from this repository to that directory
   ```

2. **⚡ Enable Plugin**
   - Go to aMember Admin → **Configuration** → **Plugins**
   - Find "Passkey Login" and click **Enable**

3. **✅ Ready to Use!**
   - Dependencies install automatically
   - Database tables create automatically
   - Users can immediately register passkeys in their profiles

### That's it! No manual commands, no technical setup required.

---

## 🎯 Requirements

- **aMember Pro** (any recent version)
- **PHP 7.4+** 
- **HTTPS enabled** (required for WebAuthn security)
- **Modern browser** (Chrome 67+, Firefox 60+, Safari 14+, Edge 18+)

---

## 🔧 Configuration

### Admin Settings
Navigate to **Configuration** → **Setup/Configuration** → **Passkey Login**:

- **🌐 Relying Party Settings**
  - **RP Name**: Your site name (e.g., "aMember Site")
  - **RP ID**: Your domain (auto-detected)

- **⏱️ WebAuthn Configuration**
  - **Timeout**: Authentication timeout (default: 60 seconds)
  - **User Verification**: Biometric/PIN requirements
  - **Resident Key**: Passkey storage preferences
  - **Authenticator Attachment**: Platform vs. cross-platform devices
  - **Attestation**: Security verification level

### Recommended Settings
- **User Verification**: "Preferred" (works with most devices)
- **Resident Key**: "Preferred" (best user experience)
- **Authenticator Attachment**: "Both" (maximum compatibility)
- **Attestation**: "None" (maximum compatibility)

---

## 👥 User Experience

### For Users - Registration
1. **Log in to member area**
2. **Go to Profile → Passkeys tab**
3. **Click "Register New Passkey"**
4. **Follow device prompts** (TouchID, FaceID, etc.)
5. **Name your passkey** (e.g., "iPhone", "Security Key")

### For Users - Login
1. **Visit login page**
2. **Click "Login with Passkey" button**
3. **Authenticate with device** (TouchID, FaceID, security key)
4. **Instantly logged in!**

### Multiple Passkeys
- Users can register multiple passkeys per account
- Manage (rename/delete) passkeys from profile
- Use different devices interchangeably

---

## 🛠️ Technical Details

### Automatic Features
- **🎯 Dependency Management**: WebAuthn library installs automatically via Composer
- **🗄️ Database Setup**: Credential tables create automatically
- **🔄 Updates**: Dependencies update automatically
- **🚨 Error Handling**: Graceful fallbacks and clear error messages

### Security Features
- **WebAuthn/FIDO2 compliant**
- **Phishing-resistant authentication**
- **Private key never leaves device**
- **Works with hardware security keys**
- **Biometric authentication support**

### Browser Compatibility
| Browser | Version | Platform Support |
|---------|---------|------------------|
| Chrome  | 67+     | ✅ All platforms |
| Firefox | 60+     | ✅ All platforms |
| Safari  | 14+     | ✅ All platforms |
| Edge    | 18+     | ✅ All platforms |

---

## 🐛 Troubleshooting

### Common Issues

**❓ Passkey button not appearing**
- Ensure HTTPS is enabled
- Check browser compatibility
- Verify plugin is enabled in aMember admin

**❓ Registration fails**
- Check browser console for errors
- Verify user verification settings
- Try different authenticator attachment setting

**❓ Login fails**
- Ensure passkey was registered on same domain
- Check if passkey still exists on device
- Verify browser hasn't cleared WebAuthn data

### Debug Mode
Add `?passkey-debug=1` to any URL to access detailed diagnostic information:
- Plugin status and configuration
- Database connectivity
- Dependency verification
- WebAuthn browser support test
- Server environment details

### Log Files
Check your PHP error logs for detailed information:
```bash
tail -f /path/to/php/error.log | grep "Passkey Plugin"
```

---

## 🔒 Security Notes

- **HTTPS Required**: WebAuthn only works over secure connections
- **Same Origin**: Passkeys are bound to your exact domain
- **Privacy**: No biometric data leaves the user's device
- **Backup**: Users should register multiple passkeys as backup
- **Compatibility**: Works alongside existing password authentication

---

## 📝 Developer Information

### File Structure
```
passkey/
├── passkey.php           # Main plugin file (3,890 lines)
├── composer.json         # Dependency definitions
├── composer.lock         # Locked dependency versions
├── vendor/              # Auto-installed dependencies
│   └── web-auth/
│       └── webauthn-lib/
└── blocks/              # UI template blocks
    ├── passkey-login.phtml
    └── passkey-profile.phtml
```

### Key Features
- **Single-file plugin** following aMember conventions
- **Automated dependency management** with Composer
- **Dynamic database table creation**
- **Comprehensive error handling and logging**
- **Cross-browser WebAuthn compatibility**

---

## 🎉 What's New in This Version

- ✅ **Zero manual setup** - fully automated installation
- ✅ **Self-contained dependencies** - no global Composer requirements  
- ✅ **Automatic database creation** - tables create themselves
- ✅ **Enhanced admin configuration** - comprehensive WebAuthn settings
- ✅ **Improved error handling** - graceful fallbacks and clear messages
- ✅ **Better browser compatibility** - works with all major browsers
- ✅ **Professional UI/UX** - clean, modern interface

---

## 📞 Support

If you encounter any issues:

1. **Check the debug page**: `yoursite.com?passkey-debug=1`
2. **Review PHP error logs** for detailed information
3. **Verify HTTPS and browser compatibility**
4. **Test with different devices/browsers**

---

## 📁 Repository Structure

This repository contains the plugin files that should be uploaded to your aMember installation:

```
Repository Files → Installation Location
├── passkey.php           → /amember/application/default/plugins/misc/passkey/passkey.php
├── blocks/               → /amember/application/default/plugins/misc/passkey/blocks/
│   ├── passkey-login.phtml
│   └── passkey-profile.phtml
└── README.md             → (documentation only)

Auto-created during installation:
├── composer.json         → (created automatically)
├── composer.lock         → (created during dependency install)
└── vendor/               → (dependencies installed automatically)
```

**Installation**: Simply upload `passkey.php` and `blocks/` folder to the aMember plugin directory. Everything else is automated!

---

**🚀 Transform your aMember site with modern, secure, passwordless authentication!**
