
# 🔐 aMember Pro Passkey Authentication Plugin

A comprehensive **single-file** WebAuthn/FIDO2 passkey authentication plugin for aMember Pro that provides modern passwordless authentication with complete admin management.

## ✨ **Key Features**

### 🔑 **Complete Passkey Authentication**
- **WebAuthn/FIDO2 Implementation** - Industry standard passwordless authentication
- **Multi-Device Support** - TouchID, FaceID, Windows Hello, USB security keys
- **User & Admin Authentication** - Separate secure authentication for both user and admin accounts
- **Cross-Platform Compatibility** - Works on all modern browsers and devices

### 🛠️ **Self-Contained Design**
- **Single File Plugin** - Complete functionality in one file (`passkey.php`)
- **Auto-Installing Dependencies** - Automatically installs required Composer packages
- **Built-in Admin Interface** - Self-contained admin dashboard and management tools
- **No External Files Required** - Everything needed is included in the plugin

### 🎛️ **Comprehensive Admin Management**
- **Built-in Admin Dashboard** - Professional interface with navigation (`/ajax.php?action=admin-passkey-dashboard`)
- **Complete User Overview** - View all users with passkeys, statistics, and management tools
- **Individual User Details** - Detailed passkey information per user with delete capabilities
- **Real-time Statistics** - User counts, passkey totals, registration timelines
- **Debug & Test Tools** - Built-in diagnostics and status checking

### ⚙️ **Advanced Configuration**
- **Flexible Settings** - Configurable authenticator requirements, user verification, attestation
- **Separate Admin Security** - Stricter security settings for admin accounts
- **Platform Preferences** - Control platform vs cross-platform authenticator usage
- **Security Policies** - Customizable security requirements for different user types

## 🚀 **Installation**

### **Simple Installation Process**
1. **Upload the Plugin File**
   ```
   Upload passkey.php to: /path/to/amember/application/default/plugins/misc/passkey.php
   ```

2. **Activate in aMember Admin**
   - Go to **aMember Admin** → **Setup/Configuration** → **Plugins** → **Miscellaneous**
   - Find **"Passkey"** plugin and **enable** it
   - Configure the plugin settings
   - **Save** the configuration

3. **Access Admin Interface**
   - Configuration page will show admin management links
   - Use the built-in admin dashboard for comprehensive management

### **That's It!**
- Dependencies auto-install automatically
- Database tables created automatically  
- No additional files or setup required

## 🎯 **Admin Interface Access**

### **Primary Access Methods**
1. **Plugin Configuration** (Recommended)
   - aMember Admin → Setup → Plugins → Miscellaneous → Passkey
   - Click "�️ Admin Dashboard" for full interface

2. **User Admin Tabs**
   - aMember Admin → Users → Select user → "Passkeys" tab
   - Links to both individual and overall management

3. **Direct URLs** (Bookmark these)
   - **Admin Dashboard**: `/ajax.php?action=admin-passkey-dashboard`
   - **Direct Management**: `/ajax.php?action=admin-passkey-management`
   - **Test Status**: `/ajax.php?action=passkey-test-status`
   - **Debug Info**: `/ajax.php?action=passkey-debug`

## 📊 **Admin Features**

### **Dashboard Overview**
- **Professional Interface** - Clean, responsive design with navigation
- **User Statistics** - Complete overview of passkey adoption and usage
- **Quick Access** - Direct links to all management functions
- **Embedded Tools** - All management pages accessible within the dashboard

### **User Management**
- **Complete User List** - All users with registered passkeys
- **Device Information** - Device names, types, registration dates
- **Individual Details** - Detailed view of each user's passkeys
- **Delete Management** - Remove passkeys as needed
- **Search & Filter** - Easy navigation through user data

### **Monitoring & Diagnostics**
- **Real-time Status** - Plugin health and dependency status
- **Environment Check** - PHP requirements and extension verification
- **Database Status** - Table existence and connectivity verification
- **Debug Tools** - Comprehensive troubleshooting information

## 🔧 **Technical Specifications**

### **Requirements**
- **aMember Pro** 6.x or later
- **PHP** 7.4+ (8.x recommended)
- **Extensions**: OpenSSL, mbstring, JSON
- **Database**: MySQL/MariaDB with aMember tables

### **Security Features**
- **WebAuthn Standard** - Full compliance with W3C WebAuthn specification
- **FIDO2 Protocol** - Industry-standard authentication protocol
- **Origin Validation** - Prevents cross-origin attacks
- **User Verification** - Configurable biometric/PIN requirements
- **Separate Admin Security** - Enhanced security for admin accounts

### **Architecture**
- **Single File Design** - Complete functionality in one PHP file
- **Auto-dependency Management** - Composer packages installed automatically
- **Database Integration** - Native aMember database integration
- **Hook System** - Proper aMember plugin architecture
- **AJAX Architecture** - Modern asynchronous interface

## 🎨 **User Experience**

### **Registration Process**
- **One-Click Registration** - Simple passkey creation process
- **Device Detection** - Automatic detection of available authenticators
- **Friendly Naming** - Users can name their passkeys for easy identification
- **Multiple Devices** - Support for multiple passkeys per user

### **Login Experience**
- **Passwordless Login** - No passwords required
- **Quick Authentication** - Touch/face recognition or security key
- **Fallback Support** - Works alongside existing authentication methods
- **Cross-Device Support** - Use passkeys across different devices

## 📈 **Benefits**

### **For Users**
- **Enhanced Security** - Stronger than passwords, immune to phishing
- **Convenience** - No passwords to remember or type
- **Speed** - Instant authentication with biometrics
- **Privacy** - No shared secrets or trackable credentials

### **For Administrators**
- **Complete Visibility** - Full oversight of passkey usage
- **Easy Management** - Simple tools for user and device management
- **Enhanced Security** - Stronger authentication for admin accounts
- **Reduced Support** - Fewer password-related support requests

### **For Organizations**
- **Future-Proof** - Industry-standard authentication technology
- **Compliance** - Meets modern security requirements
- **Cost-Effective** - Reduces authentication infrastructure needs
- **User Satisfaction** - Improved user experience and security

## 🛡️ **Security**

This plugin implements the full WebAuthn/FIDO2 specification with:
- **Origin verification** to prevent cross-origin attacks
- **Challenge-response authentication** with cryptographic signatures
- **Public key cryptography** for secure credential storage
- **User verification** requirements (biometric/PIN)
- **Separate admin security policies** with enhanced requirements

## 📞 **Support**

- **Self-Contained Design** - Minimal dependencies, easy troubleshooting
- **Built-in Diagnostics** - Comprehensive status and debug tools
- **Complete Documentation** - Integrated help and status information
- **Professional Implementation** - Production-ready with proper error handling

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
