# 🔐 aMember Pro Passkey Authentication Plugin

![Built with AI](https://img.shields.io/badge/Built%20with-AI-blue?logo=githubcopilot)
> **This plugin was built with assistance from GitHub Copilot and AI-powered development tools.**

---

A comprehensive **single-file** WebAuthn/FIDO2 passkey authentication plugin for aMember Pro that provides modern passwordless authentication for users.

> **Note:** This version does **not** implement passkey authentication for admin login. All passkey features are for member (user) accounts only. Admin management and login via passkey are not supported in this release. Feel free to submit a pull request to add this feature.

## ✨ **Key Features**

### 🔑 **Complete Passkey Authentication**

- **WebAuthn/FIDO2 Implementation** - Industry standard passwordless authentication
- **Multi-Device Support** - TouchID, FaceID, Windows Hello, USB security keys
- **User Authentication Only** - Passkey login for member accounts (no admin login)
- **Cross-Platform Compatibility** - Works on all modern browsers and devices

### 🛠️ **Self-Contained Design**

- **Single File Plugin** - Complete functionality in one file (`passkey.php`)
- **Auto-Installing Dependencies** - Automatically installs required Composer packages
- **No External Files Required** - Everything needed is included in the plugin

### 🎛️ **User Management**

- **Profile Integration** - Users can register, view, and delete passkeys from their profile
- **Multiple Devices** - Support for multiple passkeys per user
- **Device Naming** - Users can name their passkeys for easy identification

### ⚙️ **Advanced Configuration**

- **Flexible Settings** - Configurable authenticator requirements, user verification, attestation
- **Platform Preferences** - Control platform vs cross-platform authenticator usage
- **Security Policies** - Customizable security requirements for different user types

## 🚀 Installation

### **Preferred Installation (Recommended)**

1. **Clone the Repository**

   ```bash
   git clone https://github.com/kumpeapps/amember_plugin_passkey.git /path/to/amember/application/default/plugins/misc/passkey
   ```

   This will create the `passkey` folder and copy all plugin files automatically.

2. **Activate in aMember Admin**

   - Go to **aMember Admin** → **Setup/Configuration** → **Plugins** → **Miscellaneous**
   - Find **"Passkey"** plugin and **enable** it
   - Configure the plugin settings
   - **Save** the configuration

3. **User Profile Access**

   - Users can register and manage passkeys from their profile page

### **Alternate Installation (Manual Upload)**

1. **Upload the Plugin File**

copy all files from this repository to `/path/to/amember/application/default/plugins/misc/passkey/`

2. **Activate and Configure** (same as above)

---

### **That's It!**

- Dependencies auto-install automatically
- Database tables created automatically
- No additional files or setup required

## 🎯 **User Experience**

### **Registration Process**

- **Log in to member area**
- **Go to Profile → Passkeys tab**
- **Click "Register New Passkey"**
- **Follow device prompts** (TouchID, FaceID, etc.)
- **Name your passkey** (e.g., "iPhone", "Security Key")

### **Login Experience**

- **Visit login page**
- **Click "Login with Passkey" button**
- **Authenticate with device** (TouchID, FaceID, security key)
- **Instantly logged in!**

### **Multiple Passkeys**

- Users can register multiple passkeys per account
- Manage (rename/delete) passkeys from profile
- Use different devices interchangeably

## 🛡️ **Security**

- **WebAuthn/FIDO2 compliant**
- **Phishing-resistant authentication**
- **Private key never leaves device**
- **Works with hardware security keys**
- **Biometric authentication support**
- **HTTPS required**

## 🔧 **Integration Examples**

The `/examples` folder contains complete integration examples for using the passkey authentication API:

### 🛡️ **Secure Implementation (Recommended)**

- **`passkey_login_secure.html`** - Secure frontend that auto-loads configuration from aMember
- **`secure_passkey_auth.php`** - Secure server-side proxy that protects API keys
- **`passkey_login_example.html`** - Auto-detecting proxy version

### 🧪 **Testing Tools**

- **`test_config_endpoint.html`** - Test the new configuration endpoint

### ⚠️ **Important Security Warning**

- **`passkey_login_direct.html`** - **CONTAINS SECURITY WARNING** - Do not use this approach
- **Never expose API keys in client-side JavaScript code**
- **Always use server-side proxies for API authentication**
- **Store sensitive configuration only on the server**

### 📡 **API Endpoints**

The plugin provides REST API endpoints at:

**Configuration Endpoint:**

```http
GET /api/passkey/config
```

Returns WebAuthn configuration settings from aMember admin including:

- Relying Party ID and Name
- Timeout settings
- User verification requirements
- Authenticator attachment preferences
- Attestation settings

**Authentication Endpoint:**

```http
POST /api/check-access/by-passkey
```

Verifies passkey credentials and returns user access information.

Both endpoints require:

- Valid API key with `by-login-pass` permission
- HTTPS connection
- Proper WebAuthn credential data (for authentication endpoint)

**The secure examples automatically fetch configuration from aMember, eliminating the need for manual setup.**

**For production use, always implement the secure server-side proxy pattern shown in the examples.**

## 🐛 **Troubleshooting**

- Ensure HTTPS is enabled
- Check browser compatibility
- Verify plugin is enabled in aMember admin
- Check PHP error logs for details

## 📝 **Developer Information**

### File Structure

```text
passkey/
├── passkey.php           # Main plugin file
├── composer.json         # Dependency definitions (installed automatically when plugin is enabled)
├── composer.lock         # Locked dependency versions (installed automatically when plugin is enabled)
├── vendor/               # Auto-installed dependencies (installed automatically when plugin is enabled)
└── blocks/               # UI template blocks
    └── passkey-login.phtml
```

### Key Features

- **Single-file plugin** following aMember conventions
- **Automated dependency management** with Composer
- **Dynamic database table creation**
- **Comprehensive error handling**
- **Cross-browser WebAuthn compatibility**

---

**🚀 Transform your aMember site with modern, secure, passwordless authentication for users!**
