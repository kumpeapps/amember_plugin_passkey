# Admin Passkey Management Access - Single File Plugin

## 🎯 **IMMEDIATE ACCESS METHODS**

### ✅ **Method 1: Plugin Configuration Page (EASIEST)**
1. Go to **aMember Admin** → **Setup/Configuration** → **Plugins** → **Miscellaneous**
2. Find **"Passkey"** plugin configuration
3. Scroll down to **"Admin Management"** section
4. Click **"�️ Admin Dashboard"** for the complete interface

### ✅ **Method 2: User Admin Tabs**
1. Go to **aMember Admin** → **Users** → Select any user
2. Click the **"Passkeys"** tab
3. Click **"�️ Admin Dashboard"** link at the top

### ✅ **Method 3: Direct URLs (BOOKMARK THESE)**
- **🖥️ Complete Admin Dashboard**: `/ajax.php?action=admin-passkey-dashboard`
- **📊 Direct Management**: `/ajax.php?action=admin-passkey-management`
- **🧪 Test Status**: `/ajax.php?action=passkey-test-status`
- **🐛 Debug Info**: `/ajax.php?action=passkey-debug`

## 🔧 **Available Admin Features**

### 📊 **Passkey Management Dashboard**
- **Complete User List**: All users with registered passkeys
- **Device Information**: Device names, registration dates, credential IDs
- **Statistics**: Total users with passkeys, total passkeys, first/latest registration dates
- **Direct User Access**: Click on any user to view their detailed passkey information
- **Plugin Status**: WebAuthn library status, configuration verification

### 👤 **Individual User Management**
- **User Information**: Login, name, email, account status
- **Passkey Details**: All passkeys for the user with creation dates and device names
- **Raw Credential Data**: For advanced debugging and troubleshooting
- **Delete Capabilities**: Remove individual passkeys as needed

### 🐛 **Debug & Troubleshooting**
- **Plugin Status**: Verify WebAuthn library loading and configuration
- **Environment Information**: Server details, PHP version, dependency status
- **Configuration Validation**: Check all WebAuthn settings and admin configuration
- **Error Logs**: Access to plugin-specific logging information
