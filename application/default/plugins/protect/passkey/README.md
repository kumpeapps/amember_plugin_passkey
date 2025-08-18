# aMember Passkey (WebAuthn) Plugin Installation & Setup

## Requirements
- aMember Pro installation
- PHP 8.0+
- Composer (for PHP dependencies)
- HTTPS enabled (required for WebAuthn)

## Installation Steps

1. **Copy Plugin Files**
    - Place the `passkey` plugin folder into `application/default/plugins/protect/` in your aMember installation, so the full path is:
       `application/default/plugins/protect/passkey/`

2. **Install PHP Dependencies**
   - In your aMember root directory, run:
     ```bash
     composer require web-auth/webauthn-lib
     ```
   - This will install the WebAuthn library and dependencies.

3. **Create Passkey Table**
   - Import the provided `db.sql` file into your aMember database to create the `?_passkey` table.
   - Example (replace `amember` with your DB name):
     ```bash
       mysql -u USER -p amember < application/default/plugins/protect/passkey/db.sql
     ```

4. **Enable the Plugin**
   - Log in to aMember admin.
   - Go to **Configuration > Plugins**.
   - Enable the **Passkey Login** plugin.
   - Configure plugin options under **Configuration > Setup/Configuration > Passkey Login**.

5. **Test Passkey Registration & Login**
   - Users can register passkeys in their profile ("Passkeys" tab).
   - Passkey login button will appear on member and admin login forms.

## Notes
- Your site must use HTTPS for passkey (WebAuthn) to work.
- For production, ensure your server time is correct and PHP sessions are working.
- For advanced configuration, see the plugin settings in the admin panel.

## Troubleshooting
- If you see PHP errors about missing classes, ensure Composer dependencies are installed and autoloaded.
- If passkey registration or login fails, check browser console and PHP error logs for details.

## Uninstallation
- Disable the plugin in aMember admin.
- (Optional) Remove the `passkey` plugin folder and drop the `?_passkey` table from your database.
