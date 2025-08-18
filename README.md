
# aMember Passkey (WebAuthn) Plugin Installation & Setup

## Requirements
- aMember Pro installation
- PHP 8.0+
- Composer (for PHP dependencies)
- HTTPS enabled (required for WebAuthn)

> **Important:**
> The `vendor/` directory and all Composer dependencies (including `web-auth/webauthn-lib`) must be present. If missing, run `composer install` in the project root.

## Installation Steps

1. **Copy Plugin Files**
   - Place the `passkey` plugin folder into `application/default/plugins/misc/` in your aMember installation.

2. **Install PHP Dependencies**
   - In your project root directory, run:
     ```bash
     composer install
     ```
   - This will install all dependencies listed in `composer.json`, including `web-auth/webauthn-lib`.

3. **Create Passkey Table**
   - Import the provided `db.sql` file into your aMember database to create the `?_passkey_credentials` table.
   - Example (replace `amember` with your DB name):
     ```bash
     mysql -u USER -p amember < application/default/plugins/misc/passkey/db.sql
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
- If you see PHP errors about missing classes or `vendor/` directory, run `composer install` in the project root.
- If passkey registration or login fails, check browser console and PHP error logs for details.

## Uninstallation
- Disable the plugin in aMember admin.
- (Optional) Remove the `passkey` plugin folder and drop the `?_passkey_credentials` table from your database.

---

## Database Table Example (db.sql)

Create a file at `application/default/plugins/misc/passkey/db.sql` with the following content:

```sql
CREATE TABLE IF NOT EXISTS am_passkey_credentials (
    user_id INT NOT NULL,
    credential_id VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INT NOT NULL,
    transports VARCHAR(255),
    PRIMARY KEY (user_id, credential_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```
