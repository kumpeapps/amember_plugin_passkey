# aMember Passkey Plugin Structure

## Important Notes for Development

### Plugin Installation Location
- **The plugin downloads directly to the `misc/passkey` folder in aMember**
- **DO NOT manually create or copy files to `application/default/plugins/misc/passkey/`**
- The plugin file `passkey.php` should remain in the root development directory
- When installed in aMember, it will be placed in the correct location automatically

### URL Routing
- aMember routes `/misc/passkey` requests to the plugin automatically once installed
- The plugin handles AJAX requests through the `onAjax()` method
- JavaScript should make AJAX calls to `/misc/passkey` with action parameters
- The plugin registers hooks for various AJAX events in the constructor

### Development Workflow
1. Develop and test the plugin file in the root directory
2. The plugin will be packaged and installed to the correct aMember location
3. No manual file copying to subdirectories is needed during development

### Key Plugin Methods
- `onAjax()` - Handles all AJAX requests to `/misc/passkey`
- `directAction()` - Handles direct HTTP requests to the plugin URL
- Multiple hook registrations in constructor for different AJAX scenarios

This structure ensures the plugin works correctly within aMember's plugin system without manual directory management.
