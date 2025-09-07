#!/bin/bash
# Force Plugin Update Script for aMember
# Run this script on your server to force the enhanced plugin to load

echo "🔄 Force updating aMember Passkey plugin..."

PLUGIN_PATH="/var/www/html/kumpeapps.com/www/application/default/plugins/misc/passkey"

# Step 1: Clear all caches
echo "1. Clearing aMember caches..."
rm -rf /var/www/html/kumpeapps.com/www/application/data/cache/* 2>/dev/null || true
rm -rf /var/www/html/kumpeapps.com/www/application/data/tmp/* 2>/dev/null || true

# Step 2: Clear PHP OPcache
echo "2. Clearing PHP OPcache..."
php -r "if (function_exists('opcache_reset')) { opcache_reset(); echo 'OPcache cleared\n'; } else { echo 'OPcache not available\n'; }"

# Step 3: Update plugin file timestamp
echo "3. Updating plugin timestamp..."
if [ -f "$PLUGIN_PATH/passkey.php" ]; then
    touch "$PLUGIN_PATH/passkey.php"
    echo "Plugin file timestamp updated"
else
    echo "❌ Plugin file not found at: $PLUGIN_PATH/passkey.php"
    echo "Please upload the updated plugin file to the correct location"
fi

# Step 4: Restart PHP-FPM (try multiple service names)
echo "4. Restarting PHP-FPM..."
for service in php-fpm php8.2-fpm php8.1-fpm php8.0-fpm php7.4-fpm; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        echo "Restarting $service..."
        sudo systemctl reload $service
        break
    fi
done

echo ""
echo "✅ Plugin update complete!"
echo ""
echo "🔍 Now test the API endpoint and look for:"
echo "  - 'ENHANCED DEBUGGING VERSION 2.0' in error logs"
echo "  - 'onApiRoute ENTRY - Starting API route handling'"
echo ""
echo "📊 Test API: https://www.kumpeapps.com/api/passkey/config"
echo "📋 Check logs: tail -f /var/log/apache2/error.log | grep 'Passkey Plugin'"
