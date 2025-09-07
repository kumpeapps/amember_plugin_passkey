#!/bin/bash
# aMember Plugin Reload Script
# Run this on your server to force plugin reload

echo "🔄 Forcing aMember Plugin Reload..."

# Clear aMember caches if they exist
if [ -d "/var/www/html/kumpeapps.com/www/application/data/cache" ]; then
    echo "Clearing aMember cache directory..."
    rm -rf /var/www/html/kumpeapps.com/www/application/data/cache/*
fi

# Clear any opcache if available
if command -v php &> /dev/null; then
    echo "Clearing PHP OPcache..."
    php -r "if (function_exists('opcache_reset')) { opcache_reset(); echo 'OPcache cleared'; } else { echo 'OPcache not available'; }"
fi

# Touch the plugin file to update timestamp
echo "Updating plugin timestamp..."
touch /var/www/html/kumpeapps.com/www/application/default/plugins/misc/passkey/passkey.php

# Restart PHP-FPM if available (adjust service name as needed)
if systemctl is-active --quiet php-fpm; then
    echo "Restarting PHP-FPM..."
    sudo systemctl reload php-fpm
elif systemctl is-active --quiet php7.4-fpm; then
    echo "Restarting PHP 7.4 FPM..."
    sudo systemctl reload php7.4-fpm
elif systemctl is-active --quiet php8.0-fpm; then
    echo "Restarting PHP 8.0 FPM..."
    sudo systemctl reload php8.0-fpm
elif systemctl is-active --quiet php8.1-fpm; then
    echo "Restarting PHP 8.1 FPM..."
    sudo systemctl reload php8.1-fpm
fi

echo "✅ Plugin reload steps completed!"
echo ""
echo "🔍 Now test the API endpoint and check error logs for:"
echo "  - 'Passkey Plugin: onApiRoute ENTRY'"
echo "  - 'Passkey Plugin: Got request object: YES'"
echo "  - 'Passkey Plugin: handlePasskeyConfig called'"
echo ""
echo "📊 Test URLs:"
echo "  - /api/passkey/config"
echo "  - Plugin status test page"
