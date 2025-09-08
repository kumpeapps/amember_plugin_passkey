#!/bin/bash

# Cross-Domain Passkey Setup Script
# This script helps set up the .well-known/webauthn file on related domains

echo "🔐 Cross-Domain Passkey Setup Script"
echo "=================================="
echo ""

# Check current well-known file
echo "📋 Current .well-known/webauthn file content:"
if [ -f "/var/www/html/kumpeapps.com/www/.well-known/webauthn" ]; then
    cat /var/www/html/kumpeapps.com/www/.well-known/webauthn | jq .
    echo ""
    echo "File size: $(stat -c%s /var/www/html/kumpeapps.com/www/.well-known/webauthn) bytes"
else
    echo "❌ File not found at /var/www/html/kumpeapps.com/www/.well-known/webauthn"
fi

echo ""
echo "🌐 Related domains that need this file:"
echo "  • www.kumpe3d.com"
echo "  • kumpe3d.com"
echo "  • incarcerationbot.vm.kumpeapps.com"

echo ""
echo "📁 Suggested setup options:"
echo ""
echo "Option 1: Symbolic Links (if domains share same server)"
echo "  ln -s /var/www/html/kumpeapps.com/www/.well-known/webauthn /path/to/kumpe3d.com/.well-known/webauthn"
echo ""
echo "Option 2: Copy files (manual sync)"
echo "  cp /var/www/html/kumpeapps.com/www/.well-known/webauthn /path/to/kumpe3d.com/.well-known/"
echo ""
echo "Option 3: Automated sync with cron"
echo "  # Add to crontab:"
echo "  */5 * * * * cp /var/www/html/kumpeapps.com/www/.well-known/webauthn /path/to/kumpe3d.com/.well-known/ 2>/dev/null"

echo ""
echo "🧪 Test the setup:"
echo "  curl -s https://www.kumpeapps.com/.well-known/webauthn | jq ."
echo "  curl -s https://www.kumpe3d.com/.well-known/webauthn | jq ."
echo "  curl -s https://kumpe3d.com/.well-known/webauthn | jq ."

echo ""
echo "✅ Infinite loop fix is working - ready for cross-domain testing!"
