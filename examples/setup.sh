#!/bin/bash

# Setup script for Simple Passkey Authentication
echo "🔧 Setting up Simple Passkey Authentication..."

# Check if we're in the right directory
if [ ! -f "server.php" ]; then
    echo "❌ Error: Please run this script from the examples directory"
    exit 1
fi

# Create config.php from example if it doesn't exist
if [ ! -f "config.php" ]; then
    echo "📝 Creating config.php from example..."
    cp config.example.php config.php
    echo "⚠️  Please edit config.php with your database settings!"
fi

# Check if PHP is installed
if ! command -v php &> /dev/null; then
    echo "❌ Error: PHP is not installed"
    exit 1
fi

echo "✅ PHP found: $(php -v | head -n 1)"

# Check if MySQL/MariaDB is available
if command -v mysql &> /dev/null; then
    echo "✅ MySQL found: $(mysql --version)"
elif command -v mariadb &> /dev/null; then
    echo "✅ MariaDB found: $(mariadb --version)"
else
    echo "⚠️  Warning: No MySQL/MariaDB found. Make sure your database is accessible."
fi

# Check if Composer is installed (for future use)
if command -v composer &> /dev/null; then
    echo "✅ Composer found: $(composer --version --no-ansi | head -n 1)"
    
    # If composer.json exists, install dependencies
    if [ -f "composer.json" ]; then
        echo "📦 Installing Composer dependencies..."
        composer install --no-dev --optimize-autoloader
    fi
else
    echo "⚠️  Composer not found. Installing for future use..."
    
    # Download and install Composer locally
    php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
    
    # Verify installer (optional, but recommended)
    EXPECTED_CHECKSUM="$(php -r 'copy("https://composer.github.io/installer.sig", "php://stdout");')"
    ACTUAL_CHECKSUM="$(php -r "echo hash_file('sha384', 'composer-setup.php');")"
    
    if [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then
        echo "❌ Error: Invalid Composer installer checksum"
        rm composer-setup.php
        exit 1
    fi
    
    # Install Composer
    php composer-setup.php --quiet
    rm composer-setup.php
    
    echo "✅ Composer installed locally as composer.phar"
fi

# Test PHP syntax
echo "🧪 Testing PHP syntax..."
php -l server.php
if [ $? -eq 0 ]; then
    echo "✅ server.php syntax OK"
else
    echo "❌ Error: server.php has syntax errors"
    exit 1
fi

php -l index.html
if [ $? -eq 0 ]; then
    echo "✅ index.html syntax OK"
else
    echo "❌ Error: index.html has syntax errors"
    exit 1
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit config.php with your database settings"
echo "2. Run the SQL in setup.sql to create database tables"
echo "3. Start the development server:"
echo "   php -S localhost:8080"
echo "4. Open http://localhost:8080 in your browser"
echo ""
echo "For production deployment:"
echo "1. Update rp_id in config.php to your domain"
echo "2. Ensure HTTPS is configured"
echo "3. Test on your production domain"
