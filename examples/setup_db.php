<?php
/**
 * Database Setup Script
 * Automatically creates required tables
 */

$config = require_once 'config.php';

try {
    $pdo = new PDO(
        "mysql:host={$config['host']};dbname={$config['database']}",
        $config['username'],
        $config['password'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    
    echo "Connected to database successfully.\n";
    
    // Read and execute SQL from setup.sql
    $sql = file_get_contents('setup.sql');
    
    if ($sql === false) {
        die("Could not read setup.sql file\n");
    }
    
    // Split SQL into individual statements
    $statements = array_filter(array_map('trim', explode(';', $sql)));
    
    foreach ($statements as $statement) {
        if (!empty($statement)) {
            try {
                $pdo->exec($statement);
                echo "Executed: " . substr($statement, 0, 50) . "...\n";
            } catch (PDOException $e) {
                // Ignore table already exists errors
                if (strpos($e->getMessage(), 'already exists') === false) {
                    echo "Error executing statement: " . $e->getMessage() . "\n";
                }
            }
        }
    }
    
    // Check if tables were created
    $result = $pdo->query("SHOW TABLES");
    $tables = $result->fetchAll(PDO::FETCH_COLUMN);
    
    echo "\nTables in database:\n";
    foreach ($tables as $table) {
        echo "- $table\n";
    }
    
    // Check for required tables
    $requiredTables = ['users', 'passkey_credentials'];
    $missingTables = array_diff($requiredTables, $tables);
    
    if (empty($missingTables)) {
        echo "\n✅ All required tables exist!\n";
    } else {
        echo "\n❌ Missing tables: " . implode(', ', $missingTables) . "\n";
    }
    
} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage() . "\n";
    echo "\nPlease check your config.php settings:\n";
    echo "- Host: {$config['host']}\n";
    echo "- Database: {$config['database']}\n";
    echo "- Username: {$config['username']}\n";
    echo "- Password: [hidden]\n";
}
