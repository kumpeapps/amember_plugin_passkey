<?php

// Test file to debug class loading issue
define('AM_APPLICATION_PATH', '/tmp'); // Mock the constant

// Try to load just the class definition part
$content = file_get_contents('passkey.php');

// Extract just the class definition (everything from class declaration to first method)
preg_match('/class Am_Plugin_Passkey.*?{.*?function init/s', $content, $matches);

if (empty($matches)) {
    echo "Could not extract class definition\n";
    exit(1);
}

echo "Class definition extracted successfully\n";
echo "Length: " . strlen($matches[0]) . " characters\n";

// Try to find any syntax issues
$classStart = strpos($content, 'class Am_Plugin_Passkey');
$classEnd = strrpos($content, '}');

if ($classStart === false) {
    echo "ERROR: Could not find class start\n";
    exit(1);
}

if ($classEnd === false) {
    echo "ERROR: Could not find class end\n";
    exit(1);
}

echo "Class starts at position: $classStart\n";
echo "Class ends at position: $classEnd\n";
echo "Class length: " . ($classEnd - $classStart + 1) . " characters\n";

// Check for basic syntax
$errors = [];
$lines = explode("\n", $content);
$braceCount = 0;
$inClass = false;

foreach ($lines as $lineNum => $line) {
    if (strpos($line, 'class Am_Plugin_Passkey') !== false) {
        $inClass = true;
    }
    
    if ($inClass) {
        $braceCount += substr_count($line, '{');
        $braceCount -= substr_count($line, '}');
    }
}

echo "Final brace count: $braceCount (should be 0)\n";

if ($braceCount != 0) {
    echo "ERROR: Unmatched braces detected!\n";
} else {
    echo "SUCCESS: Braces are balanced\n";
}
