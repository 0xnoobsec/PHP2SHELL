<?php
// Category B lab: FIRE endpoint
// Uses php session handler (default)
// When it reads session data written by the php_serialize handler,
// the pipe character | inside the serialized value is misinterpreted
// as a session key/value separator, triggering deserialization of injected objects

// Autoload Monolog/Guzzle for POP chain exploitation
if (file_exists('/var/www/html/gadget.php')) {
    require_once '/var/www/html/gadget.php';
}
if (file_exists('/var/www/html/vendor/autoload.php')) {
    require_once '/var/www/html/vendor/autoload.php';
}

session_start();

echo "<html><head><title>Cat-B Fire</title></head><body>";
echo "<h1>Category B - Fire (php handler)</h1>";
echo "<p>PHP " . phpversion() . "</p>";
echo "<p>Handler: " . ini_get('session.serialize_handler') . "</p>";
echo "<p>Session ID: " . session_id() . "</p>";

if (!empty($_SESSION)) {
    echo "<h2>Session Data:</h2><pre>";
    print_r($_SESSION);
    echo "</pre>";
} else {
    echo "<p>No session data. <a href='/seed/'>Go seed some data first</a></p>";
}

// Show loaded classes for POP chain reconnaissance
echo "<h2>Loaded Classes (" . count(get_declared_classes()) . "):</h2>";
echo "<details><summary>Click to expand</summary><pre>";
foreach (get_declared_classes() as $cls) {
    if (strpos($cls, 'Monolog') !== false || strpos($cls, 'Guzzle') !== false) {
        echo $cls . "\n";
    }
}
echo "</pre></details>";

echo "<p>Monolog loaded: " . (class_exists('Monolog\\Logger') ? 'YES' : 'NO') . "</p>";
echo "<p>Guzzle loaded: " . (class_exists('GuzzleHttp\\Client') ? 'YES' : 'NO') . "</p>";
echo "</body></html>";
