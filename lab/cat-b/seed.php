<?php
// Category B lab: SEED endpoint
// Uses php_serialize session handler
// Writes session data that the /fire endpoint will deserialize with the php handler
// The handler mismatch allows injecting arbitrary serialized objects

// php_serialize writes: key|s:N:"value";
// When php handler reads this, the pipe in the VALUE is treated as a key/value delimiter
// allowing injection of arbitrary serialized objects

session_start();

if (isset($_POST['data'])) {
    $_SESSION['data'] = $_POST['data'];
    echo "Session data stored (php_serialize handler).\n";
    echo "Session ID: " . session_id() . "\n";
    echo "Handler: " . ini_get('session.serialize_handler') . "\n";
} else {
    echo "<html><head><title>Cat-B Seed</title></head><body>";
    echo "<h1>Category B - Seed (php_serialize handler)</h1>";
    echo "<p>PHP " . phpversion() . "</p>";
    echo "<p>Handler: " . ini_get('session.serialize_handler') . "</p>";
    echo "<p>Session ID: " . session_id() . "</p>";
    echo "<form method='POST'>";
    echo "<textarea name='data' rows='5' cols='60' placeholder='Enter session data...'></textarea><br>";
    echo "<button type='submit'>Store in session</button>";
    echo "</form>";
    echo "<p><a href='/fire/'>Go to Fire endpoint (php handler)</a></p>";
    echo "</body></html>";
}
