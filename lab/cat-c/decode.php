<?php
// Category C lab: DECODE endpoint
// Triggers unserialize() on attacker-controlled data
// CVE-2026-109618: >1018 back-references overflow VAR_ENTRIES_MAX
// causing use-after-free in var_unserializer.re

error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: text/plain');

// Method 1: Direct unserialize of POST body
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['payload'])) {
    $payload = $_POST['payload'];
    echo "[*] Received payload: " . strlen($payload) . " bytes\n";
    echo "[*] Back-reference count estimate: " . substr_count($payload, 'R:') . "\n";
    echo "[*] VAR_ENTRIES_MAX = 1018\n";
    echo "[*] Memory limit: " . ini_get('memory_limit') . "\n";
    echo "[*] Calling unserialize()...\n";
    flush();

    // This is the vulnerable call - with >1018 R: back-references,
    // the var_entries array overflows and freed pointers are reused
    $before_mem = memory_get_usage(true);
    $result = @unserialize($payload);
    $after_mem = memory_get_usage(true);

    echo "[*] Memory delta: " . ($after_mem - $before_mem) . " bytes\n";

    if ($result !== false) {
        echo "[+] Deserialization succeeded\n";
        echo "[+] Result type: " . gettype($result) . "\n";
        if (is_object($result)) {
            echo "[+] Object class: " . get_class($result) . "\n";
        } elseif (is_array($result)) {
            echo "[+] Array size: " . count($result) . "\n";
        }
    } else {
        $err = error_get_last();
        echo "[-] Deserialization returned false\n";
        if ($err) {
            echo "[-] Last error: " . $err['message'] . "\n";
            echo "[-] Error type: " . $err['type'] . "\n";
        }
    }
    exit;
}

// Method 2: Session-based trigger via upload progress
// The session handler calls unserialize() on session data during session_start()
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_FILES)) {
    echo "[*] File upload received, session handler will unserialize session data\n";
    echo "[*] Session save path: " . ini_get('session.save_path') . "\n";
    echo "[*] Session handler: " . ini_get('session.serialize_handler') . "\n";

    session_start();
    echo "[*] session_start() completed\n";
    echo "[*] Session ID: " . session_id() . "\n";

    if (!empty($_SESSION)) {
        echo "[+] Session data present:\n";
        print_r($_SESSION);
    }
    exit;
}

// Method 3: Raw body unserialize (for binary payloads)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = file_get_contents('php://input');
    if (strlen($raw) > 0) {
        echo "[*] Raw POST body: " . strlen($raw) . " bytes\n";
        echo "[*] Calling unserialize() on raw body...\n";
        flush();

        $result = @unserialize($raw);

        if ($result !== false) {
            echo "[+] Deserialization succeeded\n";
            echo "[+] Result type: " . gettype($result) . "\n";
        } else {
            $err = error_get_last();
            echo "[-] Deserialization returned false\n";
            if ($err) {
                echo "[-] Last error: " . $err['message'] . "\n";
            }
        }
        exit;
    }
}

// GET: show info page
echo "<html><head><title>Cat-C Decode</title></head><body>";
echo "<h1>Category C - UAF Trigger (unserialize)</h1>";
echo "<p>PHP " . phpversion() . "</p>";
echo "<p>Memory limit: " . ini_get('memory_limit') . "</p>";
echo "<p>VAR_ENTRIES_MAX: 1018 (hardcoded in ext/standard/var_unserializer.re)</p>";

echo "<h2>Method 1: POST payload=&lt;serialized_data&gt;</h2>";
echo "<form method='POST'>";
echo "<textarea name='payload' rows='10' cols='80' placeholder='Paste serialized payload with >1018 R: back-references...'></textarea><br>";
echo "<button type='submit'>Trigger unserialize()</button>";
echo "</form>";

echo "<h2>Method 2: File upload (session-based trigger)</h2>";
echo "<form method='POST' enctype='multipart/form-data'>";
echo "<input type='hidden' name='PHP_SESSION_UPLOAD_PROGRESS' value='test'>";
echo "<input type='file' name='file'><br>";
echo "<button type='submit'>Upload + session_start()</button>";
echo "</form>";

echo "<h2>Method 3: Raw POST body</h2>";
echo "<p>Send raw serialized data as the POST body (no form encoding)</p>";
echo "<pre>curl -X POST -d 'a:2:{...}' http://host/decode.php</pre>";

echo "<p><a href='/'>Back to index</a></p>";
echo "</body></html>";
