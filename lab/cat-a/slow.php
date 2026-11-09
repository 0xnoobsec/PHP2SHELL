<?php
// Slow endpoint - keeps connection open to extend session file lifetime
// Used by the race condition exploit: while this request is processing,
// the session file exists on disk and can be included via LFI

session_start();

// Read slowly to keep the session file alive
$delay = isset($_GET['delay']) ? (int)$_GET['delay'] : 30;
$delay = min($delay, 120); // cap at 2 minutes

header('Content-Type: text/plain');
echo "Processing slowly for {$delay} seconds...\n";
flush();

for ($i = 0; $i < $delay; $i++) {
    echo ".";
    flush();
    sleep(1);
}

echo "\nDone.\n";
