<?php
// Category C leak endpoint: session starts before any output, like a real app
session_start();
header('Content-Type: text/plain');
if (!empty($_FILES)) {
    echo "files=" . count($_FILES) . "\n";
} else {
    echo "no-files sid=" . session_id() . "\n";
}
echo "ok\n";
