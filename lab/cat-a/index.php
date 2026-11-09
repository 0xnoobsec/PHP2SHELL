<?php
// Category A lab: LFI endpoint
// Deliberately vulnerable - include from user-controlled parameter
// This simulates a common real-world LFI pattern

$page = isset($_GET['page']) ? $_GET['page'] : null;
$file = isset($_GET['file']) ? $_GET['file'] : null;
$inc  = isset($_GET['inc'])  ? $_GET['inc']  : null;
$load = isset($_GET['load']) ? $_GET['load'] : null;
$path = isset($_GET['path']) ? $_GET['path'] : null;
$doc  = isset($_GET['doc'])  ? $_GET['doc']  : null;

// Multiple param names for testing LFI param discovery
$target = $page ?? $file ?? $inc ?? $load ?? $path ?? $doc ?? null;

if ($target !== null) {
    // Direct include - vulnerable to LFI
    @include($target);
} else {
    echo "<html><head><title>Cat-A Lab</title></head><body>";
    echo "<h1>Category A - Session Upload Progress + LFI</h1>";
    echo "<p>PHP " . phpversion() . "</p>";
    echo "<p>Params: page, file, inc, load, path, doc</p>";
    echo "<p>Session save path: " . ini_get('session.save_path') . "</p>";
    echo "<p>upload_progress.enabled: " . ini_get('session.upload_progress.enabled') . "</p>";
    echo "<p>upload_progress.cleanup: " . ini_get('session.upload_progress.cleanup') . "</p>";
    echo "<p><a href='/info.php'>phpinfo()</a></p>";
    echo "</body></html>";
}
