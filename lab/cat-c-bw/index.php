<?php
// Landing page for the Category C containers. Descriptive text only.
echo "<html><head><title>Cat-C Lab</title></head><body>";
echo "<h1>Category C - memory behaviour lab</h1>";
echo "<p>PHP " . phpversion() . "</p>";
echo "<p>Memory limit: " . ini_get('memory_limit') . "</p>";
echo "<ul>";
echo "<li><a href='/decode.php'>/decode.php</a> - the endpoint the harness posts to</li>";
if (file_exists(__DIR__ . '/info.php')) {
    echo "<li><a href='/info.php'>phpinfo()</a></li>";
}
echo "</ul>";
echo "<h2>What is tested here</h2>";
echo "<p>CVE-2026-109618 and CVE-2026-109619: a multipart request that runs PHP out of ";
echo "memory while it is still parsing, followed by a request that carries only the ";
echo "upload-progress field. On PHP 8.4.26 the worker then aborts with ";
echo "<code>zend_mm_heap corrupted</code>. On the patched releases it does not.</p>";
echo "<p>The harness also sends an unserialize() payload with many back-references. ";
echo "That is a detection probe: on the builds tested it decodes without corruption.</p>";
echo "<p>No code execution through memory corruption has been demonstrated with this lab.</p>";
echo "</body></html>";
