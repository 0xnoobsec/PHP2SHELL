<?php
echo "<html><head><title>Cat-B Lab</title></head><body>";
echo "<h1>Category B - Session Handler Mismatch + POP Chains</h1>";
echo "<p>PHP " . phpversion() . "</p>";
echo "<ul>";
echo "<li><a href='/seed/'>/seed/</a> — php_serialize handler (writes session data)</li>";
echo "<li><a href='/fire/'>/fire/</a> — php handler (reads + deserializes injected objects)</li>";
echo "<li><a href='/info.php'>phpinfo()</a></li>";
echo "</ul>";
echo "<p>Monolog installed: " . (file_exists('/var/www/html/vendor/monolog') ? 'YES' : 'NO') . "</p>";
echo "<p>Guzzle installed: " . (file_exists('/var/www/html/vendor/guzzlehttp') ? 'YES' : 'NO') . "</p>";
echo "</body></html>";
