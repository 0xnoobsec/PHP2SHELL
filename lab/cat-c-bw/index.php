<?php
echo "<html><head><title>Cat-C Lab</title></head><body>";
echo "<h1>Category C - UAF via VAR_ENTRIES_MAX Overflow</h1>";
echo "<p>PHP " . phpversion() . "</p>";
echo "<p>CVE-2026-109618: Use-after-free in ext/standard/var_unserializer.re</p>";
echo "<ul>";
echo "<li><a href='/decode.php'>/decode.php</a> — Trigger unserialize() with crafted payload</li>";
echo "<li><a href='/info.php'>phpinfo()</a></li>";
echo "</ul>";
echo "<h2>Attack Vector</h2>";
echo "<p>Send a serialized payload with &gt;1018 back-references (R:N;) to overflow ";
echo "the VAR_ENTRIES_MAX limit. The overflow causes freed zval pointers to be reused, ";
echo "enabling heap corruption and potential code execution.</p>";
echo "<h2>Heap Spray</h2>";
echo "<p>Memory limit: " . ini_get('memory_limit') . " (high for spray room)</p>";
echo "<p>The PoC sprays ~50 stdClass objects to fill freed slots with controlled data.</p>";
echo "</body></html>";
