<?php
// Reports which worker process answered. c_validate.py calls this before and
// after each trial: a changed pid means the worker that served the trial died.
//
// The October 2026 runs used a probe like this one (the raw logs show
// "GET /probe.php"), but that file was not kept. This is a replacement. The
// validator reads only "pid".
header('Content-Type: application/json');
echo json_encode([
    'pid' => getmypid(),
    'php' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'memory_limit' => ini_get('memory_limit'),
]);
