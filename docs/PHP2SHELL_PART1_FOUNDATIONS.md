# Understanding PHP2Shell: PHP Internals, Sessions, and Memory Management

*Part 1 of a three-part laboratory study of PHP's request lifecycle, sessions, out-of-memory handling, and CVE-2026-109618 / CVE-2026-109619.*

> **PHP2Shell series**
> 1. **Foundations: PHP Internals, Sessions, and Memory Management** — *you are here*
> 2. Source-Code Analysis: Analyzing the PHP Source Code and Security Patches
> 3. Original Research: Reproducing Memory Corruption and Analyzing the Results
>
> *Audience for this part: beginners, pentesters, and developers. No prior memory-corruption experience assumed.*

## 1. Introduction and research objective

I recently spent some time investigating two PHP core vulnerabilities, CVE-2026-109618 and CVE-2026-109619, following the PHP2Shell research published by Calif.

The vulnerabilities involve how PHP handles out-of-memory (OOM) conditions and partially initialized internal state. Under certain conditions, an operation can be interrupted before PHP finishes updating or cleaning up its internal data structures.

I wanted to understand what was actually happening inside PHP rather than simply run an existing exploit and observe the result.

My initial goal was straightforward: build a vulnerable PHP environment, reproduce the reported behavior, compare it against patched versions, and understand the underlying code.

It turned out to be more complicated than I expected.

Some tests failed because of incorrect configuration. Others successfully triggered OOM without producing memory corruption. At one point, five consecutive trials suggested a 100% reproduction rate. When I increased the sample size to 20, the observed rate dropped to 50%.

Along the way the work split into three categories. Two of them turned out to be application-level problems that patching PHP does not fix. The third is the engine bug the series spends most of its time on.

This is a three-part write-up of what I learned:

* **Part 1 (this part)** builds the PHP concepts needed to understand the issue and a small laboratory for studying request and memory behavior.
* **Part 2** examines the PHP source code and compares the vulnerable and patched releases.
* **Part 3** presents the reproduction, the measured results, all three categories, and the limitations of my findings.

The lab exercises focus on demonstrations against an isolated local environment. The harness used for the experiments — including the command-execution chains and the corruption trigger — is in the repository's `poc/` directory. Run it only against the lab in `lab/`.

**A note on what this series claims.** Wherever I describe a mechanism from source code, I try to say so. Wherever I describe something I measured, I try to give the number. The two are not the same kind of statement, and most of the mistakes in this project came from blurring them.

### Where the series lands

This summary is the destination; Parts 2 and 3 substantiate it.

| Research question | Finding |
|---|---|
| Can ordinary OOM be reproduced? | Yes, on all five tested builds |
| Was allocator corruption observed? | Yes, 10/20 trials on PHP 8.4.26 |
| Was corruption observed on patched comparisons? | No, 0/20 on each of the four |
| Was the original corruption site identified? | No |
| Was RCE demonstrated through memory corruption? | No |
| Did application-level chains work on patched PHP? | Yes, in the synthetic lab |

---

## 2. PHP request lifecycle and sessions

### 2.1 The pipeline

When someone visits a PHP application running on Apache, the process generally looks like this:

```text
Browser
   |
   | HTTP Request
   v
Apache
   |
   v
PHP Request Initialization
   |
   v
Parse GET / POST / FILES
   |
   v
Initialize Extensions
   |
   v
Execute PHP Application
   |
   v
Request Shutdown
   |
   v
HTTP Response
```

This is simplified. The exact lifecycle depends on the SAPI and configuration.

Two things matter for this research.

First, PHP performs considerable work before executing the application's script. It may parse request bodies, process uploaded files, initialize internal data structures, and invoke extension callbacks.

Second, a server process can handle multiple requests over its lifetime.

That means the engine must correctly initialize and clean up request-specific resources. Otherwise, problems can appear during later processing.

### 2.2 What a PHP worker is

With Apache's prefork model and mod_php, a worker process handles one request, finishes it, and may later handle another.

```text
Worker Process
    |
    +-- Request 1
    |      |-- Initialization
    |      |-- Execution
    |      +-- Cleanup
    |
    +-- Request 2
           |-- Initialization
           |-- Execution
           +-- Cleanup
```

Each request has its own lifecycle even though the process survives.

### 2.3 A conditional in request shutdown

There is a detail in this lifecycle worth knowing before reading the rest, because it shapes several of the observations later.

PHP sets a flag when extension initialization has completed:

```c
/* main/main.c, php_request_startup() — excerpt */
php_hash_environment();      /* parses POST, multipart, uploads  */
zend_activate_modules();     /* RINIT for every extension        */
PG(modules_activated) = 1;
```

and request shutdown only calls extension shutdown when that flag is set:

```c
/* main/main.c, php_request_shutdown() — excerpt */
if (PG(modules_activated)) {
    zend_deactivate_modules();
}
```

Read together, these two excerpts describe a conditional path: if a fatal error occurs during request parsing — before module activation — extension shutdown is not run for that request.

I want to be precise about what that does and does not tell us.

It tells us the *control flow* has a branch that skips extension cleanup. It does not, by itself, establish that any particular pointer became dangling, that the worker always survived, or that skipped cleanup caused the corruption I later observed. Those are separate questions, and Part 3 shows that my evidence for them is partial.

What it does give us is a plausible lifecycle inconsistency to keep in mind: a request can end with its heap discarded but without the extension cleanup that would normally run first.

### 2.4 Sessions

PHP sessions allow applications to maintain information across requests.

```php
<?php
session_start();

$_SESSION['username'] = 'alice';
$_SESSION['authenticated'] = true;

echo "Session initialized";
```

PHP associates the session with an identifier, usually carried in a cookie such as `PHPSESSID`. A later request can read the data back:

```php
<?php
session_start();

echo $_SESSION['username'] ?? 'Guest';
```

Depending on the configured handler, session data may live in files, a database, Redis, or another backend.

The identifier and the data are different things. That sounds obvious, and it becomes relevant in Part 3.

### 2.5 Session upload progress

PHP can track multipart upload progress through session data, via `session.upload_progress`.

```text
HTTP Multipart Request
       |
       v
PHP Multipart Parser
       |
       v
Upload Progress Callback
       |
       v
Session Progress Update
       |
       v
Continue Processing Upload
```

The interesting property is that the upload-progress callback can perform session operations **while PHP is still parsing the request** — before the application script runs.

### 2.6 Session state initialized during parsing

Here is the code path that does it:

```c
/* ext/session/session.c, MULTIPART_EVENT_FILE_START — excerpt */
if (Z_ISUNDEF(progress->data)) {
    ...
    php_rinit_session(0);
    PS(id) = zend_string_init(Z_STRVAL(progress->sid), Z_STRLEN(progress->sid), 0);
    ...
}
```

Two observations from this excerpt:

* `PS(id)` is a string allocated during request processing, on the request heap.
* This runs during `php_hash_environment()`, before `zend_activate_modules()` — so the flag in section 2.3 is still 0.

The cleanup that would normally release that string lives in `php_rshutdown_session_globals()`, an extension shutdown handler — the same path gated by the conditional above.

So the pieces fit together: an early session initialization, and a shutdown path that is skipped when parsing fails. Whether that combination produces an exploitable inconsistency is a separate question — one I could not answer completely. It is the question Part 3 works on, with the source detail supplied in Part 2.

---

## 3. A beginner Docker lab: sessions, memory, and OOM

Before looking at engine internals, it helps to build a small lab and watch ordinary behavior: sessions persisting, memory being used, and a normal OOM error.

You need Docker and a terminal.

```text
php-memory-lab/
├── Dockerfile
├── php.ini
├── compose.yaml
├── index.php
├── memory.php
├── oom.php
└── session_info.php
```

### 3.1 Dockerfile

```dockerfile
FROM php:8.4-apache

COPY php.ini /usr/local/etc/php/conf.d/lab.ini
COPY ./*.php /var/www/html/
```

Two notes on reproducibility.

The image tag `php:8.4-apache` floats: it currently resolves to a patched 8.4 release, and will move again. If you need a stable environment, something like `php:8.4.27-apache` is better than the floating tag — but a tag is still not a digest. To pin exactly:

```bash
docker image inspect php:8.4.27-apache --format '{{index .RepoDigests 0}}'
```

and use the resulting `name@sha256:...` reference.

Also note that the Dockerfile copies every PHP file in the directory. If you add `oom.php` later (exercise 2), it will be present — provided you rebuild. Forgetting the rebuild is a classic "the file does not exist" moment.

### 3.2 php.ini

```ini
memory_limit = 16M
display_errors = On
log_errors = On
session.upload_progress.enabled = On
```

The low memory limit is for observing ordinary OOM handling. It is not intended to reproduce the vulnerability.

### 3.3 index.php

```php
<?php

session_start();

$_SESSION['visits'] =
    ($_SESSION['visits'] ?? 0) + 1;

echo "<h2>PHP Memory Lab</h2>";

echo "PHP Version: " . PHP_VERSION . "<br>";
echo "Session active: " .
    (session_status() === PHP_SESSION_ACTIVE ? "yes" : "no") . "<br>";
echo "Visits: " . $_SESSION['visits'] . "<br>";

echo "Memory Limit: " .
    ini_get('memory_limit') . "<br>";

echo "Memory Usage: " .
    memory_get_usage(true) . "<br>";
```

The page deliberately does not print the session identifier. If you need it for local debugging, print it temporarily and never on a page reachable by others.

### 3.4 compose.yaml

```yaml
services:
  php:
    build: .
    ports:
      - "127.0.0.1:8080:80"
```

```bash
docker compose up --build -d
```

Open `http://127.0.0.1:8080` and refresh a few times. The visit counter should increase, showing session data persisting across requests.

### 3.5 Exercise 1: watch memory usage

Save this as `memory.php` and open it in the lab:

```php
<?php
$data = [];
for ($i = 0; $i < 1000; $i++) {
    $data[] = str_repeat("A", 1024);
}
echo "Memory usage: " . memory_get_usage(true);
```

Compare a few sizes. The point is to build intuition for how allocation shows up in the number — not to reach the limit.

### 3.6 Exercise 2: an ordinary OOM

```php
<?php
ini_set('memory_limit', '8M');
$data = str_repeat('A', 16 * 1024 * 1024);
echo strlen($data);
```

Rebuild, then open `oom.php`. You should see a fatal error about the allowed memory size.

This demonstrates ordinary memory-limit enforcement. It does **not** demonstrate heap corruption, a session vulnerability, or code execution.

That distinction matters, and it is easy to lose when the same word — "OOM" — appears in a CVE description and in a test script.

### 3.7 Exercise 3: find where sessions actually live

Do not assume the session directory. Save this as `session_info.php` and ask PHP:

```php
<?php
header('Content-Type: text/plain');

echo "save_handler: " . ini_get('session.save_handler') . "\n";
echo "serialize_handler: " . ini_get('session.serialize_handler') . "\n";
echo "save_path: " . ini_get('session.save_path') . "\n";
```

Then, inside the container:

```bash
docker compose exec php php -r 'echo session_save_path(), PHP_EOL;'
```

Several practical warnings:

* `save_path` can be empty, in which case PHP falls back to a default that is
  not necessarily visible from that one call. Check the effective value with
  `docker compose exec php php -i | grep session.save_path`, and treat the
  compiled-in fallback as something to look up rather than guess.
* It can also use the `N;/path` or `N;MODE;/path` syntax, where the leading number is a directory level and a hash of the session ID chooses the subdirectory. Treat the configured value as a *format*, not a path.
* Session data may only be written when the request finishes, so inspecting the directory during a request can show nothing.
* Only the `files` handler uses files. With Redis or another handler there is nothing to list.

A safer way to identify the right file is by modification time rather than by printing the session identifier:

```bash
P=$(docker compose exec -T php php -r 'echo session_save_path();')

if [ -n "$P" ]; then
    docker compose exec -T php ls -lat "$P"
else
    echo "Session path is empty; check the effective configuration."
fi
```

You are looking for a small file that changed when you refreshed the page. Its contents will look like:

```text
visits|i:3;
```

That line is the whole session. In Part 3 we will see why "the session is just bytes in a file" matters.

---

## 4. C fundamentals: pointers, structs, and hash tables

PHP is written primarily in C, so a little C helps when reading the source.

### 4.1 Pointers

```c
int age = 25;
int *p = &age;
```

`"age"` holds 25, `&age` is its address, `p` stores that address, and `*p` reads through it.

A pointer does not own what it points at. It holds an address, and nothing more.

### 4.2 Allocation and free

```c
#include <stdlib.h>

int *p = malloc(sizeof(int));

if (p == NULL) {
    return 1;
}

*p = 25;
free(p);
```

The allocation can fail, so the program checks. After `free(p)` the allocation is gone even though `p` still holds the old address. Reading through it is a use-after-free.

### 4.3 Inconsistent state

Suppose a structure tracks ten objects:

```text
objects = 10
```

but only nine were fully initialized. Code that trusts the counter will read the tenth anyway.

That is the shape of the bug family in this series: a counter or pointer that is published before the thing it describes is complete.

### 4.4 Hash tables

PHP arrays are hash tables. This:

```php
<?php
$user = ['name' => 'Alice', 'age' => 25];
```

becomes buckets holding keys and values, plus bookkeeping fields on the table itself. One of those fields is `nNumUsed`, which counts used bucket slots.

A simplified view of an insertion:

```text
1. index = table->nNumUsed++;
2. bucket = table->arData + index;
3. bucket->key = ...;
4. bucket->value = ...;
```

The counter advances before the bucket is filled. That ordering is not automatically a bug — it depends on what can happen between steps 1 and 4. If step 3 can fail by returning normally, the caller can deal with it. If step 3 can *jump out of the function* instead, the table is left with a counted-but-unfilled slot.

### 4.5 What the source actually looks like

Here is an excerpt from PHP 8.4.26 (abbreviated with `...` for the parts not relevant here):

```c
/* Zend/zend_hash.c — excerpt, abbreviated */
add_to_hash:
    idx = ht->nNumUsed++;                            /* count first */
    ht->nNumOfElements++;
    p = ht->arData + idx;
    p->key = key = zend_string_init(str, len, ...);  /* can fail */
    ...
    p->h = ZSTR_H(key) = h;
    ZVAL_COPY_VALUE(&p->val, pData);
```

And an excerpt from table destruction:

```c
/* Zend/zend_hash.c, zend_array_destroy() — excerpt */
for (p = ht->arData; p != ht->arData + ht->nNumUsed; p++) {
    i_zval_ptr_dtor(&p->val);
    if (p->key) { zend_string_release(p->key); }
}
```

Teardown iterates up to `nNumUsed`. If an insertion had been interrupted between the counter increment and the bucket fill, that loop would be one bucket longer than the initialized data — and would read a slot that was never written.

I want to be careful with that sentence: it describes a **conditional** consequence. It is not a claim that this is what happened in my lab. Part 3 explains why I could not establish that.

### 4.6 Exercise: read the struct

Open `Zend/zend_hash.h` and find `Bucket`. Then answer:

* which fields does the insert excerpt write?
* which of them does the destruction loop read?
* what is `arData`, and what does `arData + idx` point at?

That is enough to see the concern from source alone.

---

## 5. Understanding PHP's OOM handling

### 5.1 What memory_limit actually limits

```ini
memory_limit = 16M
```

This does not mean the machine has 16 MB. It means PHP's memory manager accounts for request allocations against a 16 MB budget.

Exceeding it produces:

```text
Fatal error: Allowed memory size of 16777216 bytes exhausted
```

That message is ordinary and expected for a runaway allocation.

### 5.2 The three-step problem

Now suppose the engine is in the middle of an internal operation:

```text
1. publish state      (count the slot)
2. fallible work      (allocate memory for it)
3. finish             (fill the slot)
```

If step 2 fails by returning an error, the caller can undo step 1 or simply abort safely.

If step 2 fails by *jumping out*, steps 1 and 3 disagree: the count says the slot exists, the memory says it does not.

### 5.3 zend_bailout

PHP uses `zend_bailout()` for nonlocal control flow on fatal conditions. It is not a return; it unwinds to an outer recovery point, skipping the rest of the interrupted function.

```text
Start operation
   |
Publish state
   |
Allocate
   |
Bailout  --->  recovery point
   |
(finish never runs)
```

That is why the ordering in section 4.5 matters *if* the allocation can bail out.

### 5.4 Advanced: how the allocator decides

Beginners can skip this subsection. It matters for understanding why two PHP versions behave differently, and it is where precision is easy to lose.

PHP's allocator tracks more than one number:

| Term | Meaning |
|---|---|
| **Soft limit** | `memory_limit` as configured. The ordinary budget. |
| **Hard limit** | A derived ceiling above the soft limit. With `memory_hard_limit_percent` unset (the default), it is 200% of `memory_limit` when the limit is at most 1G, and `memory_limit + 1G` when it is above 1G; the percentage can also be set explicitly. Crossing it is fatal. |
| **Fallible mode** | A per-allocation flag. A fallible allocation *reports* failure to its caller instead of raising. |

These are not three names for the same thing, and "soft" does **not** mean `memory_limit` is optional. It means that on *some* allocator paths the limit is enforced by recording an error and continuing, rather than by raising immediately.

The branch looks roughly like this (excerpt; verify against your revision):

```c
/* Zend/zend_alloc.c, zend_mm_check_limit() — excerpt */
if (!heap->fallible && add_size > heap->hard_limit - heap->real_size) {
    zend_mm_hard_limit_error(...);                    /* noreturn */
}
if (!ZEND_HAS_OOM()) { zend_mm_delayed_error(...); }
return heap->fallible ? FAILURE : SUCCESS;
```

Three qualifications that matter:

1. Delayed handling applies to **particular allocator paths**, not to every PHP allocation. Some paths, and the hard limit, still terminate.
2. `return SUCCESS` here means "the allocation may proceed while an error is pending", not "the error is ignored".
3. Which path you hit depends on the allocation site and the build. This is version-specific behaviour, and the excerpt above should be checked against the exact source revision you are studying.

In 8.4.26 this branch does not exist: crossing the soft limit raises immediately. (The hard-limit computation above was checked against `zend_mm_update_hard_limit()` in the 8.4.27 source: `percent == -1` resolves to 200, except that limits above 1G add a fixed 1G buffer.) That difference is part of why the same request can behave differently on the two builds — which is the subject of Part 2.

---

## Coming up in Part 2

We now have the vocabulary and a working lab. Three ideas from this part do most of the work in the rest of the series:

* a **lifecycle inconsistency** — a request can end with its heap discarded but without the extension cleanup that normally runs first (section 2.3);
* a **counted-but-unfilled slot** — a hash insertion increments `nNumUsed` before the bucket is filled, and teardown trusts the counter (section 4.5);
* a **nonlocal jump** — `zend_bailout()` can leave an interrupted function without finishing it (section 5.3), and whether an allocation can trigger it differs between 8.4.26 and 8.4.27 (section 5.4).

**Part 2 — *Inside PHP2Shell: Analyzing the PHP Source Code and Security Patches*** takes these three ideas to the actual PHP source, compares the vulnerable 8.4.26 and the patched 8.4.27 release, and asks what the patch does and does not establish.

---

## References

- PHP sessions: https://www.php.net/manual/en/book.session.php
- Upload progress: https://www.php.net/manual/en/session.upload-progress.php
- PHP security releases and source: https://www.php.net/
- Original PHP2Shell research by Calif: https://calif.io/php2shell/

*The lab and harness are published for reproducibility and defensive study. Run them only against the isolated environment in `lab/`.*
