# Inside PHP2Shell: Analyzing the PHP Source Code and Security Patches

*Part 2 of a three-part laboratory study of PHP's request lifecycle, sessions, out-of-memory handling, and CVE-2026-109618 / CVE-2026-109619.*

> **PHP2Shell series**
> 1. Foundations: PHP Internals, Sessions, and Memory Management
> 2. **Source-Code Analysis: Analyzing the PHP Source Code and Security Patches** — *you are here*
> 3. Original Research: Reproducing Memory Corruption and Analyzing the Results
>
> *Audience for this part: security researchers and developers. Part 1 covered the lifecycle, sessions, hash tables, and OOM handling that this part builds on; the key excerpts are repeated below so this part stands on its own.*

## Recap: what we are looking for

Part 1 left three ideas on the table, and this part takes them to the PHP source and the patch that changed them:

* a **lifecycle inconsistency** — a request can end with its request heap discarded but without the extension cleanup that normally runs first;
* a **counted-but-unfilled slot** — a hash insertion increments `nNumUsed` before the bucket is filled, and teardown trusts the counter;
* a **nonlocal jump** — `zend_bailout()` can leave an interrupted function without finishing it.

The question for this part is narrow and answerable from source: **what is different between PHP 8.4.26 (the vulnerable research build) and PHP 8.4.27 (the patched release), and what does that difference establish?**

I will keep one distinction in front of me throughout. Reading a diff tells you what the maintainers *changed* and, from the comments and shape, what they *intended*. It does not tell you which changed line stopped a particular crash in a particular lab. That second question is an experiment, and it belongs to Part 3.

---

## 6. Source review and patch comparison

### 6.1 The code before the patch

Four short excerpts from PHP 8.4.26 set up everything that follows. They were introduced one at a time in Part 1; here they are together, as the pre-patch baseline.

**The lifecycle flag, and the shutdown that depends on it.** PHP marks extension initialization complete only after it runs, and only runs extension shutdown when that flag is set:

```c
/* main/main.c, php_request_startup() — excerpt */
php_hash_environment();      /* parses POST, multipart, uploads  */
zend_activate_modules();     /* RINIT for every extension        */
PG(modules_activated) = 1;

/* main/main.c, php_request_shutdown() — excerpt */
if (PG(modules_activated)) {
    zend_deactivate_modules();
}
```

If a fatal error occurs during request parsing — before `zend_activate_modules()` — extension shutdown is skipped for that request.

**A session string allocated during parsing.** The upload-progress callback can initialize session state *before the application script runs*, on the request heap:

```c
/* ext/session/session.c, MULTIPART_EVENT_FILE_START — excerpt */
if (Z_ISUNDEF(progress->data)) {
    ...
    php_rinit_session(0);
    PS(id) = zend_string_init(Z_STRVAL(progress->sid), Z_STRLEN(progress->sid), 0);
    ...
}
```

This runs inside `php_hash_environment()`, before the flag above is set. The cleanup that would release `PS(id)` lives in `php_rshutdown_session_globals()` — an extension shutdown handler, on the gated path.

**A hash insertion that counts before it fills, and a teardown that trusts the count:**

```c
/* Zend/zend_hash.c — insertion, abbreviated */
add_to_hash:
    idx = ht->nNumUsed++;                            /* count first */
    ht->nNumOfElements++;
    p = ht->arData + idx;
    p->key = key = zend_string_init(str, len, ...);  /* can fail */
    ...
    p->h = ZSTR_H(key) = h;
    ZVAL_COPY_VALUE(&p->val, pData);

/* Zend/zend_hash.c, zend_array_destroy() — teardown */
for (p = ht->arData; p != ht->arData + ht->nNumUsed; p++) {
    i_zval_ptr_dtor(&p->val);
    if (p->key) { zend_string_release(p->key); }
}
```

**The allocator's limit check.** In 8.4.26, crossing the soft limit raises immediately; the fallible / delayed-OOM branch shown in Part 1 (section 5.4) does not exist in this build.

Put together, these describe a conditional hazard: a hash insertion interrupted by a bailout between the counter increment and the bucket fill would leave a counted-but-unfilled slot, and a request that fails during early parsing would skip the session cleanup that owns `PS(id)`. Whether either actually produces an exploitable inconsistency is what the patch — and Part 3 — speak to.

### 6.2 What I compared

I compared the two release tags directly:

```bash
git clone --filter=blob:none https://github.com/php/php-src.git
cd php-src
git fetch --depth 1 origin tag php-8.4.26 tag php-8.4.27
git rev-parse php-8.4.26^{} php-8.4.27^{}   # peeled commit hashes
git diff --stat php-8.4.26 php-8.4.27 -- Zend ext main
```

At the time of writing this resolves to:

```text
php-8.4.26  tag object e857632a369b1c390720d4358fe029afe7af4408
            commit     c31ae58ecbedc7a85dac0eee5a6a88da73543e70
php-8.4.27  tag object aa58018e5a2d69f3c497aa22a085fc897b5c3df8
            commit     00d8bae801541db0d95a698e108bb4b1b273fe6e
```

Record these when you do this. Release tags can be moved or re-cut in principle, and a report that says "8.4.26 vs 8.4.27" without hashes is harder to audit than one that pins both ends.

The diff touches a small set of files, including:

```text
Zend/zend_alloc.c
Zend/zend_hash.c
ext/session/session.c
main/main.c
```

Line counts depend on how you diff and what you include, so I have left them out of this article. Run the command and see for yourself.

### 6.3 Fallible operations

The hash-table code gains a fallible mode: a flag, a sentinel return value, and functions whose callers can check for failure.

```c
/* shape of the change, simplified */
if (!create_record()) {
    return ERROR;
}
```

The patch introduces fallible operations so callers can handle allocation failures explicitly, reducing the risk of leaving internal data structures partially updated. In source terms, that is the kind of change that would prevent an insertion from having to jump out between the counter increment and the bucket fill — a plausible reading of the diff, not something this series establishes experimentally.

### 6.4 Delayed OOM

The allocator gains the branch shown in Part 1 (section 5.4) — the fallible / delayed-error path that is absent from 8.4.26.

The important consequence for this series: an allocation that crosses the soft limit on a non-fallible path can *complete*, which means a bucket interrupted as in section 6.1 might get its key and value after all.

I say "might" deliberately. Connecting "this branch exists" to "the crash stopped" is source-supported reasoning, not an experiment. Part 3 explains what the experiment actually shows.

### 6.5 Session safeguards during multipart parsing

The session extension gains a flag, `PS(in_rfc1867_update)`, and routes its serializers through helpers that enable "incomplete classes only" while the upload-progress callback runs.

```c
/* ext/session/session.c (8.4.27) — shape of the change */
if (PS(in_rfc1867_update)) {
    php_var_unserialize_set_incomplete_classes_only(*var_hash, true);
}
...
if (PS(in_rfc1867_update)) {
    php_var_serialize_set_incomplete_classes_only(*var_hash, true);
}
```

The intent is clear from the source comments: during that early window the unserializer should not instantiate application classes, because no userland code may run yet. Objects found in session data are kept as `__PHP_Incomplete_Class`.

A caution on wording: it is tempting to say the data is "written back unchanged". I have not verified byte-identical re-serialisation, and incomplete-class handling alone would not guarantee it. The supportable statement is narrower: during the rfc1867 update, the serializer is instructed not to instantiate application classes.

### 6.6 What the patch does — and does not — establish

These three mechanisms — fallible hash operations, delayed OOM, and the rfc1867 session safeguard — explain the *design* of the fix.

They do not tell us which one prevented the crash in my lab. The differential I report in Part 3 is real; the causal line from "this line changed" to "the crash stopped" remains a hypothesis supported by reading, not by measurement.

That distinction is worth keeping straight. A changelog can make you feel you have explained a crash when you have only explained a patch.

Which brings us to the question reading cannot answer. The patch gives us three plausible defenses. The vulnerable build is one tag behind. Does the difference actually appear when you run them, and can it be attributed to anything specific?

---

## Coming up in Part 3

**Part 3 — *Investigating PHP2Shell: Reproducing Memory Corruption and Analyzing the Results*** runs the experiment this part set up: a five-build test matrix, twenty trials each, a GDB backtrace of the crash, and the two application-level chains that a PHP upgrade does not fix. It also spends as much time on what the results *do not* establish — the creation site, the causal request, code execution — as on what they do.

---

## References

- PHP source repository: https://github.com/php/php-src
- PHP security releases: https://www.php.net/
- Original PHP2Shell research by Calif: https://calif.io/php2shell/

*Code excerpts are abbreviated and should be checked against the exact tag you are studying; the commit hashes above let you pin both ends.*
