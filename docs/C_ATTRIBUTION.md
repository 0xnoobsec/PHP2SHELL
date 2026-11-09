# CVE-2026-109618 — corruption attribution (PHP 8.4.26, debug build)

## Method

* Build: PHP 8.4.26, `-g -O0`, no `ZEND_DEBUG`, apache2handler, prefork, 1 worker, 16M/64M.
* gdb attached to the worker; `handle SIGABRT stop`; 5 × (A → B) against `decode.php`.
* A = chunked multipart, progress field + 600 nested `filename=""` records.
* B = multipart, progress field, no file part.

## Observed

```
cycle 0  A 200 (OOM)  B ConnectionError
cycle 1  A 200 (OOM)  B 200
cycle 2  A 200 (OOM)  B ConnectionError
cycle 3  A 200 (OOM)  B 200
cycle 4  A 200 (OOM)  B ConnectionError
```

gdb stopped on the first SIGABRT with:

```
Program received signal SIGABRT, Aborted.
#0  raise / abort
#3  zend_mm_panic (message="zend_mm_heap corrupted")   Zend/zend_alloc.c:398
#4  zend_mm_get_next_free_slot (bin_num=3, heap=0x...040) Zend/zend_alloc.c:1326
#5  zend_mm_alloc_small (bin_num=3)                     Zend/zend_alloc.c:1410
#6  zend_mm_alloc_heap (size=32)                        Zend/zend_alloc.c:1488
#7  _emalloc (size=32)                                  Zend/zend_alloc.c:2743
#8  zend_string_alloc (len=7)
#9  zend_string_init (str="_SERVER['REQUEST_METHOD']...")
#10 lex_scan                                            Zend/zend_language_scanner.c:12153
#11 zendlex / #12 zendparse / #13 zend_compile
#16 zend_execute_script
#19 php_handler                                        sapi/apache2handler/sapi_apache2.c:717
```

At the stop: `modules_activated=1`, `ps_id=(nil)`.

## Reading

* The panic is in the **allocator's small-bin free list**
  (`zend_mm_get_next_free_slot`), allocating a 32-byte string during
  **lexing/compiling** the next request's script.
* `modules_activated=1` and `ps_id=nil` place this in a **later request**, not
  in the OOM request: the session is not active, the modules are.
* So the corruption is *created* by the OOM request and *detected* by the next
  request's first allocations — consistent with the advisory's "a later request
  ... may use that stale state".
* It is a free-list integrity failure (`zend_mm_heap corrupted`), not a
  detected double free at a session call site.

## What this does not establish

* The **creation site** of the corruption. A backtrace at the panic shows where
  integrity failed, not which earlier write damaged the free list. A watchpoint
  on the affected bin or an ASAN build would be needed for that.
* Any relation to code execution. This is a crash-attribution result.

## Corroboration

The same A→B sequence across five builds:

```
8.4.26  (vulnerable)  5/5 trials corrupted, 9 worker aborts
8.4.27  (patched)     0/5
8.2.35  (patched)     0/5
8.3.36  (patched)     0/5
8.5.12  (patched)     0/5
```
