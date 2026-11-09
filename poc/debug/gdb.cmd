# gdb.cmd -- PHP 8.4.26 mod_php request-lifecycle trace (revised)
#
# REVISION NOTE
#   The first version printed  ps_globals.id->val  at the breakpoint. That
#   dereferences a pointer whose allocation may already be invalid: a readable
#   value is not evidence of a live allocation, and a fault would abort the
#   trace. A successful read therefore proves nothing about object lifetime.
#   This version deliberately never reads through PS(id).
#
# Safe to print:
#   - core_globals.modules_activated     (module globals, not a heap allocation)
#   - ps_globals.session_status          (integer in module globals)
#   - ps_globals.id                      (pointer VALUE only)
#   - ps_globals.http_session_vars.u1.type_info  (field inside module globals)
#
# Unsafe / non-evidentiary -- do not add:
#   ps_globals.id->val, ps_globals.http_session_vars.value.*, any dereference.

set pagination off
set confirm off
set breakpoint pending on
set auto-load safe-path /

break _zend_bailout
commands
silent
printf "BAILOUT modules_activated=%d\n", core_globals.modules_activated
printf "BAILOUT session_status=%d\n", ps_globals.session_status
printf "BAILOUT ps_id=%p\n", ps_globals.id
printf "BAILOUT http_session_vars_type_info=0x%x\n", ps_globals.http_session_vars.u1.type_info
bt 6
continue
end

break php_request_shutdown
commands
silent
printf "SHUTDOWN modules_activated=%d\n", core_globals.modules_activated
printf "SHUTDOWN ps_id=%p\n", ps_globals.id
printf "SHUTDOWN http_session_vars_type_info=0x%x\n", ps_globals.http_session_vars.u1.type_info
continue
end

continue
