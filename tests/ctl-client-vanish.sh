# SPDX-License-Identifier: GPL-2.0
root_require
require_command python3

# A control-socket client that sends a request and then vanishes before
# reading the reply: bbdd_ssk_peer_nq() only buffers the response, the
# actual send() happens on the daemon's *next* poll() iteration, and by
# then the client is long gone. That makes POLLHUP show up alongside
# POLLOUT, and bbdd_ssk_peer_event() checks POLLHUP first, routing
# straight to bbdd_ssk_peer_destroy() instead of ever reaching the
# POLLOUT branch. bbdd_ssk_peer_destroy() then does its own best-effort
# flush with the error pointer set to NULL, so the resulting send()
# failure is deliberately silent -- there is nothing to observe beyond
# the daemon not crashing.
#
# No debug hook needed: a raw client that connects, sends a well-formed
# request and closes immediately reproduces the same race (if anything
# more reliably, since there's no event loop indirection on the
# client's side to add latency before the close()).

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1
adf_Bbdd_start

ctl="${!BBDD_SOCKET}/bbdd.ctl"

send_and_vanish()
{
	Python3 - "$ctl" <<'PYEOF'
import socket
import sys

req = b'{"jsonrpc":"2.0","id":1,"method":"echo","params":{"ts":0}}'

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(req)
s.close()
PYEOF
}

# A single shot could in principle race the daemon's own scheduling;
# repeat a few times so the test isn't sensitive to that.
for i in $(seq 1 10); do
	send_and_vanish
done

with_socket SD1 Bbdd -q echo
check_err $? "daemon unresponsive after send failures to vanished clients"
Bbdd_log_test "daemon survives clients vanishing right after their request"
