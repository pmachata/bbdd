# SPDX-License-Identifier: GPL-2.0
root_require
require_command python3

# bbdd_mon_subscribe_sock() (src/bbdd-mon.c) registers a monitor
# subscription on a control-socket peer via bbdd_ssk_peer_add_cbs(), but
# bbdd_mon_unsubscribe_sock() used not to withdraw it. When a monitor
# push failed (__bbdd_mon_send() -> bbdd_util_jrpc_send_keep()), the
# monitor client got freed without that callback being removed. Later,
# when the underlying connection actually closed, bbdd_ssk_peer_destroy()
# invoked the stale callback -- bbdd_mon_ssk_cli_done() -- on the
# already-freed client, unsubscribing (and freeing) it a second time: a
# double free.
#
# Reproducing a genuine send failure needed a real trigger:
# bbdd_util_jrpc_send_keep() only enqueues into a peer's tx buffer
# (peer->tx_sb), which used to grow without any limit -- a slow or
# malicious peer could make the daemon queue arbitrary amounts of
# unsent data in memory. --peer-tx-cap=<N> bounds that queue (16 MiB by
# default; set very low here), and doubles as a deterministic way to
# trigger a real send failure: attach a monitor subscriber that never
# reads its socket, flood cheap traffic to generate monitor
# notifications, and once the queued-but-unsent bytes exceed the (tiny,
# test-configured) cap, the enqueue genuinely fails.

Bbdd_setup_socket SD1
with_socket SD1
with_valgrind_d
adf_Bbdd_start --peer-tx-cap=256

ctl="${!BBDD_SOCKET}/bbdd.ctl"

python3 - "$ctl" <<'PYEOF' &
import socket
import sys
import time

req = (b'{"jsonrpc":"2.0","id":1,"method":"monitor-subscribe",'
       b'"params":{"topics":["jrpc"]}}')

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(req)
# Deliberately never read: let whatever bbdd queues for us pile up
# in its tx buffer instead of ours.
time.sleep(5)
PYEOF
client_pid=$!

sleep 0.2 # Let the subscribe request land.

# Flood cheap control-socket traffic: each request/response round trip
# fires "debug" topic notifications ("fd %d: received/sent %zd bytes")
# that get pushed to every debug-subscribed client, including our
# stalled one.
for i in $(seq 1 30); do
	Bbdd -q echo > /dev/null
done

wait "$client_pid" # Let the client's connection close.

Bbdd -q echo
check_err $? "daemon unresponsive after monitor client exceeded its tx-queue cap"
Bbdd_log_test "daemon survives a monitor client exceeding its tx-queue cap"
