# SPDX-License-Identifier: GPL-2.0
root_require
require_command python3

# Set up a daemon with a small per-client send buffer. Connect to the daemon a
# fake monitor which never consumes the socket data, prompting overflow of the
# socket buffer. This forces the daemon to unsubscribe the fake monitor client.
# Verify that the mechanism works as intended and does not crash.

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1
adf_Bbdd_start -q --stream-maxbuf=256

ctl="${!BBDD_SOCKET}/bbdd.ctl"

# Fake monitor, subscribe to jrpc topic to get a message for each handled JRPC.

Python3 - "$ctl" <<'PYEOF' &
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

# Flood JRPC messages to fill the monitor buffer.
for i in $(seq 1 30); do
	Bbdd -q echo > /dev/null
done

wait "$client_pid" # Let the client's connection close.

Bbdd -q echo
check_err $? "daemon unresponsive after monitor client exceeded its tx-queue cap"
Bbdd_log_test "monitor client exceeding stream-maxbuf"
