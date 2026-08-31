# SPDX-License-Identifier: GPL-2.0
root_require
require_command python3

# --stream-maxbuf bounds the receive/send buffer of a bbdd_sb (src/bbdd-sb.c),
# used both for a control-socket peer's outstanding tx queue and for a BFDDP
# peer's receive buffer. Without it, a peer that never reads its socket (tx
# side) or that keeps feeding bytes towards a message it declares to be huge
# (rx side) can make the daemon grow that buffer without limit.

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1 FD1
with_socket SD1
adf_Bbdd_start -q --stream-maxbuf=256

ctl="${!BBDD_SOCKET}/bbdd.ctl"

test_mon_tx()
{
	# Fake monitor, subscribe to jrpc topic to get a message for each
	# handled JRPC.
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
}

in_defer_scope test_mon_tx

test_bfdd_rx()
{
	monout="${tmpdir}/monout"
	Bbdd_bground monitor > "$monout"
	monitor_pid=$!

	# 60K message consisting of a header and 300 filler bytes.
	adf_Frr_fake_dplane FD1 '\x01\x00\x00\x00\x00\x00\xea\x60'$(:
	     )'123456789 123456789 123456789 123456789 123456789 '$(:
	     )'123456789 123456789 123456789 123456789 123456789 '$(:
	     )'123456789 123456789 123456789 123456789 123456789 '$(:
	     )'123456789 123456789 123456789 123456789 123456789 '$(:
	     )'123456789 123456789 123456789 123456789 123456789 '$(:
	     )'123456789 123456789 123456789 123456789 123456789 '

	sleep 0.2 # Let bbdd read and (attempt to) buffer the oversized message.

	kill_process "$monitor_pid"
	OUT=$(cat "$monout")

	find_match "$OUT" "Buffer overflow.*allowed 256"
	Bbdd_log_test "oversized BFDDP message rejected"

	Bbdd bfdd connected
	check_fail $? "still connected to fake dataplane after an oversized message"
	Bbdd_log_test "bfdd connection killed after an oversized message"

	Bbdd -q echo
	check_err $? "daemon unresponsive after an oversized BFDDP message"
	Bbdd_log_test "daemon survives an oversized BFDDP message"
}

in_defer_scope test_bfdd_rx

test_json_rx()
{
	# A normal JSON-RPC request/response closes the connection after one
	# message. monitor-subscribe keeps the connection open. Use it to get
	# two small, well-formed top-level JSON values parsed back-to-back on
	# one persistent connection -- nowhere near --stream-maxbuf on their own
	# -- and check both get a reply.
	OUT=$(Python3 - "$ctl" <<'PYEOF'
import socket
import sys

sub = (b'{"jsonrpc":"2.0","id":1,"method":"monitor-subscribe",'
       b'"params":{"topics":["session"]}}')
echo = b'{"jsonrpc":"2.0","id":2,"method":"echo","params":{"ts":0}}'

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2)
s.connect(sys.argv[1])

for i, req in enumerate((sub, echo)):
	s.sendall(req)
	try:
		data = s.recv(4096)
	except socket.timeout:
		data = b''
	print(f"round {i + 1}: {len(data)} bytes")
PYEOF
	)

	find_match "$OUT" "round 1: [1-9][0-9]* bytes"
	Bbdd_log_test "1st request on a connection gets reply"

	find_match "$OUT" "round 2: [1-9][0-9]* bytes"
	Bbdd_log_test "2nd request on the same connection gets a reply"

	Bbdd -q echo
	check_err $? "daemon unresponsive after a persistent JSON-RPC connection"
	Bbdd_log_test "daemon survives a persistent JSON-RPC connection"
}

in_defer_scope test_json_rx
