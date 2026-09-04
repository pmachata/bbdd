# SPDX-License-Identifier: GPL-2.0
root_require
require_command python3

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1
adf_Bbdd_start -q

ctl="${!BBDD_SOCKET}/bbdd.ctl"

send_and_vanish()
{
	# A control-socket client that sends a request and then vanishes before
	# reading the reply.

	Python3 - "$ctl" <<-'PYEOF'
		import socket
		import sys

		req = b'{"jsonrpc":"2.0","id":1,"method":"echo","params":{"ts":0}}'

		s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		s.connect(sys.argv[1])
		s.sendall(req)
		s.close()
	PYEOF
}

test_vanish()
{
	local i

	# A single shot could in principle race the daemon's own scheduling;
	# repeat a few times so the test isn't sensitive to that.
	for i in $(seq 1 10); do
		send_and_vanish
	done

	with_socket SD1 Bbdd -q echo
	check_err $? "daemon unresponsive after send failures to vanished clients"
	Bbdd_log_test "client vanishes right after their request"
}

in_defer_scope test_vanish

test_shut_wr()
{
	Python3 - "$ctl" <<-'EOF'
		import socket
		import sys
		import select

		s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		s.connect(sys.argv[1])
		s.setblocking(0)
		s.sendall(b'{"jsonrpc":"2.0","id":1,')
		s.shutdown(socket.SHUT_WR)
		ready = select.select([s], [], [], 2)
		if ready[0]:
		    sys.exit(0)
		else:
		    sys.exit(1)
	EOF
	check_err $? "mock client timed out"
	Bbdd_log_test "socket.shutdown(SHUT_WR)"
}

in_defer_scope test_shut_wr

test_fail_flush()
{
	local pid
	local out

	Python3 - "$ctl" <<-'PYEOF' &
		import socket
		import sys
		import time

		id = b'a' * 300_000
		req = b'{"jsonrpc":"2.0","id":"' + id + \
		      b'","method":"monitor-subscribe", ' + \
		      b'"params":{"topics":["error"]}}x'

		s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		s.connect(sys.argv[1])
		s.sendall(req)
		time.sleep(3)
	PYEOF

	pid=$!

	sleep 1

	out=$(with_socket SD1 Bbdd --json echo | jq -e '.reply_ts - .ts')
	((out < 100000)) # 0.1s
	check_err $? "fail_flush: daemon unresponsive"
	wait "$pid"

	Bbdd_log_test "client forces flush and never reads"
}

in_defer_scope test_fail_flush
