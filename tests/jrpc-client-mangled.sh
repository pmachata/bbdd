# SPDX-License-Identifier: GPL-2.0

# Reach the *client* through a fake server: socat binds the control
# socket and feeds back canned replies. The real daemon is not started
# in this test; we only want to confirm the client handles malformed
# responses cleanly (non-zero exit, no crash).

Bbdd_setup_socket SD1
with_socket SD1

ctl="${!BBDD_SOCKET}/bbdd.ctl"
socat_pid=

# Spin up a socat listener that, on the next connect, writes the given
# payload and shuts down. The client's request is discarded.
fake_reply()
{
	local payload=$1; shift
	local n=0

	rm -f "$ctl"
	printf '%s' "$payload" |
		socat -T 1 UNIX-LISTEN:"$ctl" - > /dev/null 2>&1 &
	socat_pid=$!

	# Wait for socat to bind before letting the client connect.
	while [[ ! -S "$ctl" ]]; do
		sleep 0.02
		((++n < 100)) || {
			echo "socat failed to bind $ctl"
			return 1
		}
	done
}

reap_fake_reply()
{
	wait "$socat_pid" 2>/dev/null
}

# Reply is correct.
fake_reply '{"jsonrpc":"2.0","id":1,"result":{"ts":100,"reply_ts":200}}'
Bbdd -q echo
check_err $? "client accepted valid response"
reap_fake_reply
Bbdd_log_test "client accepted valid response"

# Reply is byte-level garbage.
fake_reply '{"jsonrpc":"2.0","id":1,%%garbage%%}'
Bbdd -q echo
check_fail $? "client accepted byte-level garbage"
reap_fake_reply
Bbdd_log_test "client rejected byte-level garbage"

# Reply is JSON `null'. Trailing space terminates the tokener.
fake_reply 'null '
Bbdd -q echo
check_fail $? "client accepted null reply"
reap_fake_reply
Bbdd_log_test "client rejected null reply"

# Reply is JSON-valid but not a JRPC response (an array).
fake_reply '["not","a","response"]'
Bbdd -q echo
check_fail $? "client accepted array reply"
reap_fake_reply
Bbdd_log_test "client rejected non-object reply"

# Reply has both result and error (JRPC spec violation).
fake_reply '{"jsonrpc":"2.0","id":1,"result":1,"error":{"code":1,"message":"hi"}}'
Bbdd -q echo
check_fail $? "client accepted result+error reply"
reap_fake_reply
Bbdd_log_test "client rejected ambiguous reply"

# Reply has neither result nor error.
fake_reply '{"jsonrpc":"2.0","id":1}'
Bbdd -q echo
check_fail $? "client accepted result-less reply"
reap_fake_reply
Bbdd_log_test "client rejected empty reply"

# Reply is missing the `jsonrpc' version field.
fake_reply '{"id":1,"result":"ok"}'
Bbdd -q echo
check_fail $? "client accepted reply without jsonrpc field"
reap_fake_reply
Bbdd_log_test "client rejected reply missing jsonrpc field"

# Sudden hangup: no reply at all.
fake_reply ''
Bbdd -q echo
check_fail $? "client accepted EOF instead of reply"
reap_fake_reply
Bbdd_log_test "client rejected EOF without reply"
