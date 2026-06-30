# SPDX-License-Identifier: GPL-2.0

# Reach the *monitor* through a fake server: socat binds the control
# socket and feeds back a canned handshake response followed by a
# crafted notification stream. The monitor is expected to be tolerant
# of garbage in the stream (log it and keep reading), but to fail the
# handshake itself when the daemon's response is broken.

Bbdd_setup_socket SD1
with_socket SD1

ctl="${!BBDD_SOCKET}/bbdd.ctl"
out_file=${tmpdir}/monout
err_file=${tmpdir}/monerr
socat_pid=

# Successful response to the `monitor-subscribe' request the monitor
# sends as its first message. id=1 matches the client's request id.
ack='{"jsonrpc":"2.0","id":1,"result":null}'

# A valid notification carrying a `debug' message. With ts/inner-params
# in place, the monitor prints "debug               : <msg>".
nA='{"jsonrpc":"2.0","method":"debug","params":{"ts":1,"params":{"msg":"AAA"}}}'
nB='{"jsonrpc":"2.0","method":"debug","params":{"ts":2,"params":{"msg":"BBB"}}}'

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

run_monitor()
{
	Bbdd monitor > "$out_file" 2> "$err_file"
}

# Handshake itself fails: daemon replies with a JRPC error object.
# The monitor should not enter the streaming phase; it should exit
# non-zero. Stdout should be empty.
fake_reply '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nope"}}'
run_monitor
check_fail $? "monitor accepted error handshake"
find_no_match "$(cat "$out_file")" "."
Bbdd_log_test "monitor rejected handshake error response"
reap_fake_reply

# Byte-level garbage between two valid notifications. The monitor
# must log the parse error, resync past it, and process the second
# notification.
fake_reply "${ack}${nA}%${nB}"
run_monitor
check_err $? "monitor failed despite tolerant stream"
find_match "$(cat "$out_file")" "debug.*AAA"
find_match "$(cat "$out_file")" "debug.*BBB"
find_match "$(cat "$err_file")" "monitor stream"
Bbdd_log_test "monitor resynced past byte-level garbage"
reap_fake_reply

# A well-formed object that is not a valid notification (an array)
# between two good notifications. The tokenizer parses it fine; the
# dispatcher rejects it, logs, and moves on.
fake_reply "${ack}${nA}[\"not\",\"a\",\"notif\"]${nB}"
run_monitor
check_err $? "monitor failed on bogus notification shape"
find_match "$(cat "$out_file")" "debug.*AAA"
find_match "$(cat "$out_file")" "debug.*BBB"
find_match "$(cat "$err_file")" "monitor event"
Bbdd_log_test "monitor logged bogus notification and continued"

reap_fake_reply

# Truncated trailing object after a good notification. The
# tokenizer stays in `continue' state until EOF; nothing is logged
# beyond the first notification, the monitor exits cleanly.
fake_reply "${ack}${nA}{\"jsonrpc\":\"2.0\",\"method\":\"deb"
run_monitor
check_err $? "monitor failed on truncated tail"
find_match "$(cat "$out_file")" "debug.*AAA"
find_no_match "$(cat "$out_file")" "BBB"
find_no_match "$(cat "$err_file")" "monitor"
Bbdd_log_test "monitor tolerated truncated tail"
reap_fake_reply
