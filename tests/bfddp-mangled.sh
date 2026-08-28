# SPDX-License-Identifier: GPL-2.0
root_require

# Feed bbdd a malformed BFDDP frame over a fake dataplane socket and
# check the daemon stays responsive afterwards.

Bbdd_setup_socket SD1 FD1
with_socket SD1
adf_Bbdd_start -q

ctl="${!BBDD_SOCKET}/bbdd.ctl"
sock="${FD1}/bfdd_dplane.sock"
socat_pid=

# Spin up a socat listener that, on the next connect, writes a BFDDP
# message header with version=1, zero=0, type=ECHO_REQUEST (0), id=0,
# length=0 to the peer.
fake_dplane()
{
	local pl=$1; shift
	local n=0

	rm -f "$sock"
	echo -ne "$pl" |
		socat -T 1 UNIX-LISTEN:"$sock" - > /dev/null 2>&1 &
	socat_pid=$!

	while [[ ! -S "$sock" ]]; do
		sleep 0.02
		((++n < 100)) || {
			echo "socat failed to bind $sock"
			return 1
		}
	done
}

reap_fake_dplane()
{
	wait "$socat_pid" 2>/dev/null
}

adf_setup_fake_dplane()
{
	local pl=$1; shift

	fake_dplane "$pl"
	defer reap_fake_dplane

	Bbdd_bfdd_connect FD1
	check_err $? "Failed to connect to fake dataplane"

	# Give bbdd a moment to read and (if the bug is present) choke on the
	# length=0 message.
	sleep 0.2
}

test_length_0()
{
	adf_setup_fake_dplane '\x01\x00\x00\x00\x00\x00\x00\x00'

	# The control socket is served by the same poll loop as the dataplane
	# peer, so if the peer's parser is stuck spinning, this query never gets
	# a reply. So if the bug is back, the daemon is stuck looping. We can't
	# sigterm it, because signals are handled by poll, where the daemon
	# never returns if it's stuck looping on zero-length message. We can
	# sigkill it, but then it's not going to clean up after itself and needs
	# admin intervention anyway. So don't bother trying to be graceful here,
	# the test is just a canary that the issue doesn't come back. If it
	# does, there'll be mess one way or another.

	timeout -k 1 2 "${bin_dir}/bbdd" --socket "$ctl" -q echo
	check_err $? "daemon unresponsive after BFDDP message with length=0"
	Bbdd_log_test "daemon survives BFDDP message with length=0"
}

in_defer_scope test_length_0

test_length_short()
{
	monout="${tmpdir}/monout"
	with_socket SD1 Bbdd_bground monitor > "$monout"
	monitor_pid=$!

	adf_setup_fake_dplane '\x01\x00\x00\x03\x00\x00\x00\x08'

	kill_process "$monitor_pid"
	OUT=$(cat "$monout")

	find_no_match "$OUT" "bfddi:sess-del"
	Bbdd_log_test "no sess-del notification for a too-short DP_DELETE_SESSION"

	find_match "$OUT" "Message type 3 has length 8.*at least"
	Bbdd_log_test "daemon rejects a too-short DP_DELETE_SESSION message"

	with_socket SD1 Bbdd bfdd connected
	check_fail $? "still connected to fake dataplane after a malformed message"
	Bbdd_log_test "bfdd connection torn down after a malformed message"

	with_socket SD1 Bbdd -q echo
	check_err $? "daemon unresponsive after a too-short DP_DELETE_SESSION message"
	Bbdd_log_test "daemon survives a too-short DP_DELETE_SESSION message"
}

in_defer_scope test_length_short
