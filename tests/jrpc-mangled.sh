# SPDX-License-Identifier: GPL-2.0
root_require

# Feed the daemon malformed JRPC requests over a raw socket and assert
# that it bounces them with the expected JRPC errors (or, for byte-level
# garbage, cleanly closes the peer) and stays alive afterwards.
#
# The Bbdd client serializes through json-c and physically cannot send
# malformed payloads, so this test reaches the daemon via socat.

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1
adf_Bbdd_start

ctl="${!BBDD_SOCKET}/bbdd.ctl"

# Send a raw payload to the daemon's control socket and print the
# response on stdout. The half-close after the write nudges the daemon
# to flush its response promptly; the -t timeout caps how long socat
# waits for that response.
send_raw()
{
	local payload=$1; shift

	printf '%s' "$payload" |
		socat -t 0.5 - UNIX-CONNECT:"$ctl"
}

# JRPC error codes, see RFC.
err_inv_request=-32600
err_method_nf=-32601
err_inv_params=-32602

expect_error()
{
	local what=$1; shift
	local expected_code=$1; shift
	local out=$1; shift
	local code

	code=$(echo "$out" | jq -r '.error.code // "missing"' 2>/dev/null)
	[[ "$code" == "$expected_code" ]]
	check_err $? "$what: got error code $code, expected $expected_code"
}

expect_error_msg()
{
	local what=$1; shift
	local expected_code=$1; shift
	local out=$1; shift
	local data

	expect_error "$what" "$expected_code" "$out"

	data=$(echo "$out" | jq -r '.error.data // "missing"' 2>/dev/null)
	[[ "$data" =~ "$what" ]]
	check_err $? "got data '$data', expected to see '$what'"
}

# JSON top-level null: dissected request is missing entirely.
out=$(send_raw 'null ')
expect_error "null request" "$err_inv_request" "$out"
Bbdd_log_test "null request bounced as Invalid Request"

# JSON-valid but not a request object (an array).
out=$(send_raw '["not","a","request"]')
expect_error "array as request" "$err_inv_request" "$out"
Bbdd_log_test "array request bounced as Invalid Request"

# Object missing the required `method' field.
out=$(send_raw '{"jsonrpc":"2.0","id":2}')
expect_error "missing method" "$err_inv_request" "$out"
Bbdd_log_test "missing method bounced as Invalid Request"

# Object with an unknown method.
out=$(send_raw '{"jsonrpc":"2.0","id":3,"method":"no-such-method"}')
expect_error "unknown method" "$err_method_nf" "$out"
Bbdd_log_test "unknown method bounced as Method Not Found"

# Byte-level garbage (unclosed object). The tokener can never
# complete; the daemon detects the parse error and tears the peer down
# silently. No JRPC response is sent; we just check that the daemon
# survives.
send_raw '{"jsonrpc":"2.0","id":4,"method":"echo"' > /dev/null
Bbdd_log_test "byte-level garbage did not crash daemon"

# Truncated request: send half a payload, then hang up. The daemon
# should clean up the per-peer state on EOF.
printf '%s' '{"jsonrpc":"2.0","id":5' |
	socat -t 0.2 - UNIX-CONNECT:"$ctl" > /dev/null
Bbdd_log_test "truncated request did not crash daemon"

# Invalid session-add/-del/-set invocation.
out=$(send_raw '{"jsonrpc":"2.0","id":3,"method":"session-add","params":{}}')
expect_error_msg "Required member change" "$err_inv_params" "$out"
Bbdd_log_test "missing session-add 'changed': Invalid Params"

out=$(send_raw '{"jsonrpc":"2.0","id":3,"method":"session-add","params":{"select":{},"change":{}}}')
expect_error_msg "The member select" "$err_inv_params" "$out"
Bbdd_log_test "superfluous session-add 'select': Invalid Params"

out=$(send_raw '{"jsonrpc":"2.0","id":3,"method":"session-del","params":{}}')
expect_error_msg "Required member select" "$err_inv_params" "$out"
Bbdd_log_test "missing session-del 'select': Invalid Params"

out=$(send_raw '{"jsonrpc":"2.0","id":3,"method":"session-del","params":{"select":{},"change":{}}}')
expect_error_msg "The member change" "$err_inv_params" "$out"
Bbdd_log_test "superfluous session-del 'change': Invalid Params"

out=$(send_raw '{"jsonrpc":"2.0","id":3,"method":"session-set","params":{}}')
expect_error_msg "Required member" "$err_inv_params" "$out"
Bbdd_log_test "missing session-set 'change'&'select': Invalid Params"

out=$(send_raw '{"jsonrpc":"2.0","id":3,"method":"session-set","params":{"select":{}}}')
expect_error_msg "Required member change" "$err_inv_params" "$out"
Bbdd_log_test "missing session-set 'change': Invalid Params"

out=$(send_raw '{"jsonrpc":"2.0","id":3,"method":"session-set","params":{"change":{}}}')
expect_error_msg "Required member select" "$err_inv_params" "$out"
Bbdd_log_test "missing session-set 'select': Invalid Params"

# Final sanity check: the daemon is still responsive.
Bbdd -q echo
check_err $? "daemon unresponsive after malformed inputs"
Bbdd_log_test "daemon still serving requests"
