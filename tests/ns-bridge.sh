# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 $(Bbdd_IP_mask 1) \
		NS2 v2 $(Bbdd_IP_mask 2)

Bbdd_setup_sockdir SD1 SD2 SDb
in_sockdir SD1 in_ns NS1 adf_Bbdd_start
in_sockdir SD2 in_ns NS2 adf_Bbdd_start

defer_scope_push

# This has to run in the same namespace as the daemon it forwards to, so that
# netif name translation works.
in_sockdir SDb in_ns NS2 adf_Bbdd_bridge_start

in_sockdir SD2 Bbdd_bfdd_connect SDb
in_sockdir SD2 bfdd_echo_test
in_sockdir SDb bfdd_echo_test

in_sockdir SD1 Bbdd session add \
	   dst $(Bbdd_IP 2) min-tx 200ms min-rx 200ms detect-mult 3 \
	   passive
in_sockdir SD1 nsessions_test 1

in_sockdir SDb Bbdd session add \
	   dst $(Bbdd_IP 1) min-tx 200ms min-rx 200ms detect-mult 3 \
	   discr 2 passive
in_sockdir SD2 nsessions_test 1

in_sockdir SD1 session_state_test up 0
in_sockdir SD2 session_state_test up 0

in_sockdir SDb Bbdd session discr 2 del
in_sockdir SD2 nsessions_test 0

in_sockdir SDb Bbdd session add \
	   dst $(Bbdd_IP 1) min-tx 200ms min-rx 200ms detect-mult 3 \
	   discr 2 hold-time 5s

in_sockdir SD1 hold_time_test 5
in_sockdir SD2 session_state_test up 1

cpi_test()
{
	in_sockdir SD1 session_value_check '.data.cpi' false
	in_sockdir SD1 session_value_check '.state.remote.cpi' false
	in_sockdir SD2 session_value_check '.data.cpi' false
	in_sockdir SD2 session_value_check '.state.remote.cpi' false

	# This also tests session parameter change via bridge, and exercises
	# code for setting src address across the bridge.
	in_sockdir SDb Bbdd session add dst $(Bbdd_IP 1) \
		   min-tx 200ms min-rx 200ms detect-mult 3 \
		   src $(Bbdd_IP 2) netif v2 discr 2 cpi
	sleep 1

	in_sockdir SD1 session_value_check '.data.cpi' false
	in_sockdir SD1 session_value_check '.state.remote.cpi' true
	in_sockdir SD2 session_value_check '.data.cpi' true
	in_sockdir SD2 session_value_check '.state.remote.cpi' false

	Bbdd_log_test "CPI propagates"
}

cpi_test

sleep 1 # Collect some more traffic -- the CPI test already slept 1s

in_sockdir SDb packet_size_test discr 2

defer_scope_pop # Kill the bridge


# Race test: more than one bfdd-echo in flight at a time.
#
# Restart the bridge with --debug bfdd-delay=1s so that an ECHO_REPLY only
# arrives 1s after the ECHO_REQUEST. Fire 10 concurrent `bbdd bfdd echo'
# requests at the daemon. The first one prompts the daemon to send an
# ECHO_REQUEST; the rest must piggy-back on that single in-flight echo.
# Kill every other client mid-flight and verify the survivors still get
# a reply at ~1s.
bfdd_echo_race_test()
{
	local n=10
	local -a pids=()
	local -a survivors=()
	local i

	slowwait 5 not in_sockdir SDb Bbdd -q echo

	in_sockdir SDb in_ns NS2 \
		Bbdd_bground --debug=bfdd-delay=1s \
			     bfdd bridge start \
			     unix:${SDb}/bfdd_dplane.sock
	defer in_sockdir SDb Bbdd_stop $!
	in_sockdir SDb Bbdd_wait

	in_sockdir SD2 Bbdd_bfdd_connect SDb

	for ((i = 0; i < n; i++)); do
		in_sockdir SD2 Bbdd --json bfdd echo \
			> "$tmpdir/race.$i.out" &
		pids+=($!)
	done

	# Let all of them register with the daemon before the reply arrives.
	sleep 0.2

	for ((i = 0; i < ${#pids[@]}; i++)); do
		if ((i % 2 == 1)); then
			kill_process "${pids[i]}"
		else
			survivors+=($i)
		fi
	done

	for i in "${survivors[@]}"; do
		wait "${pids[i]}"
		check_err $? "bbdd bfdd echo #$i exit code"

		local reported_lat
		reported_lat=$(jq '.reply_ts - .ts' "$tmpdir/race.$i.out")
		((reported_lat > 800000))
		check_err $? "echo #$i latency $reported_lat us suspiciously low (expected ~1s)"
		((reported_lat < 1500000))
		check_err $? "echo #$i latency $reported_lat us suspiciously high (expected ~1s)"
	done

	Bbdd_log_test "bfdd echo race: ${#survivors[@]}/${#pids[@]} echos saw ~1s latency"
}

in_defer_scope bfdd_echo_race_test
