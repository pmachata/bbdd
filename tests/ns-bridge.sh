# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 192.0.2.1/28 \
		NS2 v2 192.0.2.2/28

Bbdd_setup_sockdir SD1 SD2 SDb
in_sockdir SD1 in_ns NS1 adf_Bbdd_start
in_sockdir SD2 in_ns NS2 adf_Bbdd_start
in_sockdir SDb adf_Bbdd_bridge_start

in_sockdir SD2 Bbdd_bfdd_connect SDb

in_sockdir SD1 Bbdd session add \
	   dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3
in_sockdir SD1 nsessions_test 1

in_sockdir SDb Bbdd session add \
	   dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3 \
	   discr 2 hold-time 5s
in_sockdir SD1 hold_time_test 5

in_sockdir SD2 nsessions_test 1
in_sockdir SD2 session_state_test up 1

cpi_test()
{
	in_sockdir SD1 session_value_check '.data.cpi' false
	in_sockdir SD1 session_value_check '.state.remote.cpi' false
	in_sockdir SD2 session_value_check '.data.cpi' false
	in_sockdir SD2 session_value_check '.state.remote.cpi' false

	# This also tests session parameter change via bridge.
	in_sockdir SDb Bbdd session add \
		   dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3 \
		   discr 2 cpi
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

in_sockdir SDb Bbdd session discr 2 del
in_sockdir SD2 nsessions_test 0

in_sockdir SDb echo_test
