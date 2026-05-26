# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 192.0.2.1/28 \
		NS2 v2 192.0.2.2/28

Bbdd_setup_sockdir SD1 SD2
in_sockdir SD1 in_ns NS1 adf_Bbdd_start
in_sockdir SD2 in_ns NS2 adf_Bbdd_start

in_sockdir SD1 nsessions_test 0
in_sockdir SD2 nsessions_test 0

in_sockdir SD1 Bbdd session add \
	   dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3

in_sockdir SD1 nsessions_test 1

in_sockdir SD1 nsessions_test 1 dst 192.0.2.2
in_sockdir SD1 nsessions_test 1 min-tx 200ms
in_sockdir SD1 nsessions_test 1 min-rx 200ms
in_sockdir SD1 nsessions_test 1 detect-mult 3
in_sockdir SD1 nsessions_test 1 \
	   dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3

in_sockdir SD1 nsessions_test 0 dst 192.0.2.3
in_sockdir SD1 nsessions_test 0 min-tx 300ms
in_sockdir SD1 nsessions_test 0 min-rx 300ms
in_sockdir SD1 nsessions_test 0 detect-mult 4

in_sockdir SD1 nsessions_test 0 \
	   dst 192.0.2.3 min-tx 200ms min-rx 200ms detect-mult 3
in_sockdir SD1 nsessions_test 0 \
	   dst 192.0.2.2 min-tx 300ms min-rx 200ms detect-mult 3
in_sockdir SD1 nsessions_test 0 \
	   dst 192.0.2.2 min-tx 200ms min-rx 300ms detect-mult 3
in_sockdir SD1 nsessions_test 0 \
	   dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 4

# Check that it fails to reach up
in_sockdir SD1 session_state_test up 0

in_sockdir SD2 Bbdd session add \
	   dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3
in_sockdir SD2 nsessions_test 1

# Check that they reach up
in_sockdir SD1 session_state_test up 1
in_sockdir SD2 session_state_test up 1

in_sockdir SD1 echo_test
in_sockdir SD2 echo_test

sleep 2 # Collect traffic.

in_sockdir SD1 Bbdd session del
in_sockdir SD1 nsessions_test 0

# Check that it reaches not-up
in_sockdir SD2 session_state_test not_up 1

in_sockdir SD2 Bbdd session set shutdown

in_sockdir SD2 packet_size_test
in_sockdir SD2 session_stats_consistency_test
in_sockdir SD2 session_diag_stats_consistency_test
in_sockdir SD2 global_diag_stats_consistency_test
