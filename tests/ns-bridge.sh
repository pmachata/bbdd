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
in_sockdir SDb Bbdd session add \
	   discr 2 dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3

in_sockdir SD1 nsessions_test 1
in_sockdir SD2 nsessions_test 1
in_sockdir SD1 session_state_test up 1
in_sockdir SD2 session_state_test up 1

sleep 2 # Collect traffic.

in_sockdir SDb packet_size_test discr 2

in_sockdir SDb Bbdd session discr 2 del
in_sockdir SD2 nsessions_test 0

in_sockdir SDb Bbdd -v echo
