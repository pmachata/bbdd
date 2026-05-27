# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_sockdir SD1 SDb

in_sockdir SDb adf_Bbdd_bridge_start
in_sockdir SD1 adf_Bbdd_start
in_sockdir SD1 Bbdd_bfdd_connect SDb

adf_vrf_prepare
Bbdd_setup_vrf V1 V2
Bbdd_connect_vrf V1 v1 $(Bbdd_IP_mask 1) \
		 V2 v2 $(Bbdd_IP_mask 2)

in_sockdir SDb Bbdd session add discr 101 vrf V1 dst $(Bbdd_IP 2) \
				min-tx 200ms min-rx 200ms detect-mult 3

in_sockdir SD1 nsessions_test 1 vrf V1

in_sockdir SDb Bbdd session add discr 202 vrf V2 dst $(Bbdd_IP 1) \
				min-tx 200ms min-rx 200ms detect-mult 3

in_sockdir SD1 nsessions_test 1 vrf V2

in_sockdir SD1 session_state_test up 1 vrf V1
in_sockdir SD1 session_state_test up 1 vrf V2

in_sockdir SDb Bbdd -q session bulk del
check_fail $? "bulk del against a bridge succeeded"
Bbdd_log_test "bulk del fails against a bridge"

in_sockdir SDb Bbdd session discr 101 del
in_sockdir SDb Bbdd session discr 202 del

sleep 1
in_sockdir SD1 nsessions_test 0

in_sockdir SDb Bbdd session add discr 101 vrf V1 dst $(Bbdd_IP 2) \
				min-tx 200ms min-rx 200ms detect-mult 3 multihop

in_sockdir SDb Bbdd session add discr 202 vrf V2 dst $(Bbdd_IP 1) \
				min-tx 200ms min-rx 200ms detect-mult 3

in_sockdir SD1 session_state_test up 0 vrf V1
in_sockdir SD1 session_state_test up 0 vrf V2

in_sockdir SDb Bbdd session add discr 202 vrf V2 dst $(Bbdd_IP 1) \
				min-tx 200ms min-rx 200ms detect-mult 3 multihop

in_sockdir SD1 session_state_test up 1 vrf V1
in_sockdir SD1 session_state_test up 1 vrf V2
