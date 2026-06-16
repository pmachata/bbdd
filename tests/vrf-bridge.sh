# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1 SDb

with_socket SDb adf_Bbdd_bridge_start
with_socket SD1 adf_Bbdd_start
with_socket SD1 Bbdd_bfdd_connect SDb

adf_vrf_prepare
Bbdd_setup_vrf V1 V2
Bbdd_connect_vrf V1 v1 $(Bbdd_IP_mask 1) \
		 V2 v2 $(Bbdd_IP_mask 2)

with_socket SDb Bbdd session add discr 101 vrf V1 dst $(Bbdd_IP 2) \
				min-tx 200ms min-rx 200ms detect-mult 3

with_socket SD1 nsessions_test 1 vrf V1

with_socket SDb Bbdd session add discr 202 vrf V2 dst $(Bbdd_IP 1) \
				min-tx 200ms min-rx 200ms detect-mult 3

with_socket SD1 nsessions_test 1 vrf V2

with_socket SD1 session_state_test up 1 vrf V1
with_socket SD1 session_state_test up 1 vrf V2

with_socket SDb Bbdd -q session bulk del
check_fail $? "bulk del against a bridge succeeded"
Bbdd_log_test "bulk del fails against a bridge"

with_socket SDb Bbdd session discr 101 del
with_socket SDb Bbdd session discr 202 del

sleep 1
with_socket SD1 nsessions_test 0

with_socket SDb Bbdd session add discr 101 vrf V1 dst $(Bbdd_IP 2) \
				min-tx 200ms min-rx 200ms detect-mult 3 multihop

with_socket SDb Bbdd session add discr 202 vrf V2 dst $(Bbdd_IP 1) \
				min-tx 200ms min-rx 200ms detect-mult 3

with_socket SD1 session_state_test up 0 vrf V1
with_socket SD1 session_state_test up 0 vrf V2

with_socket SDb Bbdd session add discr 202 vrf V2 dst $(Bbdd_IP 1) \
				min-tx 200ms min-rx 200ms detect-mult 3 multihop

with_socket SD1 session_state_test up 1 vrf V1
with_socket SD1 session_state_test up 1 vrf V2
