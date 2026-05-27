# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_sockdir SD1
in_sockdir SD1
adf_Bbdd_start

adf_vrf_prepare
Bbdd_setup_vrf V1 V2
Bbdd_connect_vrf V1 v1 $(Bbdd_IP_mask 1) \
		 V2 v2 $(Bbdd_IP_mask 2)

Bbdd session add vrf V1 src $(Bbdd_IP 1) dst $(Bbdd_IP 2) \
		 min-tx 200ms min-rx 200ms detect-mult 3

Bbdd session add vrf V2 src $(Bbdd_IP 2) dst $(Bbdd_IP 1) \
		 min-tx 200ms min-rx 200ms detect-mult 3 hold-time 5s
hold_time_test 5 vrf V1

session_state_test up 1 vrf V1
session_state_test up 1 vrf V2
