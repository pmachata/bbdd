# SPDX-License-Identifier: GPL-2.0

IPV=4

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1

adf_Bbdd_start

adf_vrf_prepare
Bbdd_setup_vrf V1 V2

Bbdd_connect_vrf V1 v1 $(Bbdd_IP_mask 1) \
		 V2 v2 $(Bbdd_IP_mask 2)
Bbdd_connect_vrf V1 w1 $(Bbdd_IP_mask 91) \
		 V2 w2 $(Bbdd_IP_mask 92)

Bbdd session add vrf V1 netif w1 dst $(Bbdd_IP 2) \
		 min-tx 200ms min-rx 200ms detect-mult 3

Bbdd session add vrf V2 netif w2 dst $(Bbdd_IP 1) \
		 min-tx 200ms min-rx 200ms detect-mult 3

nsessions_test 2

session_state_test up 0 vrf V1
session_state_test up 0 vrf V2

Bbdd session vrf V1 set dst $(Bbdd_IP 92)
Bbdd session vrf V2 set dst $(Bbdd_IP 91)

session_state_test up 1 vrf V1
session_state_test up 1 vrf V2
