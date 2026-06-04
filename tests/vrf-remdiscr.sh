# SPDX-License-Identifier: GPL-2.0

IPV=4

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_sockdir SD1
in_sockdir SD1
adf_Bbdd_start

adf_vrf_prepare
Bbdd_setup_vrf V1 V2
Bbdd_connect_vrf V1 v1 $(Bbdd_IP_mask 1) \
		 V2 v2 $(Bbdd_IP_mask 2)

Bbdd session add discr 0x101 remote-discr 0x222 vrf V1 \
		 src $(Bbdd_IP 1) dst $(Bbdd_IP 2) \
		 min-tx 200ms min-rx 200ms detect-mult 3

Bbdd session add discr 0x202 remote-discr 0x111 vrf V2 \
		 src $(Bbdd_IP 2) dst $(Bbdd_IP 1) \
		 min-tx 200ms min-rx 200ms detect-mult 3

nsessions_test 1 remote-discr 0x222
nsessions_test 0 remote-discr 222
nsessions_test 0 no remote-discr

session_state_test up 0 vrf V1
session_state_test up 0 vrf V2

Bbdd session vrf V1 set remote-discr 0x202
Bbdd session vrf V2 set remote-discr 0x101

session_state_test up 1 vrf V1
session_state_test up 1 vrf V2

Bbdd session vrf V2 del
Bbdd session add discr 0x303 vrf V2 \
		 src $(Bbdd_IP 2) dst $(Bbdd_IP 1) \
		 min-tx 200ms min-rx 200ms detect-mult 3

session_state_test not_up 1 vrf V1
session_state_test up 0 vrf V1
session_state_test up 0 vrf V2

Bbdd session vrf V1 set no remote-discr

session_state_test up 1 vrf V1
session_state_test up 1 vrf V2
