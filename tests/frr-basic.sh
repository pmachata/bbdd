# SPDX-License-Identifier: GPL-2.0
root_require
Frr_require

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 $(Bbdd_IP_mask 1) \
		NS2 v2 $(Bbdd_IP_mask 2)

Bbdd_setup_socket SD1 FD2

with_socket SD1 in_ns NS1 adf_Bbdd_start
with_socket FD2 in_ns NS2 adf_Frr_bfdd_start

with_socket SD1 Bbdd session add \
	   discr 101 dst $(Bbdd_IP 2) \
	   min-tx 200ms min-rx 200ms detect-mult 3

with_socket FD2 Frr_session_add $(Bbdd_IP 1)

with_socket SD1 session_state_test up 1
with_socket FD2 Frr_session_test_up $(Bbdd_IP 1)
