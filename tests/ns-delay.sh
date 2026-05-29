# SPDX-License-Identifier: GPL-2.0

IPV=4

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 $(Bbdd_IP_mask 1) \
		NS2 v2 $(Bbdd_IP_mask 2)

# Add 1-second one-way delay to each end of the link. The ping test in
# Bbdd_connect_ns has already run without delay, so adding it here does not
# affect the connectivity check.
in_ns NS1 Tc qdisc add dev v1 root netem delay 1000ms
defer in_ns NS1 Tc qdisc del dev v1 root
in_ns NS2 Tc qdisc add dev v2 root netem delay 1000ms
defer in_ns NS2 Tc qdisc del dev v2 root

Bbdd_setup_sockdir SD1 SD2
in_sockdir SD1 in_ns NS1 adf_Bbdd_start
in_sockdir SD2 in_ns NS2 adf_Bbdd_start

in_sockdir SD1 Bbdd session add dst $(Bbdd_IP 2) \
				min-tx 200ms min-rx 200ms detect-mult 6
in_sockdir SD2 Bbdd session add dst $(Bbdd_IP 1) \
				min-tx 200ms min-rx 200ms detect-mult 6

sleep 5

in_sockdir SD1 session_state_test up 1
in_sockdir SD2 session_state_test up 1
