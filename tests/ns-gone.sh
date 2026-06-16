# SPDX-License-Identifier: GPL-2.0

IPV=4

Bbdd_setup_ns NS1 NS2 NS3 NSb
Bbdd_connect_ns NS1 v1 $(Bbdd_IP_mask 1) \
		NSb vA -                 \
		NS2 v2 $(Bbdd_IP_mask 2) \
		NSb vB -                 \
		NS3 v3 $(Bbdd_IP_mask 2) \
		NSb vC -

in_ns NSb adf_ip_link_add br up type bridge
in_ns NSb Ip link set dev vA master br

in_ns NSb Ip link set dev vB master br # connect NS1-NS2

sleep 2
in_ns NS1 ping_test $(Bbdd_IP 2)
in_ns NS2 ping_test $(Bbdd_IP 1)

Bbdd_setup_socket SD1 SD2 SD3
with_socket SD1 in_ns NS1 adf_Bbdd_start
with_socket SD2 in_ns NS2 adf_Bbdd_start
with_socket SD3 in_ns NS3 adf_Bbdd_start

with_socket SD1 Bbdd session add dst $(Bbdd_IP 2) discr 0x110 \
				min-tx 200ms min-rx 200ms detect-mult 3
with_socket SD2 Bbdd session add dst $(Bbdd_IP 1) discr 0x220 \
				min-tx 200ms min-rx 200ms detect-mult 3
with_socket SD3 Bbdd session add dst $(Bbdd_IP 1) discr 0x333 \
				min-tx 200ms min-rx 200ms detect-mult 3

with_socket SD1 session_state_test up 1
with_socket SD2 session_state_test up 1
with_socket SD3 session_state_test not_up 1

with_socket SD2 Bbdd session del
with_socket SD1 session_state_test not_up 1

with_socket SD2 Bbdd session add dst $(Bbdd_IP 1) discr 0x222 \
				min-tx 200ms min-rx 200ms detect-mult 3

with_socket SD1 session_state_test up 1
with_socket SD2 session_state_test up 1
with_socket SD3 session_state_test not_up 1

in_ns NSb Ip link set dev vB nomaster
in_ns NSb Ip link set dev vC master br # connect NS1-NS3

sleep 2
in_ns NS1 ping_test $(Bbdd_IP 2)
in_ns NS3 ping_test $(Bbdd_IP 1)

with_socket SD1 session_state_test up 1
with_socket SD2 session_state_test not_up 1
with_socket SD3 session_state_test up 1

with_socket SD1 Bbdd session del
with_socket SD1 Bbdd session add dst $(Bbdd_IP 2) discr 0x111 \
				min-tx 200ms min-rx 200ms detect-mult 3

with_socket SD1 session_state_test up 1
with_socket SD2 session_state_test not_up 1
with_socket SD3 session_state_test up 1

in_ns NSb Ip link set dev vC nomaster
in_ns NSb Ip link set dev vB master br # connect NS1-NS2 again

sleep 2
in_ns NS1 ping_test $(Bbdd_IP 2)
in_ns NS2 ping_test $(Bbdd_IP 1)

with_socket SD1 session_state_test up 1
with_socket SD2 session_state_test up 1
with_socket SD3 session_state_test not_up 1
