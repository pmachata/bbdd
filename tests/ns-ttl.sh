# SPDX-License-Identifier: GPL-2.0

# Topology:
#
#   NS1 v1 --- v2a NS2 v2b --- v3 NS3
#      192.0.2.0/28   192.0.2.16/28
# 2001:db8:1::0/124   2001:db8:1::16/124
#
# NS2 routes between v2a and v2b. bbdd runs in NS1 and NS3, with a multihop
# session between them.

Bbdd_setup_ns NS1 NS2 NS3
Bbdd_connect_ns NS1 v1  $(Bbdd_IP_mask 1)  NS2 v2a $(Bbdd_IP_mask 2)  \
		NS2 v2b $(Bbdd_IP_mask 17) NS3 v3  $(Bbdd_IP_mask 18)

in_ns NS1 adf_ip_route_add $(Bbdd_IP_mask 16) via $(Bbdd_IP 2)
in_ns NS3 adf_ip_route_add $(Bbdd_IP_mask 0)  via $(Bbdd_IP 17)

in_ns NS1 ping_test $(Bbdd_IP 18)
in_ns NS3 ping_test $(Bbdd_IP 1)

Bbdd_setup_socket SD1 SD3
with_socket SD1 in_ns NS1 adf_Bbdd_start
with_socket SD3 in_ns NS3 adf_Bbdd_start

with_socket SD1 Bbdd session add dst $(Bbdd_IP 18) discr 0x100 multihop \
		ttl 255 min-tx 200ms min-rx 200ms detect-mult 3
with_socket SD3 Bbdd session add dst $(Bbdd_IP 1)  discr 0x300 multihop \
		ttl 255 min-tx 200ms min-rx 200ms detect-mult 3

# bbdd sends BFD packets with TTL 255; the one router hop decrements it to
# 254, which is below the session threshold and the packets are dropped.
with_socket SD1 session_state_test up 0
with_socket SD3 session_state_test up 0

# Lower the threshold to 254 on both sides; the post-decrement TTL now passes.
with_socket SD1 Bbdd session set ttl 254
with_socket SD3 Bbdd session set ttl 254

with_socket SD1 session_state_test up 1
with_socket SD3 session_state_test up 1

# Raise the threshold back to 255; packets are dropped again and the
# detection timer brings the session down.
with_socket SD1 Bbdd session set ttl 255
with_socket SD3 Bbdd session set ttl 255

with_socket SD1 session_state_test not_up 1
with_socket SD3 session_state_test not_up 1
