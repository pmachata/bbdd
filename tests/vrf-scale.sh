# SPDX-License-Identifier: GPL-2.0

IPV=4

: ${N_SESSIONS:=1000}

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1
adf_Bbdd_start

adf_vrf_prepare
Bbdd_setup_vrf V1 V2
Bbdd_connect_vrf V1 v1 $(Bbdd_IP_mask 1) \
		 V2 v2 $(Bbdd_IP_mask 2)

# All sessions share the same (src, dst) addresses. They are disambiguated by
# the discriminator / remote-discriminator pair: V1's session i pairs with V2's
# session N+i, and each side's remote-discr filter steers incoming packets to
# the right local session.

Bbdd_log_info "Adding $N_SESSIONS \"near-end\" sessions"

for ((i = 1; i <= N_SESSIONS; i++)); do
	Bbdd session add discr $i remote-discr $((N_SESSIONS + i)) vrf V1 \
			 src $(Bbdd_IP 1) dst $(Bbdd_IP 2) \
			 min-tx 200ms min-rx 200ms detect-mult 3
done

Bbdd_log_info "Adding $N_SESSIONS \"far-end\" sessions"

for ((i = 1; i <= N_SESSIONS; i++)); do
	Bbdd session add discr $((N_SESSIONS + i)) remote-discr $i vrf V2 \
			 src $(Bbdd_IP 2) dst $(Bbdd_IP 1) \
			 min-tx 200ms min-rx 200ms detect-mult 3
done

BBDD_SESSION_WAIT_TIME=30 nsessions_state_test up $((2 * N_SESSIONS))
