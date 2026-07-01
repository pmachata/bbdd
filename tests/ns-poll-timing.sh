# SPDX-License-Identifier: GPL-2.0
IPV=4
root_require

# Bring two sessions up against each other at 100ms/100ms/1, then have one
# end shorten both min-tx and min-rx by 1ms. The change triggers a poll
# sequence. Poll-sequence packets are trapped. If the BPF receive timer is
# not rearmed for the poll sequence packets, the session times out.

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 $(Bbdd_IP_mask 1) \
		NS2 v2 $(Bbdd_IP_mask 2)

Bbdd_setup_socket SD1 SD2
with_socket SD1 in_ns NS1 adf_Bbdd_start
with_socket SD2 in_ns NS2 adf_Bbdd_start

with_socket SD1 Bbdd session add \
	   discr 101 dst $(Bbdd_IP 2) \
	   min-tx 100ms min-rx 100ms detect-mult 1

with_socket SD2 Bbdd session add \
	   discr 202 dst $(Bbdd_IP 1) \
	   min-tx 100ms min-rx 100ms detect-mult 1

with_socket SD1 session_state_test up 1
with_socket SD2 session_state_test up 1

defer_scope_push
	touch ${SD1}/monout ${SD2}/monout
	defer rm ${SD1}/monout ${SD2}/monout

	defer_scope_push
		with_socket SD1 Bbdd_bground monitor session > ${SD1}/monout
		defer kill_process $!
		with_socket SD2 Bbdd_bground monitor session > ${SD2}/monout
		defer kill_process $!

		# Let both monitors complete their subscribe handshake
		# before we perturb anything.
		sleep 0.5

		# Kick off a poll sequence on SD1 by shortening both
		# timings by 1ms.
		with_socket SD1 Bbdd session set min-tx 99ms min-rx 99ms

		# Give the issue time to pop up. 100ms should be enough, but
		# give it a safety margin.
		sleep 1
	defer_scope_pop

	OUT1=$(cat ${SD1}/monout)
	OUT2=$(cat ${SD2}/monout)
defer_scope_pop

find_no_match "$OUT1" '\bstate down\b'
find_no_match "$OUT1" '\bstate init\b'
Bbdd_log_test "SD1 stayed up across the poll sequence"

find_no_match "$OUT2" '\bstate down\b'
find_no_match "$OUT2" '\bstate init\b'
Bbdd_log_test "SD2 stayed up across the poll sequence"
