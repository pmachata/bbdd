# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 $(Bbdd_IP_mask 1) \
		NS2 v2 $(Bbdd_IP_mask 2)

Bbdd_setup_socket SD1 SD2
with_socket SD1 in_ns NS1 adf_Bbdd_start
with_socket SD2 in_ns NS2 adf_Bbdd_start

with_socket SD1 nsessions_test 0
with_socket SD2 nsessions_test 0

with_socket SD1 Bbdd session add \
	   discr 101 dst $(Bbdd_IP 2) \
	   min-tx 200ms min-rx 200ms detect-mult 3 passive

with_socket SD1 nsessions_test 1

with_socket SD1 nsessions_test 1 dst $(Bbdd_IP 2)
with_socket SD1 nsessions_test 1 min-tx 200ms
with_socket SD1 nsessions_test 1 min-rx 200ms
with_socket SD1 nsessions_test 1 detect-mult 3
with_socket SD1 nsessions_test 1 \
	   dst $(Bbdd_IP 2) min-tx 200ms min-rx 200ms detect-mult 3

with_socket SD1 nsessions_test 0 dst $(Bbdd_IP 3)
with_socket SD1 nsessions_test 0 min-tx 300ms
with_socket SD1 nsessions_test 0 min-rx 300ms
with_socket SD1 nsessions_test 0 detect-mult 4

with_socket SD1 nsessions_test 0 \
	   dst $(Bbdd_IP 3) min-tx 200ms min-rx 200ms detect-mult 3
with_socket SD1 nsessions_test 0 \
	   dst $(Bbdd_IP 2) min-tx 300ms min-rx 200ms detect-mult 3
with_socket SD1 nsessions_test 0 \
	   dst $(Bbdd_IP 2) min-tx 200ms min-rx 300ms detect-mult 3
with_socket SD1 nsessions_test 0 \
	   dst $(Bbdd_IP 2) min-tx 200ms min-rx 200ms detect-mult 4

# Check that it fails to reach up
with_socket SD1 session_state_test up 0

passive_zero_test()
{
	Bbdd session stats | grep -q ': [^0]'
	check_fail $? "non-zero stats reported"

	Bbdd_log_test "Stats zero for passive session"
}

with_socket SD2 Bbdd session add \
	   discr 202 dst $(Bbdd_IP 1) \
	   min-tx 200ms min-rx 200ms detect-mult 3 passive
with_socket SD2 nsessions_test 1

# passive-passive: Neither should reach up yet, since they are both passive.
with_socket SD1 session_state_test up 0
with_socket SD2 session_state_test up 0

with_socket SD1 passive_zero_test
with_socket SD2 passive_zero_test

in_ns NS1 Ip -$IPV neigh del $(Bbdd_IP 2) dev v1

defer_scope_push
	touch ${SD1}/monout
	defer rm ${SD1}/monout

	defer_scope_push
		with_socket SD1 Bbdd_bground monitor ringbuf > ${SD1}/monout
		defer kill_process $!

		with_socket SD1 Bbdd session set no passive

		# SD1 is not passive anymore and both should now reach up.
		with_socket SD1 session_state_test up 1
		with_socket SD2 session_state_test up 1
	defer_scope_pop

	OUT=$(cat ${SD1}/monout)
defer_scope_pop

find_match "$OUT" "ringbuf:tx-no-neigh *: ifindex .* addr $(Bbdd_IP 2)"
Bbdd_log_test "Monitor tx-no-neigh"

find_match "$OUT" 'ringbuf:rx-unx-pkt *: wire-len .* ttl 255.*state init\b.*\bmy-disc 202 your-disc 101'
Bbdd_log_test "Monitor rx-unx-pkt init"

find_match "$OUT" 'ringbuf:rx-unx-pkt *: wire-len .* ttl 255.* state up\b.*\bmy-disc 202 your-disc 101'
Bbdd_log_test "Monitor rx-unx-pkt up"

with_socket SD1 echo_test
with_socket SD2 echo_test

sleep 2 # Collect traffic.

with_socket SD1 Bbdd session del
with_socket SD1 nsessions_test 0

# Check that it reaches not-up
with_socket SD2 session_state_test not_up 1

with_socket SD2 Bbdd session set shutdown

with_socket SD2 packet_size_test
with_socket SD2 session_stats_consistency_test
with_socket SD2 session_diag_stats_consistency_test
with_socket SD2 global_diag_stats_consistency_test
