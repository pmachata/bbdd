# SPDX-License-Identifier: GPL-2.0
IPV=4
root_require

# Exercise the tx-queue enqueue/drain path via --debug=tx-cap=<N>.
#
# tx-cap must leave headroom for a "current spinner + one more" during
# normal session updates (otherwise the handshake itself stalls), so
# cap=2 is the minimum useful value. We then force the queue by doing
# two consecutive ttl bumps on the same session: the first bump
# injects a fresh packet while the old spinner is still in fq (pinned
# = 2), and the second bump hits the capacity ceiling and defers.
#
# min-tx of 500ms gives the two ttl bumps plenty of time to happen
# before the first old spinner is dropped from fq.

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 $(Bbdd_IP_mask 1) \
		NS2 v2 $(Bbdd_IP_mask 2)

Bbdd_setup_socket SD1 SD2

with_socket SD1 in_ns NS1 Bbdd_bground --debug=mon-eager \
					--debug=tx-cap=2 \
					start
defer with_socket SD1 Bbdd_stop $!
with_socket SD1 Bbdd_wait

with_socket SD2 in_ns NS2 adf_Bbdd_start

with_socket SD1 Bbdd session add \
	   discr 101 dst $(Bbdd_IP 2) \
	   min-tx 500ms min-rx 500ms detect-mult 3

with_socket SD2 Bbdd session add \
	   discr 202 dst $(Bbdd_IP 1) \
	   min-tx 500ms min-rx 500ms detect-mult 3

with_socket SD1 session_state_test up 1
with_socket SD2 session_state_test up 1

with_socket SD1 sk_pinned_test 1

# bumping TTL issues a new periodical packet. At that point, we have two pinned
# packets: the old packet, and the packet with the new TTL. Then bump TTL again.
# Since we set tx-cap=2, this has to go to queue. In theory, this is timing
# sensitive and the old packet apparently sometimes clears, so spam TTL a third
# time to make sure.
enq_before=$(with_socket SD1 Bbdd --json global diag stats |
		     jq '.sk_enq_count')
deq_before=$(with_socket SD1 Bbdd --json global diag stats |
		     jq '.sk_deq_count')
with_socket SD1 Bbdd session set ttl 254
with_socket SD1 Bbdd session set ttl 253
with_socket SD1 Bbdd session set ttl 252
enq_after=$(with_socket SD1 Bbdd --json global diag stats |
	    jq '.sk_enq_count')

((enq_after > enq_before))
check_err $? "sk_enq_count did not climb (before=$enq_before after=$enq_after)"
Bbdd_log_test "tx queue enqueue exercised"

# The first ttl bump's old spinner drops within min_tx (~500ms),
# freeing capacity. The drain timer picks it up (fires every 50ms)
# and reissues the deferred session_update, bumping sk_deq_count.
sleep 1
deq_after=$(with_socket SD1 Bbdd --json global diag stats |
		    jq '.sk_deq_count')

((deq_after > deq_before))
check_err $? "sk_deq_count did not climb (before=$deq_before after=$deq_after)"
Bbdd_log_test "tx queue drain exercised"

# Session should still be up — the queue absorbed the burst rather
# than dropping intent.
with_socket SD1 session_state_test up 1

# Check the queue length: with tx-cap of 2, we have one periodic, then the new
# session will inject its own periodic, which exhausts the queue, and the third
# session has to go to queue.
qlen=$(with_socket SD1 Bbdd --json global diag stats |
	       jq '.sk_qlen_periodic')
((qlen == 0))
check_err $? "sk_qlen_periodic $qlen, 0 expected"

with_socket SD1 Bbdd session add \
	   discr 102 dst $(Bbdd_IP 4) \
	   min-tx 500ms min-rx 500ms detect-mult 3

with_socket SD1 Bbdd session add \
	   discr 103 dst $(Bbdd_IP 6) \
	   min-tx 500ms min-rx 500ms detect-mult 3

sleep 1

qlen=$(with_socket SD1 Bbdd --json global diag stats |
	       jq '.sk_qlen_periodic')
((qlen == 1))
check_err $? "sk_qlen_periodic $qlen, 1 expected"

with_socket SD1 Bbdd session discr 102 del

sleep 1

qlen=$(with_socket SD1 Bbdd --json global diag stats |
	       jq '.sk_qlen_periodic')
((qlen == 0))
check_err $? "sk_qlen_periodic $qlen, 0 expected again"

Bbdd_log_test "tx qlen"
