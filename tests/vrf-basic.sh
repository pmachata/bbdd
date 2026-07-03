# SPDX-License-Identifier: GPL-2.0
root_require

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1
adf_Bbdd_start

adf_vrf_prepare
Bbdd_setup_vrf V1 V2
Bbdd_connect_vrf V1 v1 $(Bbdd_IP_mask 1) \
		 V2 v2 $(Bbdd_IP_mask 2)

Bbdd session add vrf V1 src $(Bbdd_IP 1) dst $(Bbdd_IP 2) \
		 min-tx 200ms min-rx 200ms detect-mult 3

Bbdd session add vrf V2 src $(Bbdd_IP 2) dst $(Bbdd_IP 1) \
		 min-tx 200ms min-rx 200ms detect-mult 3 hold-time 5s

hold_time_test 5 vrf V1
session_state_test up 1 vrf V2

sk_pinned_test 2

Bbdd session bulk del
nsessions_test 0

sk_pinned_test 0

Bbdd session add vrf V1 src $(Bbdd_IP 1) dst $(Bbdd_IP 2) \
		 min-tx 200ms min-rx 200ms detect-mult 3 multihop

Bbdd session add vrf V2 src $(Bbdd_IP 2) dst $(Bbdd_IP 1) \
		 min-tx 200ms min-rx 200ms detect-mult 3

session_state_test up 0 vrf V1
session_state_test up 0 vrf V2

Bbdd session vrf V2 set multihop

session_state_test up 1 vrf V1
session_state_test up 1 vrf V2

sk_pinned_test 2

# Any session-set bumps gen_id, retiring the packet still spinning in
# fq for the affected session. Verify the BPF drop rule actually fires:
# bump ttl (does not trigger a poll sequence, so no confounders), wait
# comfortably past max_interval, and check tx_wrong_gen_id climbed.
before=$(Bbdd --json session vrf V1 diag stats |
	jq '.sessions[0].stats.tx_wrong_gen_id')
Bbdd session vrf V1 set ttl 254
sleep 0.3
after=$(Bbdd --json session vrf V1 diag stats |
	jq '.sessions[0].stats.tx_wrong_gen_id')
((after > before))
check_err $? "tx_wrong_gen_id did not climb (before=$before after=$after)"
Bbdd_log_test "BPF drops obsolete gen_id packets"
