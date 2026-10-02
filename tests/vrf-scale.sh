# SPDX-License-Identifier: GPL-2.0
root_require

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

echo
Bbdd_log_info "Adding $N_SESSIONS \"near-end\" sessions"

for ((i = 1; i <= N_SESSIONS; i++)); do
	Bbdd session add discr $i remote-discr $((N_SESSIONS + i)) vrf V1 \
			 src $(Bbdd_IP 1) dst $(Bbdd_IP 2) name "pair$i" \
			 min-tx 200ms min-rx 200ms detect-mult 3
done

Bbdd_log_info "Adding $N_SESSIONS \"far-end\" sessions"

for ((i = 1; i <= N_SESSIONS; i++)); do
	Bbdd session add discr $((N_SESSIONS + i)) remote-discr $i vrf V2 \
			 src $(Bbdd_IP 2) dst $(Bbdd_IP 1) name "pair$i" \
			 min-tx 200ms min-rx 200ms detect-mult 3
done

echo
BBDD_SESSION_WAIT_TIME=30 nsessions_state_test up $((2 * N_SESSIONS))

echo
Bbdd_log_info "Checking name queries"
echo

nnames=$(Bbdd --json session show | jq '[.sessions[].data.name] | unique | length')
((nnames == N_SESSIONS))
check_err $? "$nnames distinct session names reported, $N_SESSIONS expected"

nbad=$(Bbdd --json session show |
	jq '[.sessions[].data.name] | group_by(.) | map(select(length != 2)) | length')
((nbad == 0))
check_err $? "$nbad session name group(s) did not have exactly 2 members"

Bbdd_log_test "Querying by name"

nsessions_test 0 no name

Bbdd session discr 1 set no name
Bbdd session discr $((N_SESSIONS + 1)) set no name

nsessions_test 2 no name

discrs=$(Bbdd --json session no name show | jq -c '[.sessions[].data.discr] | sort')
expected=$(jq -nc --argjson b $((N_SESSIONS + 1)) '[1, $b] | sort')
[ "$discrs" = "$expected" ]
check_err $? "no-name session discrs were $discrs, expected $expected"

Bbdd_log_test "Unsetting a name"

Bbdd_log_head "bulk set shutdown"

# Hold/shwait used to each own a timerfd, so enough concurrently pending session
# timers would run the process out of file descriptors, which caused
# if_indextoname() failures.

Bbdd session bulk set shutdown
check_err $? "bulk set shutdown"
Bbdd_log_test "bulk set shutdown succeeded across $((2 * N_SESSIONS)) sessions"

# Admin-down sessions stop processing packets from the peer (RFC 6.18.6), so
# remote state is forced down. Only the local state is admindown.
nsessions_admindown()
{
	Bbdd --json session show | jq '
		[.sessions[] |
		 select(.state.local.state == "admindown" and
			.state.remote.state == "down")] |
		length'
}

nsessions_admindown_is()
{
	local xN=$1
	local N

	N=$(nsessions_admindown)
	((N == xN))
}

slowwait ${BBDD_SESSION_WAIT_TIME-30} nsessions_admindown_is $((2 * N_SESSIONS))
check_err $? "$((2 * N_SESSIONS)) sessions reach admindown/down"
Bbdd_log_test "$((2 * N_SESSIONS)) sessions reach admindown/down"
