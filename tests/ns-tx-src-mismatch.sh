# SPDX-License-Identifier: GPL-2.0
IPV=4
root_require

# Regression test for the bpf_fib_lookup() BPF_FIB_LOOKUP_SRC bug: TX used to
# always pass BPF_FIB_LOOKUP_SRC, which caused a configured source address to be
# overridden. Test the fix by setting up a session with wrong source IP and
# observing it fails to handshake.

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 $(Bbdd_IP_mask 1) \
		NS2 v2 $(Bbdd_IP_mask 2)

Bbdd_setup_socket SD1 SD2
with_socket SD1 in_ns NS1 adf_Bbdd_start
with_socket SD2 in_ns NS2 adf_Bbdd_start

with_socket SD1 Bbdd session add \
	   discr 111 src $(Bbdd_IP 9) dst $(Bbdd_IP 2) \
	   min-tx 200ms min-rx 200ms detect-mult 3

with_socket SD2 Bbdd session add \
	   discr 212 src $(Bbdd_IP 2) dst $(Bbdd_IP 1) \
	   min-tx 200ms min-rx 200ms detect-mult 3

get_rx_no_unique_session()
{
	with_socket SD2 Bbdd --json global diag stats |
		jq '.rx_no_unique_session'
}

# NS2 must actually be receiving NS1's packets, just failing to match them to a
# session uniquely. This rules out the setup being broken some other way.
slowwait_for_counter 3 1 get_rx_no_unique_session &>/dev/null
check_err $? "rx_no_unique_session did not climb; NS1's packets never reached NS2"
Bbdd_log_test "NS2 sees NS1's packets but cannot match them to a session"

with_socket SD2 session_state_test up 0 discr 212

remote_discr=$(with_socket SD2 Bbdd_session_get .state.remote.discr discr 212)
((remote_discr == 0))
check_err $? "NS2 remote_discr $remote_discr, expected not learned"
Bbdd_log_test "TX does not override configured source address"
