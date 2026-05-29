# SPDX-License-Identifier: GPL-2.0

IPV=4

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 $(Bbdd_IP_mask 1) \
		NS2 v2 $(Bbdd_IP_mask 2)

# Add 1-second one-way delay to each end of the link. The ping test in
# Bbdd_connect_ns has already run without delay, so adding it here does not
# affect the connectivity check.
in_sockdir SD1 Bbdd_log_info "Installing netem delay 1000ms"
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

# Test the poll sequence.

in_sockdir SD1 session_state_test bpf_stable 1

in_sockdir SD1 Bbdd_log_info "Change parameters"
in_sockdir SD1 Bbdd session set min-tx 300ms min-rx 300ms
BBDD_SESSION_WAIT_TIME=3 in_sockdir SD1 session_state_test bpf_await_final 1
BBDD_SESSION_WAIT_TIME=3 in_sockdir SD1 session_state_test bpf_await_non_final 1
BBDD_SESSION_WAIT_TIME=3 in_sockdir SD1 session_state_test bpf_stable 1

# Test admin down

get_tx_packets()
{
	in_sockdir SD1 Bbdd --json session stats |
		jq -j '.sessions[].stats.tx_packets'
}

tx_packets_0=$(get_tx_packets)

in_sockdir SD1 Bbdd_log_info "Set admin-down"
in_sockdir SD1 Bbdd session set shutdown
BBDD_SESSION_WAIT_TIME=3 in_sockdir SD1 session_state_test bpf_shutting_down 1
BBDD_SESSION_WAIT_TIME=3 in_sockdir SD1 session_state_test bpf_stable 1

tx_packets_1=$(get_tx_packets)
tx_packets_d=$((tx_packets_1 - tx_packets_0))

# With detect-mult of 6, we should see about 6 AdminDown packets before the
# session is bpf_stable again. Due to netem, if we were to look at what gets out
# of v1 right now, we would first see a second of state up packets, only then
# followed by these 6 or so admin down packets. But we are checking bbdd's own
# tx_packets counter, which shows which packets have been sent, which is what we
# care about.
((tx_packets_d >= 6 && tx_packets_d <= 8))
check_err $? "Expected approximately 6 packets, got $tx_packets_d"
Bbdd_log_test "Traffic continues after shutdown for a bit"

# At this point we shouldn't be sending anymore.
sleep 2
tx_packets_2=$(get_tx_packets)
tx_packets_d=$((tx_packets_2 - tx_packets_1))
((tx_packets_d == 0))
check_err $? "Expected no more packets, got $tx_packets_d"
Bbdd_log_test "Traffic stops after shutdown eventually"

in_sockdir SD1 session_state_test not_up 1
in_sockdir SD2 session_state_test not_up 1

in_sockdir SD1 Bbdd_log_info "Set admin-up"
in_sockdir SD1 Bbdd session set no shutdown
sleep 5
in_sockdir SD1 session_state_test up 1
in_sockdir SD2 session_state_test up 1
