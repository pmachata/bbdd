# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 192.0.2.1/28 \
		NS2 v2 192.0.2.2/28

Bbdd_setup_sockdir SD1 SD2
in_sockdir SD1 in_ns NS1 adf_Bbdd_start
in_sockdir SD2 in_ns NS2 adf_Bbdd_start

check_nsessions()
{
	local xN=$1; shift
	local descr="$@"
	local N
	local pl

	descr=${descr}${descr:+ }

	if ((xN != 1)); then
		pl=s
	fi

	N=$(Bbdd --json session "$@" show | jq -r '.sessions | length')
	((N == xN))

	check_err $? "$N sessions reported, $xN expected"
	log_test "$(Bbdd_describe_env)$xN ${descr}session$pl reported"
}

in_sockdir SD1 check_nsessions 0
in_sockdir SD2 check_nsessions 0

in_sockdir SD1 Bbdd session add dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3

in_sockdir SD1 check_nsessions 1

in_sockdir SD1 check_nsessions 1 dst 192.0.2.2
in_sockdir SD1 check_nsessions 1 min-tx 200ms
in_sockdir SD1 check_nsessions 1 min-rx 200ms
in_sockdir SD1 check_nsessions 1 detect-mult 3
in_sockdir SD1 check_nsessions 1 dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3

in_sockdir SD1 check_nsessions 0 dst 192.0.2.3
in_sockdir SD1 check_nsessions 0 min-tx 300ms
in_sockdir SD1 check_nsessions 0 min-rx 300ms
in_sockdir SD1 check_nsessions 0 detect-mult 4

in_sockdir SD1 check_nsessions 0 dst 192.0.2.3 min-tx 200ms min-rx 200ms detect-mult 3
in_sockdir SD1 check_nsessions 0 dst 192.0.2.2 min-tx 300ms min-rx 200ms detect-mult 3
in_sockdir SD1 check_nsessions 0 dst 192.0.2.2 min-tx 200ms min-rx 300ms detect-mult 3
in_sockdir SD1 check_nsessions 0 dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 4

# Check that it fails to reach up
in_sockdir SD1 session_state_test up 0

in_sockdir SD2 Bbdd session add dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3
in_sockdir SD2 check_nsessions 1

# Check that they reach up
in_sockdir SD1 session_state_test up 1
in_sockdir SD2 session_state_test up 1

in_sockdir SD1 Bbdd session del
in_sockdir SD1 check_nsessions 0

# Check that it reaches not-up
in_sockdir SD2 session_state_test not_up 1
