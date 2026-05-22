#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 192.0.2.1/28 \
		NS2 v2 192.0.2.2/28

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
	log_test "$BBDD_ENV: $xN ${descr}session$pl reported"
}

Env NS1 check_nsessions 0
Env NS2 check_nsessions 0

Env NS1 Bbdd session add dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3

Env NS1 check_nsessions 1

Env NS1 check_nsessions 1 dst 192.0.2.2
Env NS1 check_nsessions 1 min-tx 200ms
Env NS1 check_nsessions 1 min-rx 200ms
Env NS1 check_nsessions 1 detect-mult 3
Env NS1 check_nsessions 1 dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3

Env NS1 check_nsessions 0 dst 192.0.2.3
Env NS1 check_nsessions 0 min-tx 300ms
Env NS1 check_nsessions 0 min-rx 300ms
Env NS1 check_nsessions 0 detect-mult 4

Env NS1 check_nsessions 0 dst 192.0.2.3 min-tx 200ms min-rx 200ms detect-mult 3
Env NS1 check_nsessions 0 dst 192.0.2.2 min-tx 300ms min-rx 200ms detect-mult 3
Env NS1 check_nsessions 0 dst 192.0.2.2 min-tx 200ms min-rx 300ms detect-mult 3
Env NS1 check_nsessions 0 dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 4

# Check that it fails to reach up
Env NS1 session_state_test up 0

Env NS2 Bbdd session add dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3
Env NS2 check_nsessions 1

# Check that they reach up
Env NS1 session_state_test up 1
Env NS2 session_state_test up 1

Env NS1 Bbdd session del
Env NS1 check_nsessions 0

# Check that it reaches not-up
Env NS2 session_state_test not_up 1
