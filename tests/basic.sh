#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

setup_ns NS1 NS2
defer cleanup_all_ns

ip link add name L netns "$NS1" type veth peer name L netns "$NS2"
defer in_ns NS1 Ip link del dev L

in_ns NS1 adf_ip_link_set_up L
in_ns NS2 adf_ip_link_set_up L

in_ns NS1 adf_ip_addr_add L 192.0.2.1/28
in_ns NS2 adf_ip_addr_add L 192.0.2.2/28

in_ns NS1 adf_forwarding_enable
in_ns NS2 adf_forwarding_enable

in_ns NS1 ping_test L 192.0.2.2
in_ns NS2 ping_test L 192.0.2.1

Env NS1 adf_Bbdd_start_or_die
Env NS2 adf_Bbdd_start_or_die

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

check_session_state()
{
	local check=$1; shift
	local goal=$1; shift
	local should_fail=$((!goal))

	Env NS1 "Bbdd_session_wait_$check"
	check_err_fail "$should_fail" $? "session up"

	log_test "$BBDD_ENV: Session $(if ((should_fail)); then echo 'never '; fi)got $check"
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
Env NS1 check_session_state up 0

Env NS2 Bbdd session add dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3
Env NS2 check_nsessions 1

# Check that they reach up
Env NS1 check_session_state up 1
Env NS2 check_session_state up 1

Env NS1 Bbdd session del
Env NS1 check_nsessions 0

# Check that it reaches not-up
Env NS2 check_session_state not_up 1
