#!/bin/bash

setup_ns NS1 NS2
defer cleanup_all_ns

ip link add name L netns "$NS1" type veth peer name L netns "$NS2"
defer ip -n "$NS1" link del dev L

adf_ip_link_set_up "$NS1" L
adf_ip_link_set_up "$NS2" L

adf_ip_addr_add "$NS1" L 192.0.2.1/28
adf_ip_addr_add "$NS2" L 192.0.2.2/28

adf_forwarding_enable
Env NS1 ping_test L 192.0.2.2

Env NS1 adf_Bbdd_start_or_die
Env NS2 adf_Bbdd_start_or_die

Env NS1 Bbdd session add dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3
Env NS2 Bbdd session add dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3

slowwait 1 Env NS1 eq val up -- Bbdd_session_remote_state
check_err $? "session not up"
log_test "NS1 remote up"

slowwait 1 Env NS2 eq val up -- Bbdd_session_remote_state
check_err $? "session not up"
log_test "NS2 remote up"
