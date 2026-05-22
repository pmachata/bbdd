#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

setup_ns NS1
defer cleanup_all_ns

Env NS1

adf_forwarding_enable
adf_vrf_prepare

adf_vrf_create V1
adf_ip_link_set_up V1

adf_vrf_create V2
adf_ip_link_set_up V2

adf_ip_link_add L1 master V1 type veth peer name L2
adf_ip_link_set_up L1

adf_ip_link_set_master L2 V2
adf_ip_link_set_up L2

adf_ip_addr_add L1 192.0.2.1/28
adf_ip_addr_add L2 192.0.2.2/28

in_vrf V1 ping_test 192.0.2.2
in_vrf V2 ping_test 192.0.2.1

adf_Bbdd_start_or_die

Bbdd session add vrf V1 dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3
Bbdd session add vrf V2 dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3

session_state_test up 1 vrf V1
session_state_test up 1 vrf V2
