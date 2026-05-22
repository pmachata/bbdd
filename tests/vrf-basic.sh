#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1

Env NS1

adf_vrf_prepare
Bbdd_setup_vrf V1 V2
Bbdd_connect_vrf V1 v1 192.0.2.1/28 \
		 V2 v2 192.0.2.2/28

Bbdd session add vrf V1 dst 192.0.2.2 min-tx 200ms min-rx 200ms detect-mult 3
Bbdd session add vrf V2 dst 192.0.2.1 min-tx 200ms min-rx 200ms detect-mult 3

session_state_test up 1 vrf V1
session_state_test up 1 vrf V2
