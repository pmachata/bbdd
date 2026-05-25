# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1
Bbdd_setup_sockdir SD1

in_ns NS1 adf_vrf_prepare
in_ns NS1 Bbdd_setup_vrf V1

in_sockdir SD1

in_ns NS1 adf_Bbdd_start

Bbdd -q session add
check_fail $? "parameter-less session"

Bbdd -q session add no dst
check_fail $? "no dst"

Bbdd -q session add dst 192.0.2.1 src 2001:db8::1
check_fail $? "IPv4 x IPv6 mismatch 1"

Bbdd -q session add src 192.0.2.1 dst 2001:db8::1
check_fail $? "IPv4 x IPv6 mismatch 2"

Bbdd -q session add dst 192.0.2.1 detect-mult 0
check_fail $? "detect-mult 0"

Bbdd -q session add dst 192.0.2.1 detect-mult 300
check_fail $? "detect-mult >255"

Bbdd -q session add dst 192.0.2.1 netif foo
check_fail $? "unknown netif"

Bbdd -q session add dst 192.0.2.1 netif-index 1111
check_fail $? "unknown netif-index"

# Existing netif, wrong index.
Bbdd -q session add dst 192.0.2.1 netif lo netif-index 2
check_fail $? "invalid netif / netif-index combination"

Bbdd -q session add dst 192.0.2.1 vrf bar
check_fail $? "unknown vrf"

Bbdd -q session add dst 192.0.2.1 vrf-index 2222
check_fail $? "unknown vrf-index"

Bbdd -q session add dst 192.0.2.1 vrf lo
check_fail $? "vrf is not a VRF netdevice"

Bbdd -q session add dst 192.0.2.1 vrf V1 vrf-index 2222
check_fail $? "invalid vrf / vrf-index combination"

Bbdd -q session add dst 192.0.2.1 vrf V1 vrf-table 1234
check_fail $? "invalid vrf / vrf-table combination"

Bbdd_log_test "$xN ${descr}Invalid session parameters"
