# SPDX-License-Identifier: GPL-2.0
root_require

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1

adf_vrf_prepare
Bbdd_setup_vrf V1 V2
V1_ifindex=$(ip_link_ifindex V1)
Bbdd_connect_vrf V1 v1 192.0.2.1/28 \
		 V2 v2 192.0.2.2/28

adf_Bbdd_start

Bbdd -q session add \
     discr 1111 vrf V1 dst 192.0.2.2 min-tx 200ms min-rx 500ms detect-mult 3

OUT=$(Bbdd -v session show)

# session fields
find_match "$OUT" "\bdiscr 1111\b"
find_match "$OUT" "\bno src\b"
find_match "$OUT" "\bdst 192.0.2.2\b"
find_match "$OUT" "\bmin-tx 200ms\b"
find_match "$OUT" "\bmin-rx 500ms\b"
find_match "$OUT" "\bdetect-mult 3\b"
find_match "$OUT" "\bno netif\b"
find_match "$OUT" "\bvrf V1\b"
find_match "$OUT" "\bvrf-index ${V1_ifindex}\b"
find_match "$OUT" "\bvrf-table 1\b"
find_match "$OUT" "\bdiscr 0\b" # remote
find_no_match "$OUT" "remote-discr"
Bbdd_log_test "Session output"

OUT=$(Bbdd session show)
find_no_match "$OUT" "src"
find_no_match "$OUT" "netif"
Bbdd_log_test "Session output (non-verbose)"

Bbdd -q session set remote-discr 1234
OUT=$(Bbdd -v session show)
find_match "$OUT" "\bdiscr 1111\b"
find_match "$OUT" "\bdiscr 1234\b"
find_match "$OUT" "\bremote-discr 1234\b"
Bbdd_log_test "Session output (remote-discr)"
