# SPDX-License-Identifier: GPL-2.0

Bbdd_setup_ns NS1 NS2
Bbdd_connect_ns NS1 v1 192.0.2.1/28 \
		NS2 v2 192.0.2.2/28

Bbdd_setup_sockdir SD1 SD2 SD1br
in_sockdir SD1 in_ns NS1 adf_Bbdd_start
in_sockdir SD2 in_ns NS2 adf_Bbdd_start
in_sockdir SD1br adf_Bbdd_bridge_start

in_sockdir SD1 Bbdd_bfdd_connect SD1br

sleep 1

in_sockdir SD1br Bbdd -v echo
