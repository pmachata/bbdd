#!/bin/bash

tests_dir=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")
source ${tests_dir}/defer.sh
source ${tests_dir}/lib.sh

: "${TESTS:=
	ns-basic4.sh
	ns-basic6.sh
	frr-basic4.sh
	frr-basic6.sh
	frr-bfdd4.sh
	frr-bfdd6.sh
	vrf-basic4.sh
	vrf-basic6.sh
	ns-bridge4.sh
	ns-bridge6.sh
	ns-gone.sh
	ns-ttl4.sh
	ns-ttl6.sh
	vrf-bridge4.sh
	vrf-bridge6.sh
	vrf-ifbound.sh
	vrf-scale.sh
	ns-delay.sh
	ns-poll-timing.sh
	err.sh
	cli.sh
	jrpc-mangled.sh
	jrpc-client-mangled.sh
	jrpc-monitor-mangled.sh
}"

printf -v divider '%*s' 74 ''

for t in $TESTS; do
	echo
	echo "$t"
	echo "${divider// /-}"

	${tests_dir}/run1.sh "${tests_dir}/$t"
	check_err $? "$t"

	echo "${divider// /-}"
	log_test "$t"
done

echo
echo "${divider// /=}"
RET=$EXIT_STATUS
log_test "bbdd tests"
exit "$EXIT_STATUS"
