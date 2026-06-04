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
	vrf-bridge4.sh
	vrf-bridge6.sh
	vrf-ifbound.sh
	ns-delay.sh
	err.sh
	cli.sh
}"

for t in $TESTS; do
	echo "== $t =="

	${tests_dir}/run1.sh "${tests_dir}/$t"
	check_err $? "$t"

	log_test "$t"
done

exit "$EXIT_STATUS"
