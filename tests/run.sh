#!/bin/bash

tests_dir=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")

: "${TESTS:=
	ns-basic4.sh
	ns-basic6.sh
	vrf-basic4.sh
	vrf-basic6.sh
	ns-bridge4.sh
	ns-bridge6.sh
	vrf-bridge4.sh
	vrf-bridge6.sh
	vrf-ifbound.sh
	err.sh
	cli.sh
}"

for t in $TESTS; do
	echo == $t ==
	${tests_dir}/run1.sh "${tests_dir}/$t"
done
