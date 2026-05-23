#!/bin/bash

tests_dir=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")

: "${TESTS:=
	ns-basic.sh
	vrf-basic.sh
	ns-bridge.sh
}"

for t in $TESTS; do
	echo == $t ==
	${tests_dir}/run1.sh "${tests_dir}/$t"
done
