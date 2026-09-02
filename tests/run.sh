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
	ns-tx-cap.sh
	err.sh
	cli.sh
	jrpc-mangled.sh
	jrpc-client-mangled.sh
	jrpc-monitor-mangled.sh
	bfddp-mangled.sh
	nl-extack-mangled.sh
	bpf-diag-mangled.sh
	maxbuf.sh
	ctl-client-vanish.sh
	mon-debug-feedback.sh
}"

printf -v divider '%*s' 74 ''

# Per-test log_test output, captured as it's produced so it can be replayed
# as a summary at the end. Reused across iterations (each log_test call
# truncates it); accumulated into $summary as we go.
line=$(mktemp)
summary=$(mktemp)
trap 'rm -f "$line" "$summary"' EXIT

for t in $TESTS; do
	echo
	echo "$t"
	echo "${divider// /-}"

	${tests_dir}/run1.sh "${tests_dir}/$t"
	check_err $? "$t"

	echo "${divider// /-}"

	# log_test is not piped into tee here: piping would run it in a
	# subshell, and its EXIT_STATUS update would be lost to the parent
	# shell. Redirect to a file instead, then replay it both to stdout
	# and into the cumulative summary.
	log_test "$t" > "$line"
	cat "$line"
	cat "$line" >> "$summary"
done

echo
echo "Summary"
echo "${divider// /=}"
cat "$summary"
echo "${divider// /=}"

RET=$EXIT_STATUS
log_test "bbdd tests"
exit "$EXIT_STATUS"
