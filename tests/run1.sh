#!/bin/bash

T=$1; shift

tests_dir=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")
top_dir=${tests_dir}/..
bin_dir=${top_dir}/.output

source ${tests_dir}/defer.sh
trap defer_scopes_cleanup EXIT

source ${tests_dir}/lib.sh
source ${tests_dir}/libbbdd.sh
source ${tests_dir}/libfrr.sh

if [[ "$(id -u)" -ne 0 ]]; then
	log_test_skip "need root privileges"
	exit "$EXIT_STATUS"
fi

if [[ ! -e "$T" ]]; then
	log_test_skip "The test file $T does not exist"
else
	source "$T"
fi

exit "$EXIT_STATUS"
