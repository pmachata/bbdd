#!/bin/bash
t=$1
shift

tests_dir=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")
top_dir=${tests_dir}/..
bin_dir=${top_dir}/.output

source ${tests_dir}/lib.sh

trap defer_scopes_cleanup EXIT

tmpdir=$(mktemp -d XXXXXX)
defer rm -Rf "$tmpdir"

sockdir=${tmpdir}/sock
mkdir "$sockdir"
defer rm -Rf "$sockdir"

run_bbdd()
{
	sleep 1
	${bin_dir}/bbdd -v --sockdir "$sockdir" "$@"
}

run_bbdd2()
{
	${bin_dir}/bbdd --sockdir "$sockdir" "$@"
}

bbdd_start()
{
	local pid

	run_bbdd start &
	pid=$!
	defer kill_process "$pid"

	echo waiting
	slowwait 10 run_bbdd2 -q ping
	echo ready
}

source "$t"
