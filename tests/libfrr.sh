# SPDX-License-Identifier: GPL-2.0

FRR_BFDD=/usr/libexec/frr/bfdd
FRR_VTYSH=/usr/bin/vtysh

Frr_require()
{
	local tool

	for tool in "$FRR_BFDD" "$FRR_VTYSH"; do
		if [[ ! -x "$tool" ]]; then
			log_test_skip "$tool not found"
			exit "$EXIT_STATUS"
		fi
	done
}

in_frrdir()
{
	local fd_name=$1; shift

	FRRD="${fd_name}" "$@"
}

Frr_vtysh()
{
	"$FRR_VTYSH" --vty_socket "${!FRRD}" -d bfdd "$@"
}

adf_Frr_bfdd_start()
{
	$(nspfx) "$FRR_BFDD" \
		 --vty_socket "${!FRRD}" \
		 --pid_file "${!FRRD}/bfdd.pid" \
		 --socket "${!FRRD}/zserv.api" \
		 --log file:/dev/stderr --log-level error &
	local pid=$!
	defer kill_process $pid

	slowwait 5 test -S "${!FRRD}/bfdd.vty"
	if [[ $? != 0 ]]; then
		echo "failed to start bfdd" >/dev/stderr
		exit 1
	fi
}

Frr_session_add()
{
	local peer=$1; shift

	Frr_vtysh \
		-c "configure terminal" \
		-c "bfd" \
		-c "peer $peer" \
		-c "echo receive-interval disabled" \
		-c "end"
}

Frr_session_state()
{
	local peer=$1; shift

	Frr_vtysh -c "show bfd peers json" | \
		jq -r --arg peer "$peer" '.[] | select(.peer == $peer) | .status'
}

Frr_session_is_up()
{
	local peer=$1; shift

	[[ "$(Frr_session_state "$peer")" == "up" ]]
}

Frr_session_wait_up()
{
	local peer=$1; shift

	slowwait ${BBDD_SESSION_WAIT_TIME-5} Frr_session_is_up "$peer"
}

Frr_session_test_up()
{
	local peer=$1; shift

	Frr_session_wait_up "$peer"
	check_err $? "FRR bfdd session with $peer did not reach up"
	log_test "$(format_env "$FRRD")FRR bfdd session with $peer up"
}
