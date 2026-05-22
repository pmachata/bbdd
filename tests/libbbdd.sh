# SPDX-License-Identifier: GPL-2.0

: "${PING:=ping}"
: "${PING_COUNT:=10}"
: "${PING_TIMEOUT:=5}"

tmpdir=$(mktemp -d XXXXXX)
defer rm -Rf "$tmpdir"

Env()
{
	local NS=$1; shift
	local sockdir="${tmpdir}/sock-$NS"

	if [[ ! -e "${sockdir}" ]]; then
		mkdir -p "${sockdir}"
		defer rm -Rf "${sockdir}"
	fi

	BBDD_ENV="$NS" BBDD_SOCKDIR="${sockdir}" in_ns "$NS" "$@"
}

Bbdd()
{
	local ns=$IN_NS

	$(nspfx) "${bin_dir}/bbdd" --sockdir "$BBDD_SOCKDIR" "$@"
}

Bbdd_stop()
{
	local pid=$1; shift

	Bbdd -q ping
	if [[ $? != 0 ]]; then
		echo "bbdd already dead" >/dev/stderr
		return
	fi

	Bbdd -q stop
	if [[ $? != 0 ]]; then
		echo "couldn't issue bbdd stop" >/dev/stderr
		return
	fi

	slowwait 1 not Bbdd -q ping

	if [[ $? != 0 ]]; then
		echo "timeout waiting for bbdd to stop, killing" >/dev/stderr
		kill_process "$pid"
	fi
}

Bbdd_wait()
{
	slowwait 5 Bbdd -q ping
}

adf_Bbdd_start()
{
	Bbdd start &
	defer Env "$BBDD_ENV" Bbdd_stop $!

	Bbdd_wait
	if [[ $? != 0 ]]; then
		echo "failed to start bbdd" >/dev/stderr
		return 1
	fi

	return 0
}

adf_Bbdd_start_or_die()
{
	adf_Bbdd_start
	if [[ $? != 0 ]]; then
		exit 1
	fi
}

master_name_get()
{
	local if_name=$1

	$(nspfx) ip -j link show dev "$if_name" | jq -r '.[]["master"] // ""'
}

Bbdd_session_get()
{
	local key=$1; shift

	Bbdd --json session "$@" show | jq -r ".sessions.[]$key"
}

Bbdd_session_remote_state()
{
	Bbdd_session_get .state.local.state "$@"
}

Bbdd_session_wait_up()
{
	slowwait 1 eq val up , Bbdd_session_remote_state
}

Bbdd_session_wait_not_up()
{
	slowwait 1 not eq val up , Bbdd_session_remote_state
}

ping_do()
{
	local if_name=$1
	local dip=$2

	$(nspfx) $(vrfpfx) \
		$PING -c "$PING_COUNT" -i 0.1 \
		      -w "$PING_TIMEOUT" "$dip" &> /dev/null
}

ping_test()
{
	local if_name=$1; shift
	local dip=$1; shift

	local vrf_name=$(master_name_get $if_name)

	RET=0

	in_vrf "$vrf_name" \
	       ping_do "$if_name" "$dip"
	check_err $?
	log_test "ping"
}
