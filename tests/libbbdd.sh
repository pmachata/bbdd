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

	# If Env() is to affect global settings when it's given without
	# commands, then the values need to be set one after another. Otherwise
	# the in_ns command serves as a command to make the earlier settings
	# command-local.
	if (($# == 0)); then
		BBDD_ENV="$NS"
		BBDD_SOCKDIR="${sockdir}"
		in_ns "$NS"
	else
		BBDD_ENV="$NS" BBDD_SOCKDIR="${sockdir}" in_ns "$NS" "$@"
	fi
}

Bbdd()
{
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
	slowwait 1 eq val up , Bbdd_session_remote_state "$@"
}

Bbdd_session_wait_not_up()
{
	slowwait 1 not eq val up , Bbdd_session_remote_state "$@"
}

session_state_test()
{
	local check=$1; shift
	local goal=$1; shift
	local should_fail=$((!goal))

	"Bbdd_session_wait_$check" "$@"
	check_err_fail "$should_fail" $? "session up"

	log_test "$BBDD_ENV: Session $(if ((should_fail)); then echo 'never '; fi)got $check"
}
