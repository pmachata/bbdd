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

Bbdd_setup_ns()
{
	local -a ns_names=("$@")
	local ns_name

	setup_ns "${ns_names[@]}"
	defer cleanup_ns "${ns_names[@]}"

	for ns_name in "${ns_names[@]}"; do
		in_ns "$ns_name" adf_forwarding_enable
		Env "$ns_name" adf_Bbdd_start_or_die
	done
}

Bbdd_setup_vrf()
{
	local -a vrf_names=("$@")
	local vrf_name

	for vrf_name in "${vrf_names[@]}"; do
		adf_vrf_create "$vrf_name"
		adf_ip_link_set_up "$vrf_name"
	done
}

Bbdd_connect_ns()
{
	while (($# > 0)); do
		local ns1_name=$1; shift
		local ns1_link=$1; shift
		local ns1_addr=$1; shift

		local ns2_name=$1; shift
		local ns2_link=$1; shift
		local ns2_addr=$1; shift

		ip link add name "$ns1_link" netns "${!ns1_name}" type veth \
		   peer name "$ns2_link" netns "${!ns2_name}"
		defer in_ns "$ns1_name" Ip link del dev "$ns1_link"

		in_ns "$ns1_name" adf_ip_link_set_up "$ns1_link"
		in_ns "$ns2_name" adf_ip_link_set_up "$ns2_link"

		in_ns "$ns1_name" adf_ip_addr_add "$ns1_link" "$ns1_addr"
		in_ns "$ns2_name" adf_ip_addr_add "$ns2_link" "$ns2_addr"

		in_ns "$ns1_name" ping_test "${ns2_addr%/*}"
		in_ns "$ns2_name" ping_test "${ns1_addr%/*}"
	done
}

Bbdd_connect_vrf()
{
	while (($# > 0)); do
		local vrf1_name=$1; shift
		local vrf1_link=$1; shift
		local vrf1_addr=$1; shift

		local vrf2_name=$1; shift
		local vrf2_link=$1; shift
		local vrf2_addr=$1; shift

		adf_ip_link_add "$vrf1_link" master "$vrf1_name" type veth \
				peer name "$vrf2_link"
		adf_ip_link_set_up "$vrf1_link"

		adf_ip_link_set_master "$vrf2_link" "$vrf2_name"
		adf_ip_link_set_up "$vrf2_link"

		adf_ip_addr_add "$vrf1_link" "$vrf1_addr"
		adf_ip_addr_add "$vrf2_link" "$vrf2_addr"

		in_vrf "$vrf1_name" ping_test "${vrf2_addr%/*}"
		in_vrf "$vrf2_name" ping_test "${vrf1_addr%/*}"
	done
}
