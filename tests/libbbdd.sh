# SPDX-License-Identifier: GPL-2.0

: "${PING:=ping}"
: "${PING_COUNT:=10}"
: "${PING_TIMEOUT:=5}"

tmpdir=$(mktemp -d XXXXXX)
defer rm -Rf "$tmpdir"

Bbdd_setup_sockdir()
{
	local sd_name

	for sd_name in "$@"; do
		eval "${sd_name}=${tmpdir}/${sd_name,,}-$(mktemp -u XXXXXX)"
		mkdir -p "${!sd_name}"
		defer rm -Rf "${!sd_name}"
	done
}

in_sockdir()
{
	local sd_name=$1; shift

	BBDD_SOCKDIR="${sd_name}" "$@"
}

Bbdd()
{
	$(nspfx) "${bin_dir}/bbdd" --sockdir "${!BBDD_SOCKDIR}" "$@"
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

	if [[ $? != 0 ]]; then
		echo "failed to start bbdd" >/dev/stderr
		exit 1
	fi
}

adf_Bbdd_start()
{
	Bbdd start &
	defer in_sockdir "$BBDD_SOCKDIR" Bbdd_stop $!

	Bbdd_wait
}

adf_Bbdd_bridge_start()
{
	Bbdd bfdd bridge start unix:${!BBDD_SOCKDIR}/bfdd.sock &
	defer in_sockdir "$BBDD_SOCKDIR" Bbdd_stop $!

	Bbdd_wait
}

Bbdd_bfdd_connect()
{
	local dst_sockdir=$1; shift

	Bbdd bfdd connect unix:${!dst_sockdir}/bfdd.sock
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

Bbdd_describe_env()
{
	format_env $(collect_env) "$BBDD_SOCKDIR"
}

session_state_test()
{
	local check=$1; shift
	local goal=$1; shift
	local should_fail=$((!goal))

	"Bbdd_session_wait_$check" "$@"
	check_err_fail "$should_fail" $? "session up"

	log_test "$(Bbdd_describe_env)session $(if ((should_fail)); then echo 'never '; fi)got $check"
}

nsessions_test()
{
	local xN=$1; shift
	local descr="$@"
	local N
	local pl

	descr=${descr}${descr:+ }

	if ((xN != 1)); then
		pl=s
	fi

	N=$(Bbdd --json session "$@" show | jq -r '.sessions | length')
	((N == xN))

	check_err $? "$N sessions reported, $xN expected"
	log_test "$(Bbdd_describe_env)$xN ${descr}session$pl reported"
}

Bbdd_setup_ns()
{
	local -a ns_names=("$@")
	local ns_name

	for ns_name in "${ns_names[@]}"; do
		setup_ns "$ns_name"
		defer cleanup_ns "${!ns_name}"
		in_ns "$ns_name" adf_forwarding_enable
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
