# SPDX-License-Identifier: GPL-2.0

tmpdir=$(mktemp -d /tmp/XXXXXX)
defer rm -Rf "$tmpdir"
chmod a+rwx "${tmpdir}"

Bbdd_setup_socket()
{
	local s_name
	local dir

	for s_name in "$@"; do
		dir="${tmpdir}/${s_name}"
		eval "${s_name}=${dir}"
		mkdir "${!s_name}"
		defer rm -Rf "${!s_name}"
		chmod a+rwx "${!s_name}"
	done
}

with_socket()
{
	local s_name=$1; shift

	BBDD_SOCKET="${s_name}" "$@"
}

Bbdd()
{
	$(nspfx) "${bin_dir}/bbdd" --socket "${!BBDD_SOCKET}/bbdd.ctl" "$@"
}

Bbdd_bground()
{
	$(nspfx) "${bin_dir}/bbdd" --socket "${!BBDD_SOCKET}/bbdd.ctl" "$@" &
}

Bbdd_stop()
{
	local pid=$1; shift

	Bbdd -q echo
	if [[ $? != 0 ]]; then
		echo "bbdd already dead" >/dev/stderr
		return
	fi

	Bbdd -q stop
	if [[ $? != 0 ]]; then
		echo "couldn't issue bbdd stop" >/dev/stderr
		return
	fi

	slowwait 1 not Bbdd -q echo

	if [[ $? != 0 ]]; then
		echo "timeout waiting for bbdd to stop, killing" >/dev/stderr
		kill_process "$pid"
	fi
}

Bbdd_wait()
{
	slowwait 5 Bbdd -q echo

	if [[ $? != 0 ]]; then
		echo "failed to start bbdd" >/dev/stderr
		exit 1
	fi
}

adf_Bbdd_start()
{
	Bbdd --debug=mon-eager start &
	defer with_socket "$BBDD_SOCKET" Bbdd_stop $!

	Bbdd_wait
}

adf_Bbdd_bridge_start()
{
	Bbdd --debug=mon-eager \
	     bfdd bridge start unix:${!BBDD_SOCKET}/bfdd_dplane.sock &
	defer with_socket "$BBDD_SOCKET" Bbdd_stop $!

	Bbdd_wait
}

Bbdd_bfdd_connect()
{
	local dst_socket=$1; shift

	Bbdd bfdd connect unix:${!dst_socket}/bfdd_dplane.sock "$@"
}

Bbdd_bfdd_disconnect()
{
	local dst_socket=$1; shift

	Bbdd bfdd disconnect "$@"
}

Bbdd_session_get()
{
	local key=$1; shift

	Bbdd --json session "$@" show | jq -r ".sessions.[]$key"
}

Bbdd_session_local_state_is()
{
	local op=$1; shift
	local what=$1; shift
	local state

	state=$(Bbdd_session_get .state.local.state "$@")
	[ $state $op $what ]
}

Bbdd_session_remote_state_is()
{
	local op=$1; shift
	local what=$1; shift
	local state

	state=$(Bbdd_session_get .state.remote.state "$@")
	[ $state $op $what ]
}

Bbdd_session_state_is()
{
	local op=$1; shift
	local what=$1; shift
	local state

	Bbdd_session_local_state_is $op $what "$@" && \
		Bbdd_session_remote_state_is $op $what "$@"
}

Bbdd_session_bpf_state_is()
{
	local op=$1; shift
	local what=$1; shift
	local state

	state=$(Bbdd_session_get .state.bpf.bstate "$@")
	[ $state $op $what ]
}

Bbdd_session_bpf_state_stable()
{
	local state

	Bbdd_session_bpf_state_is == stable "$@"
	if (($? != 0)); then
		return 1
	fi

	# When the state is stable we also shouldn't be seeing qd_timing.
	state=$(Bbdd_session_get .state.bpf.qd_timing "$@")
	[ $state != true ]
}

Bbdd_session_wait()
{
	slowwait ${BBDD_SESSION_WAIT_TIME-2} "$@"
}

Bbdd_session_wait_local_down()
{
	Bbdd_session_wait Bbdd_session_local_state_is == down "$@"
}

Bbdd_session_wait_local_admindown()
{
	Bbdd_session_wait Bbdd_session_local_state_is == admindown "$@"
}

Bbdd_session_wait_up()
{
	Bbdd_session_wait Bbdd_session_state_is == up "$@"
}

Bbdd_session_wait_not_up()
{
	Bbdd_session_wait Bbdd_session_state_is != up "$@"
}

Bbdd_session_wait_bpf_stable()
{
	Bbdd_session_wait Bbdd_session_bpf_state_stable "$@"
}

Bbdd_session_wait_bpf_await_final()
{
	Bbdd_session_wait Bbdd_session_bpf_state_is == await-final "$@"
}

Bbdd_session_wait_bpf_await_non_final()
{
	Bbdd_session_wait Bbdd_session_bpf_state_is == await-non-final "$@"
}

Bbdd_session_wait_bpf_shutting_down()
{
	Bbdd_session_wait Bbdd_session_bpf_state_is == shutting-down "$@"
}

Bbdd_describe_env()
{
	format_env $(collect_env) "$BBDD_SOCKET"
}

Bbdd_log_test()
{
	log_test "$(Bbdd_describe_env)$1"
}

Bbdd_log_info()
{
	log_info "$(Bbdd_describe_env)$1"
}

Bbdd_log_head()
{
	echo
	Bbdd_log_info "$@"
	echo
}

session_state_check()
{
	local check=$1; shift
	local goal=$1; shift
	local should_fail=$((!goal))

	"Bbdd_session_wait_$check" "$@"
	check_err_fail "$should_fail" $? "session $check"
}

session_state_test()
{
	local check=$1; shift
	local goal=$1; shift
	local should_fail=$((!goal))
	local what="$@"

	session_state_check "$check" "$goal" "$@"
	Bbdd_log_test "session $what${what:+ }$(if ((should_fail)); then echo 'never '; fi)got $check"
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

	Bbdd_log_test "$xN ${descr}session$pl reported"
}

# Count sessions whose local & remote states both equal $goal.
Bbdd_nsessions_in_state()
{
	local goal=$1; shift

	Bbdd --json session show | jq "
		[.sessions[] |
		 select(.state.local.state == \"$goal\" and
			.state.remote.state == \"$goal\")] |
		 length"
}

Bbdd_nsessions_in_state_is()
{
	local goal=$1; shift
	local xN=$1; shift
	local N

	N=$(Bbdd_nsessions_in_state "$goal")
	((N == xN))
}

# Wait for exactly $xN sessions to reach $goal state. Single jq pass per
# poll, so this scales to many sessions.
nsessions_state_test()
{
	local goal=$1; shift
	local xN=$1; shift

	slowwait ${BBDD_SESSION_WAIT_TIME-2} \
		 Bbdd_nsessions_in_state_is "$goal" "$xN"
	check_err $? "$xN sessions reach $goal"

	Bbdd_log_test "$xN sessions reach $goal"
}

session_value_check()
{
	local key=$1; shift
	local value=$1; shift
	local out

	out=$(Bbdd --json session show | jq -r ".sessions[]$key")
	[[ "$out" == "$value" ]]
	check_err $? "$(Bbdd_describe_env)session value $key is $out, expected $value"
}

__echo_test()
{
	local t0
	local t1
	local rc
	local reported_lat
	local resp

	t0=$(now)
	resp=$(Bbdd --json "$@")
	rc=$?
	t1=$(now)
	check_err "$rc" "bbdd $@ exit code is $rc, 0 expected"

	reported_lat=$(echo "$resp" | jq '.reply_ts - .ts')
	measured_lat=$((t1 - t0))

	# This doesn't test much except that the value is not a complete
	# nonsense. Whatever we measure in bash is going to be orders of
	# magnitude worse than the actual thing. For the low limit, just
	# invent an arbitrary can't-be-this-fast limit.
	((reported_lat > 10))
	check_err $? "reported latency ($reported_lat) suspiciously low (measured $measured_lat)"
	((reported_lat < measured_lat / 2))
	check_err $? "reported latency ($reported_lat) suspiciously high (measured $measured_lat)"

	Bbdd_log_test "echo ($reported_lat us)"
}

__fail_echo_test()
{
	local t0
	local t1
	local rc
	local reported_lat
	local resp

	Bbdd -q "$@"
	rc=$?
	check_fail "$rc" "bbdd $@ exit code is $rc, != 0 expected"

	Bbdd_log_test "no echo"
}

echo_test()
{
	__echo_test echo
}

bfdd_echo_test()
{
	__echo_test bfdd echo
}

bfdd_fail_echo_test()
{
	__fail_echo_test bfdd echo
}

packet_size_test()
{
	local -a sel=("$@")

	# In live sessions, this is racy: if we collect the stats after packets
	# have been bumped, but before bytes have been bumped, we will get a
	# non-integer value and it all breaks.
	local pksizes=$(
		Bbdd --json session "${sel[@]}" stats |
			jq -j '.sessions[] | .stats |
			       (.rx_bytes / .rx_packets, " ",
				.tx_bytes / .tx_packets)'
	)
	local rx_pksize=${pksizes% *}
	local tx_pksize=${pksizes#* }

	((rx_pksize == tx_pksize))
	check_err $? "RX ($rx_pksize) and TX ($tx_pksize) packet sizes expected to be the same"

	# 14 bytes of Eth, 20+ bytes of IPv4, 8 bytes of UDP, 24 bytes BFD
	((rx_pksize >= 66))
	check_err $? "packet size suspiciously low $rx_pksize"

	# The packet could be larger for IPv4 with options, or for VLANs, or for
	# BFD authentication, but none of these should come up here. Only IPv6
	# which is 40 bytes.
	((rx_pksize <= 86))
	check_err $? "packet size suspiciously high $rx_pksize"

	Bbdd_log_test "Counters indicate reasonable packet size"
}

hold_time_test()
{
	local timeout=$1; shift
	local i

	for ((i = 0; i < timeout - 1; i++)); do
		BBDD_SESSION_WAIT_TIME=1 session_state_check up 0 "$@"
	done

	sleep 2

	session_state_test up 1 "$@"

	Bbdd_log_test "Hold time delays session creation"
}

__stats_consistency_test()
{
	local jqq=$1; shift
	local -a command=("$@")
	local what="${command[@]}"
	local found=0
	local out1
	local out2
	local i

	for ((i = 0; i < 10; i++)); do
		out1=$(Bbdd --json "${command[@]}" |
			       jq -r ".$jqq |"'
				      to_entries[] |
				      "\(.key): \(.value)"')
		[[ ! -z "$out1" ]]
		check_err "$?" "JSON output empty"

		out2=$(Bbdd "${command[@]}" |
			       sed '1d; s/^\t//')
		[[ ! -z "$out2" ]]
		check_err "$?" "non-JSON output empty"

		if [[ "$out1" == "$out2" ]]; then
			found=1
			break
		fi
	done

	((found == 1))
	check_err $? "different counters in json vs. non-json: ${out1} vs. ${out2}"

	Bbdd_log_test "$what: JSON & plain output consistent"
}

session_stats_consistency_test()
{
	__stats_consistency_test "sessions[].stats" session "$@" stats
}

session_diag_stats_consistency_test()
{
	__stats_consistency_test "sessions[].stats" session "$@" diag stats
}

global_diag_stats_consistency_test()
{
	__stats_consistency_test "" global diag stats
}

find_match()
{
	local out=$1; shift
	local match=$1; shift

	echo "$out" | grep -q -e "$match"
	check_err "$?" "$match not found"
}

find_no_match()
{
	local out=$1; shift
	local match=$1; shift

	echo "$out" | grep -q -e "$match"
	check_fail "$?" "$match found"
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

		local do_ping=1

		ip link add name "$ns1_link" netns "${!ns1_name}" type veth \
		   peer name "$ns2_link" netns "${!ns2_name}"
		defer in_ns "$ns1_name" Ip link del dev "$ns1_link"

		in_ns "$ns1_name" adf_ip_link_set_up "$ns1_link"
		in_ns "$ns2_name" adf_ip_link_set_up "$ns2_link"

		if [[ "$ns1_addr" != - ]]; then
			in_ns "$ns1_name" adf_ip_addr_add "$ns1_link" "$ns1_addr"
		else
			do_ping=0
		fi
		if [[ "$ns2_addr" != - ]]; then
			in_ns "$ns2_name" adf_ip_addr_add "$ns2_link" "$ns2_addr"
		else
			do_ping=0
		fi

		if ((do_ping)); then
			sleep 2
			in_ns "$ns1_name" ping_test "${ns2_addr%/*}"
			in_ns "$ns2_name" ping_test "${ns1_addr%/*}"
		fi
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

		sleep 2
		in_vrf "$vrf1_name" ping_test "${vrf2_addr%/*}"
		in_vrf "$vrf2_name" ping_test "${vrf1_addr%/*}"
	done
}

__Bbdd_IP4()
{
	local n=$1; shift

	echo "192.0.2.$n"
}

__Bbdd_IP4_mask()
{
	local n=$1; shift

	echo $(__Bbdd_IP4 "$n")/28
}

__Bbdd_IP6()
{
	local n=$1; shift

	echo "2001:db8:1::$n"
}

__Bbdd_IP6_mask()
{
	local n=$1; shift

	echo $(__Bbdd_IP6 "$n")/124
}

Bbdd_IP()
{
	__Bbdd_IP"$IPV" "$@"
}

Bbdd_IP_mask()
{
	__Bbdd_IP"$IPV"_mask "$@"
}
