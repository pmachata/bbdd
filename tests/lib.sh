# SPDX-License-Identifier: GPL-2.0

##############################################################################
# Defines

: "${WAIT_TIMEOUT:=20}"

# Whether to pause on after a failure.
: "${PAUSE_ON_FAIL:=no}"

BUSYWAIT_TIMEOUT=$((WAIT_TIMEOUT * 1000)) # ms

# Kselftest framework constants.
ksft_pass=0
ksft_fail=1
ksft_xfail=2
ksft_skip=4

# namespace list created by setup_ns
NS_LIST=()

# Exit status to return at the end. Set in case one of the tests fails.
EXIT_STATUS=0
# Per-test return value. Clear at the beginning of each test.
RET=0

##############################################################################
# Helpers

__ksft_status_merge()
{
	local a=$1; shift
	local b=$1; shift
	local -A weights
	local weight=0

	local i
	for i in "$@"; do
		weights[$i]=$((weight++))
	done

	if [[ ${weights[$a]} -ge ${weights[$b]} ]]; then
		echo "$a"
		return 0
	else
		echo "$b"
		return 1
	fi
}

ksft_status_merge()
{
	local a=$1; shift
	local b=$1; shift

	__ksft_status_merge "$a" "$b" \
		$ksft_pass $ksft_xfail $ksft_skip $ksft_fail
}

ksft_exit_status_merge()
{
	local a=$1; shift
	local b=$1; shift

	__ksft_status_merge "$a" "$b" \
		$ksft_xfail $ksft_pass $ksft_skip $ksft_fail
}

loopy_wait()
{
	local sleep_cmd=$1; shift
	local timeout_ms=$1; shift

	local start_time="$(date -u +%s%3N)"
	while true
	do
		local out
		if out=$("$@"); then
			echo -n "$out"
			return 0
		fi

		local current_time="$(date -u +%s%3N)"
		if ((current_time - start_time > timeout_ms)); then
			echo -n "$out"
			return 1
		fi

		$sleep_cmd
	done
}

busywait()
{
	local timeout_ms=$1; shift

	loopy_wait : "$timeout_ms" "$@"
}

# timeout in seconds
slowwait()
{
	local timeout_sec=$1; shift

	loopy_wait "sleep 0.1" "$((timeout_sec * 1000))" "$@"
}

not()
{
	"$@"
	[[ $? != 0 ]]
}

val()
{
	echo "$@"
}

binary_op()
{
	local op=$1; shift

	local -a lhs=()
	while [[ $# > 0 ]]; do
		arg=$1; shift

		if [[ "$arg" == , ]]; then
			break
		fi

		lhs[${#lhs[@]}]=$arg
	done

	local L=$("${lhs[@]}")
	local R=$("$@")
	[ "$L" "$op" "$R" ]
}

eq()
{
	binary_op == "$@"
}

until_counter_is()
{
	local expr=$1; shift
	local current=$("$@")

	echo $((current))
	((current $expr))
}

busywait_for_counter()
{
	local timeout=$1; shift
	local delta=$1; shift

	local base=$("$@")
	busywait "$timeout" until_counter_is ">= $((base + delta))" "$@"
}

slowwait_for_counter()
{
	local timeout=$1; shift
	local delta=$1; shift

	local base=$("$@")
	slowwait "$timeout" until_counter_is ">= $((base + delta))" "$@"
}

# Check for existence of tools which are built as part of selftests
# but may also already exist in $PATH
check_gen_prog()
{
	local prog_name=$1; shift

	if ! which $prog_name >/dev/null 2>/dev/null; then
		PATH=$PWD:$PATH
		if ! which $prog_name >/dev/null; then
			echo "'$prog_name' command not found; skipping tests"
			exit $ksft_skip
		fi
	fi
}

remove_ns_list()
{
	local item=$1
	local ns
	local ns_list=("${NS_LIST[@]}")
	NS_LIST=()

	for ns in "${ns_list[@]}"; do
		if [ "${ns}" != "${item}" ]; then
			NS_LIST+=("${ns}")
		fi
	done
}

cleanup_ns()
{
	local ns=""
	local ret=0

	for ns in "$@"; do
		[ -z "${ns}" ] && continue
		ip netns pids "${ns}" 2> /dev/null | xargs -r kill || true
		ip netns delete "${ns}" &> /dev/null || true
		if ! busywait $BUSYWAIT_TIMEOUT ip netns list \| grep -vq "^$ns$" &> /dev/null; then
			echo "Warn: Failed to remove namespace $ns"
			ret=1
		else
			remove_ns_list "${ns}"
		fi
	done

	return $ret
}

cleanup_all_ns()
{
	cleanup_ns "${NS_LIST[@]}"
}

# setup netns with given names as prefix. e.g
# setup_ns local remote
setup_ns()
{
	local ns_name=""
	local ns_list=()
	for ns_name in "$@"; do
		# avoid conflicts with local var: internal error
		if [ "${ns_name}" = "ns_name" ]; then
			echo "Failed to setup namespace '${ns_name}': invalid name"
			cleanup_ns "${ns_list[@]}"
			exit $ksft_fail
		fi

		# Some test may setup/remove same netns multi times
		if [ -z "${!ns_name}" ]; then
			eval "${ns_name}=${ns_name,,}-$(mktemp -u XXXXXX)"
		else
			cleanup_ns "${!ns_name}"
		fi

		if ! ip netns add "${!ns_name}"; then
			echo "Failed to create namespace $ns_name"
			cleanup_ns "${ns_list[@]}"
			return $ksft_skip
		fi
		ip -n "${!ns_name}" link set lo up
		ip netns exec "${!ns_name}" sysctl -wq net.ipv4.conf.all.rp_filter=0
		ip netns exec "${!ns_name}" sysctl -wq net.ipv4.conf.default.rp_filter=0
		ns_list+=("${!ns_name}")
	done
	NS_LIST+=("${ns_list[@]}")
}

in_all_ns()
{
	local ret=0
	local ns_list=("${NS_LIST[@]}")

	for ns in "${ns_list[@]}"; do
		ip netns exec "${ns}" "$@"
		(( ret = ret || $? ))
	done

	return "${ret}"
}

# Create netdevsim with given id and net namespace.
create_netdevsim() {
    local id="$1"
    local ns="$2"

    modprobe netdevsim &> /dev/null
    udevadm settle

    echo "$id 1" | ip netns exec $ns tee /sys/bus/netdevsim/new_device >/dev/null
    local dev=$(ip netns exec $ns ls /sys/bus/netdevsim/devices/netdevsim$id/net)
    ip -netns $ns link set dev $dev name nsim$id
    ip -netns $ns link set dev nsim$id up

    echo nsim$id
}

create_netdevsim_port() {
    local nsim_id="$1"
    local ns="$2"
    local port_id="$3"
    local perm_addr="$4"
    local orig_dev
    local new_dev
    local nsim_path

    nsim_path="/sys/bus/netdevsim/devices/netdevsim$nsim_id"

    echo "$port_id $perm_addr" | ip netns exec "$ns" tee "$nsim_path"/new_port > /dev/null || return 1

    orig_dev=$(ip netns exec "$ns" find "$nsim_path"/net/ -maxdepth 1 -name 'e*' | tail -n 1)
    orig_dev=$(basename "$orig_dev")
    new_dev="nsim${nsim_id}p$port_id"

    ip -netns "$ns" link set dev "$orig_dev" name "$new_dev"
    ip -netns "$ns" link set dev "$new_dev" up

    echo "$new_dev"
}

# Remove netdevsim with given id.
cleanup_netdevsim() {
    local id="$1"

    if [ -d "/sys/bus/netdevsim/devices/netdevsim$id/net" ]; then
        echo "$id" > /sys/bus/netdevsim/del_device
    fi
}

tc_rule_stats_get()
{
	local dev=$1; shift
	local pref=$1; shift
	local dir=${1:-ingress}; shift
	local selector=${1:-.packets}; shift

	tc -j -s filter show dev $dev $dir pref $pref \
	    | jq ".[] | select(.options.actions) |
		  .options.actions[].stats$selector"
}

tc_rule_handle_stats_get()
{
	local id=$1; shift
	local handle=$1; shift
	local selector=${1:-.packets}; shift
	local netns=${1:-""}; shift

	tc $netns -j -s filter show $id \
	    | jq ".[] | select(.options.handle == $handle) | \
		  .options.actions[0].stats$selector"
}

# attach a qdisc with two children match/no-match and a flower filter to match
tc_set_flower_counter() {
	local -r ns=$1
	local -r ipver=$2
	local -r dev=$3
	local -r flower_expr=$4

	tc -n $ns qdisc add dev $dev root handle 1: prio bands 2 \
			priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

	tc -n $ns qdisc add dev $dev parent 1:1 handle 11: pfifo
	tc -n $ns qdisc add dev $dev parent 1:2 handle 12: pfifo

	tc -n $ns filter add dev $dev parent 1: protocol ipv$ipver \
			flower $flower_expr classid 1:2
}

tc_get_flower_counter() {
	local -r ns=$1
	local -r dev=$2

	tc -n $ns -j -s qdisc show dev $dev handle 12: | jq .[0].packets
}

ret_set_ksft_status()
{
	local ksft_status=$1; shift
	local msg=$1; shift

	RET=$(ksft_status_merge $RET $ksft_status)
	if (( $? )); then
		retmsg=$msg
	fi
}

log_test_result()
{
	local test_name=$1; shift
	local opt_str=$1; shift
	local result=$1; shift
	local retmsg=$1

	printf "TEST: %-60s  [%s]\n" "$test_name $opt_str" "$result"
	if [[ $retmsg ]]; then
		printf "\t%s\n" "$retmsg"
	fi
}

pause_on_fail()
{
	if [[ $PAUSE_ON_FAIL == yes ]]; then
		echo "Hit enter to continue, 'q' to quit"
		read a
		[[ $a == q ]] && exit 1
	fi
}

handle_test_result_pass()
{
	local test_name=$1; shift
	local opt_str=$1; shift

	log_test_result "$test_name" "$opt_str" " OK "
}

handle_test_result_fail()
{
	local test_name=$1; shift
	local opt_str=$1; shift

	log_test_result "$test_name" "$opt_str" FAIL "$retmsg"
	pause_on_fail
}

handle_test_result_xfail()
{
	local test_name=$1; shift
	local opt_str=$1; shift

	log_test_result "$test_name" "$opt_str" XFAIL "$retmsg"
	pause_on_fail
}

handle_test_result_skip()
{
	local test_name=$1; shift
	local opt_str=$1; shift

	log_test_result "$test_name" "$opt_str" SKIP "$retmsg"
}

log_test()
{
	local test_name=$1
	local opt_str=$2
	local ret

	if [[ $# -eq 2 ]]; then
		opt_str="($opt_str)"
	fi

	if ((RET == ksft_pass)); then
		handle_test_result_pass "$test_name" "$opt_str"
	elif ((RET == ksft_xfail)); then
		handle_test_result_xfail "$test_name" "$opt_str"
	elif ((RET == ksft_skip)); then
		handle_test_result_skip "$test_name" "$opt_str"
	else
		handle_test_result_fail "$test_name" "$opt_str"
	fi

	EXIT_STATUS=$(ksft_exit_status_merge $EXIT_STATUS $RET)
	ret="$RET"
	RET=0
	return "$ret"
}

log_test_skip()
{
	RET=$ksft_skip retmsg= log_test "$@"
}

log_test_xfail()
{
	RET=$ksft_xfail retmsg= log_test "$@"
}

log_info()
{
	local msg=$1

	echo "INFO: $msg"
}

tests_run()
{
	local current_test

	for current_test in ${TESTS:-$ALL_TESTS}; do
		in_defer_scope \
			$current_test
	done
}

# Whether FAILs should be interpreted as XFAILs. Internal.
FAIL_TO_XFAIL=

check_err()
{
	local err=$1
	local msg=$2

	if ((err)); then
		if [[ $FAIL_TO_XFAIL = yes ]]; then
			ret_set_ksft_status $ksft_xfail "$msg"
		else
			ret_set_ksft_status $ksft_fail "$msg"
		fi
	fi
}

check_fail()
{
	local err=$1
	local msg=$2

	check_err $((!err)) "$msg"
}

check_err_fail()
{
	local should_fail=$1; shift
	local err=$1; shift
	local what=$1; shift

	if ((should_fail)); then
		check_fail $err "$what succeeded, but should have failed"
	else
		check_err $err "$what failed"
	fi
}

xfail()
{
	FAIL_TO_XFAIL=yes "$@"
}

xfail_on_slow()
{
	if [[ $KSFT_MACHINE_SLOW = yes ]]; then
		FAIL_TO_XFAIL=yes "$@"
	else
		"$@"
	fi
}

omit_on_slow()
{
	if [[ $KSFT_MACHINE_SLOW != yes ]]; then
		"$@"
	fi
}

xfail_on_veth()
{
	local dev=$1; shift
	local kind

	kind=$(ip -j -d link show dev $dev |
			jq -r '.[].linkinfo.info_kind')
	if [[ $kind = veth ]]; then
		FAIL_TO_XFAIL=yes "$@"
	else
		"$@"
	fi
}

mac_get()
{
	local if_name=$1

	Ip -j link show dev "$if_name" | jq -r '.[]["address"]'
}

kill_process()
{
	local pid=$1; shift

	# Suppress noise from killing the process.
	{ kill $pid && wait $pid; } 2>/dev/null
}

check_command()
{
	local cmd=$1; shift

	if [[ ! -x "$(command -v "$cmd")" ]]; then
		log_test_skip "$cmd not installed"
		return $EXIT_STATUS
	fi
}

require_command()
{
	local cmd=$1; shift

	if ! check_command "$cmd"; then
		exit $EXIT_STATUS
	fi
}

adf_ip_link_add()
{
	local name=$1; shift

	Ip link add name "$name" "$@" && \
		Defer Ip link del dev "$name"
}

adf_ip_link_set_master()
{
	local member=$1; shift
	local master=$1; shift

	Ip link set dev "$member" master "$master" && \
		Defer Ip link set dev "$member" nomaster
}

adf_ip_link_set_addr()
{
	local name=$1; shift
	local addr=$1; shift

	local old_addr=$(mac_get "$name")
	Ip link set dev "$name" address "$addr" && \
		Defer Ip link set dev "$name" address "$old_addr"
}

ip_link_has_flag()
{
	local name=$1; shift
	local flag=$1; shift

	local state=$(Ip -j link show "$name" |
		      jq --arg flag "$flag" 'any(.[].flags[]; . == $flag)')
	[[ $state == true ]]
}

ip_link_is_up()
{
	local name=$1; shift

	ip_link_has_flag "$name" UP
}

adf_ip_link_set_up()
{
	local name=$1; shift

	if ! ip_link_is_up "$name"; then
		Ip link set dev "$name" up && \
			Defer Ip link set dev "$name" down
	fi
}

adf_ip_link_set_down()
{
	local name=$1; shift

	if ip_link_is_up "$name"; then
		Ip link set dev "$name" down && \
			Defer Ip link set dev "$name" up
	fi
}

ip_link_ifindex()
{
	local name=$1; shift

	Ip -j link show dev "$name" | jq '.[].ifindex'
}

adf_ip_addr_add()
{
	local name=$1; shift

	Ip addr add dev "$name" "$@" && \
		Defer Ip addr del dev "$name" "$@"
}

adf_ip_route_add()
{
	Ip route add "$@" && \
		Defer Ip route del "$@"
}

wait_local_port_listen()
{
	local listener_ns="${1}"
	local port="${2}"
	local protocol="${3}"
	local pattern
	local i

	pattern=":$(printf "%04X" "${port}") "

	# for tcp protocol additionally check the socket state
	[ ${protocol} = "tcp" ] && pattern="${pattern}0A"
	for i in $(seq 10); do
		if ip netns exec "${listener_ns}" awk '{print $2" "$4}' \
		   /proc/net/"${protocol}"* | grep -q "${pattern}"; then
			break
		fi
		sleep 0.1
	done
}

cmd_jq()
{
	local cmd=$1
	local jq_exp=$2
	local jq_opts=$3
	local ret
	local output

	output="$($cmd)"
	# it the command fails, return error right away
	ret=$?
	if [[ $ret -ne 0 ]]; then
		return $ret
	fi
	output=$(echo $output | jq -r $jq_opts "$jq_exp")
	ret=$?
	if [[ $ret -ne 0 ]]; then
		return $ret
	fi
	echo $output
	# return success only in case of non-empty output
	[ ! -z "$output" ]
}

Ip()
{
	$(nspfx) ip "$@"
}

Sysctl()
{
	$(nspfx) sysctl "$@"
}

in_ns()
{
	local NS=$1; shift

	IN_NS="${NS}" "$@"
}

Defer()
{
	local maybe_ns
	local maybe_vrf

	if [[ ! -z "$IN_NS" ]]; then
		maybe_ns="in_ns $IN_NS"
	fi
	if [[ ! -z "$IN_VRF" ]]; then
		maybe_vrf="in_vrf $IN_VRF"
	fi

	defer $maybe_ns $maybe_vrf "$@"
}

in_vrf()
{
	local VRF=$1; shift

	IN_VRF="$VRF" "$@"
}

nspfx()
{
	if [[ ! -z "$IN_NS" ]]; then
		echo "ip netns exec ${!IN_NS}"
	fi
}

vrfpfx()
{
	if [[ ! -z "$IN_VRF" ]]; then
		echo "ip vrf exec $IN_VRF"
	fi
}

declare -A SYSCTL_ORIG
sysctl_save()
{
	local sysctl=$1; shift
	local key=$IN_NS,$sysctl

	SYSCTL_ORIG[$key]=$(Sysctl -n $sysctl)
}

sysctl_set()
{
	local sysctl=$1; shift
	local value=$1; shift

	sysctl_save "$sysctl"
	Sysctl -qw $sysctl="$value"
}

sysctl_restore()
{
	local sysctl=$1; shift
	local key=$IN_NS,$sysctl

	Sysctl -qw $sysctl="${SYSCTL_ORIG[$key]}"
}

forwarding_enable()
{
	sysctl_set net.ipv4.conf.all.forwarding 1
	sysctl_set net.ipv6.conf.all.forwarding 1
}

forwarding_restore()
{
	sysctl_restore net.ipv6.conf.all.forwarding
	sysctl_restore net.ipv4.conf.all.forwarding
}

adf_forwarding_enable()
{
	forwarding_enable
	Defer forwarding_restore
}

vrf_prepare()
{
	Ip -4 rule add pref 32765 table local
	Ip -4 rule del pref 0
	Ip -6 rule add pref 32765 table local
	Ip -6 rule del pref 0
}

vrf_cleanup()
{
	Ip -6 rule add pref 0 table local
	Ip -6 rule del pref 32765
	Ip -4 rule add pref 0 table local
	Ip -4 rule del pref 32765
}

adf_vrf_prepare()
{
	vrf_prepare
	defer in_ns ${IN_NS} vrf_cleanup
}

__last_tb_id=0
declare -A __TB_IDS

__vrf_td_id_assign()
{
	local vrf_name=$1

	__last_tb_id=$((__last_tb_id + 1))
	__TB_IDS[$vrf_name]=$__last_tb_id
	return $__last_tb_id
}

__vrf_td_id_lookup()
{
	local vrf_name=$1

	return ${__TB_IDS[$vrf_name]}
}

vrf_create()
{
	local vrf_name=$1
	local tb_id

	__vrf_td_id_assign $vrf_name
	tb_id=$?

	Ip link add dev $vrf_name type vrf table $tb_id
	Ip -4 route add table $tb_id unreachable default metric 4278198272
	Ip -6 route add table $tb_id unreachable default metric 4278198272
}

vrf_destroy()
{
	local vrf_name=$1
	local tb_id

	__vrf_td_id_lookup $vrf_name
	tb_id=$?

	Ip -6 route del table $tb_id unreachable default metric 4278198272
	Ip -4 route del table $tb_id unreachable default metric 4278198272
	Ip link del dev $vrf_name
}

adf_vrf_create()
{
	local vrf_name=$1

	vrf_create "$vrf_name" && \
		Defer vrf_destroy "$vrf_name"
}

collect_env()
{
	echo "$IN_NS" "$IN_VRF"
}

format_env()
{
	local -a items=("$@")
	local str
	local item

	for item in "${items[@]}"; do
		str="$str$item "
	done

	str=${str% }
	echo "${str}${str:+: }"
}

describe_env()
{
	format_env $(collect_env)
}

Ping()
{
	$(nspfx) $(vrfpfx) $PING "$@"
}

ping_test()
{
	local dip=$1; shift

	Ping -c "$PING_COUNT" -i 0.01 -w "$PING_TIMEOUT" "$dip" &> /dev/null
	check_err $?
	log_test "$(describe_env)ping $dip"
}

now()
{
	date +%s%6N
}
