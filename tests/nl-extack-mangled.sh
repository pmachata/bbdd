# SPDX-License-Identifier: GPL-2.0
root_require
require_command python3

# bbdd_nl_extack_attr() (src/bbdd-nl.c) used to feed NLMSGERR_ATTR_MSG's
# payload straight into a "%s" format without checking it's actually
# NUL-terminated (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING)). bbdd
# never checks who sent a netlink message either, and libmnl's seq/
# portid matching is a no-op when the forged message uses seq=0 and
# pid=0 -- so any local, unprivileged process can unicast a forged
# NLMSGERR to bbdd's own netlink portid (== its PID, visible via /proc)
# and make bbdd read past the end of a crafted, non-NUL-terminated
# attribute.
#
# bbdd only talks netlink at startup (creating its RX/TX veth pair) and
# shutdown (tearing it down). We inject once startup is done -- the
# socket is idle by then, so our unicast just sits queued -- and then
# stop the daemon: netlink delivery is FIFO, so our forged message is
# guaranteed to be the first thing bbdd's shutdown veth teardown reads.
# No timing race involved.
#
# We can't prove exactly how far the resulting OOB read runs -- that
# depends on adjacent heap contents -- but the read always *starts* at
# our attribute's first byte, so a marker placed there is a reliable,
# deterministic witness: present in bbdd's own error output if the bug
# is back, absent if the length is validated as it should be.

Bbdd_setup_ns NS1 NS2
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1

errlog="${tmpdir}/bbdd.stderr"
Bbdd_bground --debug=mon-eager start 2> "$errlog"
bbdd_pid=$!
defer with_socket "$BBDD_SOCKET" Bbdd_stop "$bbdd_pid"

Bbdd_wait

marker=BBDD_TEST_NL_EXTACK_MARKER

BBDD_NL_DST_PID="$bbdd_pid" Python3 - <<PYEOF
import os
import socket
import struct

NLMSG_ERROR = 0x2
NLM_F_CAPPED = 0x100
NLM_F_ACK_TLVS = 0x200
NLMSGERR_ATTR_MSG = 1

# Deliberately not NUL-terminated.
marker = b"$marker" + b"A" * 200

nlmsgerr = struct.pack("=i", -22) + b"\x00" * 16
attr = struct.pack("=HH", 4 + len(marker), NLMSGERR_ATTR_MSG) + marker
payload = nlmsgerr + attr
header = struct.pack("=IHHII", 16 + len(payload), NLMSG_ERROR,
                      NLM_F_CAPPED | NLM_F_ACK_TLVS, 0, 0)

dst_pid = int(os.environ["BBDD_NL_DST_PID"])
s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
s.sendto(header + payload, (dst_pid, 0))
PYEOF
check_err $? "Failed to inject forged netlink message"

Bbdd -q stop
check_err $? "Failed to ask daemon to stop"
wait "$bbdd_pid"

find_no_match "$(cat "$errlog")" "$marker"
Bbdd_log_test "forged netlink extack"
