# SPDX-License-Identifier: GPL-2.0
root_require
require_command python3

# RFC 5880 assigns meaning to BPF diag field values 0-8, but that does not
# exhaust the 5-bit physical format. Inject a packet with a value out of the
# specified bounds. The packet is unexpected and thus sent through the ring
# buffer. libbbdd.sh runs bbdd with --debug=mon-eager, which forces formatting
# of the ring buffer message, and prompts a crash, unless the out of bounds
# value is handled.

Bbdd_setup_ns NS1
in_ns NS1

Bbdd_setup_socket SD1
with_socket SD1
adf_Bbdd_start

Python3 - <<'PYEOF'
import socket
import struct

# version=1 (valid), diag=31 (valid on the wire, but past the 9-entry
# table). your-disc=0 so the packet is reported unconditionally,
# without needing a live session first.
version_diag = (1 << 5) | 0x1f
pkt = struct.pack("!BBBBIIIII", version_diag, 0, 1, 24,
		   0x12345678, 0, 0, 0, 0)

for port in (3784, 4784):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.sendto(pkt, ("127.0.0.1", port))
PYEOF
check_err $? "Failed to inject malformed BFD packet"

sleep 0.2 # Let bbdd process it before we probe.

with_socket SD1 Bbdd -q echo
check_err $? "daemon unresponsive after BFD packet with out-of-range diag"
Bbdd_log_test "daemon survives BFD packet with out-of-range diag"

Bbdd_log_test "Monitor handles out-of-range diag"
