// SPDX-License-Identifier: GPL-2.0+
#include "bbdd-nl.h"

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libmnl/libmnl.h>
#include <linux/ethtool_netlink.h>
#include <linux/genetlink.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

#include "bbdd-sock.h"
#include "bbdd-util.h"

struct bbdd_nl {
	struct mnl_socket *sk;
	struct mnl_socket *genl_sk;
	uint16_t ethtool_family;
	size_t bufsize;
	char buf[];
};

static char *bbdd_nl_buf(struct bbdd_nl *nl)
{
	return nl->buf;
}

struct bbdd_nl_cb {
	char **error;
};

static int bbdd_mnl_cb_noop(const struct nlmsghdr *, void *)
{
	return MNL_CB_OK;
}

static int bbdd_mnl_cb_error(const struct nlmsghdr *nlh, void *)
{
	//xxx for extack: struct bbdd_nl_cb *cb = data;
	const struct nlmsgerr *err;

	if (mnl_nlmsg_get_payload_len(nlh) < sizeof(*err))
		return MNL_CB_STOP;
	err = mnl_nlmsg_get_payload(nlh);

	/* Netlink subsystems returns the errno value with different signess */
	if (err->error < 0)
		errno = -err->error;
	else
		errno = err->error;

	// xxx extack

	return err->error == 0 ? MNL_CB_STOP : MNL_CB_ERROR;
}

static int bbdd_mnl_cb_stop(const struct nlmsghdr *nlh, void *)
{
	int len;

	if (mnl_nlmsg_get_payload_len(nlh) < sizeof(len))
		return MNL_CB_STOP;

	len = *(int *)mnl_nlmsg_get_payload(nlh);
	if (len < 0) {
		errno = -len;
		// xxx extack
		return MNL_CB_ERROR;
	}

	return MNL_CB_STOP;
}

static mnl_cb_t bbdd_mnl_cb_array[NLMSG_MIN_TYPE] = {
	[NLMSG_NOOP]	= bbdd_mnl_cb_noop,
	[NLMSG_ERROR]	= bbdd_mnl_cb_error,
	[NLMSG_DONE]	= bbdd_mnl_cb_stop,
	[NLMSG_OVERRUN]	= bbdd_mnl_cb_noop,
};

static int bbdd_socket_recv_run(struct bbdd_nl *nl, struct mnl_socket *sk,
				unsigned int seq, mnl_cb_t cb, void *cb_data)
{
	unsigned int portid = mnl_socket_get_portid(sk);
	char *buf = bbdd_nl_buf(nl);
	size_t bufsize = nl->bufsize;
	ssize_t rc;

	do {
		rc = mnl_socket_recvfrom(sk, buf, bufsize);
		if (rc <= 0)
			break;
		rc = mnl_cb_run2(buf, (size_t) rc, seq, portid,
				 cb, cb_data,
				 bbdd_mnl_cb_array,
				 ARRAY_SIZE(bbdd_mnl_cb_array));
	} while (rc > 0);

	return (int) rc;
}

static struct mnl_socket *bbdd_nl_socket_open(int bus)
{
	struct mnl_socket *nl;
	int one = 1;

	nl = mnl_socket_open(bus);
	if (nl == NULL)
		return NULL;

	mnl_socket_setsockopt(nl, NETLINK_CAP_ACK, &one, sizeof(one));
	mnl_socket_setsockopt(nl, NETLINK_EXT_ACK, &one, sizeof(one));

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		goto socket_close;

	return nl;

socket_close:
	mnl_socket_close(nl);
	return NULL;
}

static int bbdd_nl_ethtool_family_attr(const struct nlattr *attr, void *data)
{
	if (mnl_attr_get_type(attr) == CTRL_ATTR_FAMILY_ID)
		*(uint16_t *) data = mnl_attr_get_u16(attr);
	return MNL_CB_OK;
}

static int bbdd_nl_ethtool_family_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), bbdd_nl_ethtool_family_attr, data);
	return MNL_CB_OK;
}

static int bbdd_nl_resolve_ethtool(struct bbdd_nl *nl)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	uint16_t family_id = 0;
	ssize_t rc;

	nlh = mnl_nlmsg_put_header(bbdd_nl_buf(nl));
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = (uint32_t) time(NULL);

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(*genl));
	genl->cmd = CTRL_CMD_GETFAMILY;
	genl->version = 1;

	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, ETHTOOL_GENL_NAME);

	rc = mnl_socket_sendto(nl->genl_sk, nlh, nlh->nlmsg_len);
	if (rc < 0)
		return -1;

	rc = bbdd_socket_recv_run(nl, nl->genl_sk, nlh->nlmsg_seq,
				  bbdd_nl_ethtool_family_cb, &family_id);
	if (rc < 0)
		return -1;

	return family_id;
}

struct bbdd_nl *bbdd_nl_create(void)
{
	struct bbdd_nl *nl;
	size_t bufsize;
	long sz;
	int err;

	/* The macro MNL_SOCKET_BUFFER_SIZE involves sysconf() calls. */
	sz = MNL_SOCKET_BUFFER_SIZE;
	if (sz < 0) {
		fprintf(stderr, "Failed to determine netlink socket buffer size: %m");
		return NULL;
	}

	bufsize = (unsigned long) sz;
	nl = malloc(sizeof(*nl) + bufsize);
	if (nl == NULL)
		return NULL;

	nl->bufsize = bufsize;
	nl->sk = bbdd_nl_socket_open(NETLINK_ROUTE);
	if (nl->sk == NULL) {
		fprintf(stderr, "Failed to open netlink socket: %m");
		goto free_nl;
	}

	nl->genl_sk = bbdd_nl_socket_open(NETLINK_GENERIC);
	if (nl->genl_sk == NULL) {
		fprintf(stderr, "Failed to open generic netlink socket: %m");
		goto close_sk;
	}

	err = bbdd_nl_resolve_ethtool(nl);
	if (err < 0) {
		fprintf(stderr, "Failed to resolve ethtool netlink family: %m");
		goto close_genl_sk;
	}
	nl->ethtool_family = (uint16_t) err;

	return nl;

close_genl_sk:
	mnl_socket_close(nl->genl_sk);
close_sk:
	mnl_socket_close(nl->sk);
free_nl:
	free(nl);
	return NULL;
}

void bbdd_nl_destroy(struct bbdd_nl *nl)
{
	mnl_socket_close(nl->genl_sk);
	mnl_socket_close(nl->sk);
	free(nl);
}

static int bbdd_nl_maybe_get_ifindex(uint32_t *ifindex, const char *name,
				     char **error)
{
	if (!ifindex)
		return 0;

	*ifindex = if_nametoindex(name);
	if (!*ifindex) {
		bbdd_util_fmterr(error, "Failed to find ifindex of a just-created interface `%s'",
				 name);
		return -1;
	}

	return 0;
}

int bbdd_nl_add_veth(struct bbdd_nl *nl,
		     const char *name, uint32_t *ifindex,
		     const char *peer_name, uint32_t *peer_ifindex,
		     char **error)
{
	struct nlattr *linkinfo, *infodata, *peer_attr;
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	ssize_t rc;

	nlh = mnl_nlmsg_put_header(bbdd_nl_buf(nl));
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = (NLM_F_REQUEST | NLM_F_CREATE |
			    NLM_F_EXCL | NLM_F_ACK);
	nlh->nlmsg_seq = (uint32_t) time(NULL);

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;

	mnl_attr_put_strz(nlh, IFLA_IFNAME, name);

	linkinfo = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "veth");

	infodata = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);

	peer_attr = mnl_attr_nest_start(nlh, VETH_INFO_PEER);
	mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	mnl_attr_put_strz(nlh, IFLA_IFNAME, peer_name);
	mnl_attr_nest_end(nlh, peer_attr);

	mnl_attr_nest_end(nlh, infodata);

	mnl_attr_nest_end(nlh, linkinfo);

	rc = mnl_socket_sendto(nl->sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to send netlink message: %m");
		return -1;
	}

	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL, NULL);
	if (rc < 0) {
		bbdd_util_fmterr(error,
				 "Failed to create veth pair `%s'<->`%s': %m",
				 name, peer_name);
		return -1;
	}

	if (bbdd_nl_maybe_get_ifindex(ifindex, name, error) < 0 ||
	    bbdd_nl_maybe_get_ifindex(peer_ifindex, peer_name, error) < 0)
		return -1;

	return 0;
}

int bbdd_nl_del_if(struct bbdd_nl *nl, const char *name, char **error)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	ssize_t rc;

	nlh = mnl_nlmsg_put_header(bbdd_nl_buf(nl));
	nlh->nlmsg_type = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = (uint32_t) time(NULL);

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;

	mnl_attr_put_strz(nlh, IFLA_IFNAME, name);

	rc = mnl_socket_sendto(nl->sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to send netlink message: %m");
		return -1;
	}

	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL, NULL);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to delete interface `%s': %m",
				 name);
		return -1;
	}

	return 0;
}

int bbdd_nl_set_if_up(struct bbdd_nl *nl, uint32_t ifindex, char **error)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	ssize_t rc;

	nlh = mnl_nlmsg_put_header(bbdd_nl_buf(nl));
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = (uint32_t) time(NULL);

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = (int)ifindex;
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = IFF_UP;

	rc = mnl_socket_sendto(nl->sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to send netlink message: %m");
		return -1;
	}

	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL, NULL);
	if (rc < 0) {
		bbdd_util_fmterr(error,
				 "Failed to bring up interface %u: %m",
				 ifindex);
		return -1;
	}

	return 0;
}

int bbdd_nl_add_qdisc(struct bbdd_nl *nl,
		      uint32_t ifindex, uint32_t parent,
		      uint16_t handle, const char *kind, char **error)
{
	struct nlmsghdr *nlh;
	struct tcmsg *tc;
	ssize_t rc;

	nlh = mnl_nlmsg_put_header(bbdd_nl_buf(nl));
	nlh->nlmsg_type = RTM_NEWQDISC;
	nlh->nlmsg_flags = (NLM_F_REQUEST | NLM_F_CREATE |
			    NLM_F_EXCL | NLM_F_ACK);
	nlh->nlmsg_seq = (uint32_t) time(NULL);

	tc = mnl_nlmsg_put_extra_header(nlh, sizeof(*tc));
	tc->tcm_family = AF_UNSPEC;
	tc->tcm_ifindex = (int) ifindex;
	tc->tcm_handle = ((uint32_t) handle) << 16;
	tc->tcm_parent = parent;

	mnl_attr_put_strz(nlh, TCA_KIND, kind);

	rc = mnl_socket_sendto(nl->sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to send netlink message: %m");
		return -1;
	}

	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL, NULL);
	if (rc < 0) {
		bbdd_util_fmterr(error,
				 "Failed to create `%s' qdisc on ifindex %u: %m",
				 kind, ifindex);
		return -1;
	}

	return 0;
}

uint32_t bbdd_nl_tc_h_root(void)
{
	return TC_H_ROOT;
}

int bbdd_nl_refresh_neigh(struct bbdd_nl *nl, uint32_t ifindex,
			  const struct bbdd_sockaddr *addr, char **error)
{
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	const void *raw_addr;
	size_t addr_len;
	ssize_t rc;

	nlh = mnl_nlmsg_put_header(bbdd_nl_buf(nl));
	nlh->nlmsg_type = RTM_NEWNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
	nlh->nlmsg_seq = (uint32_t) time(NULL);

	ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
	ndm->ndm_family = (uint8_t) addr->sa.sa_family;
	ndm->ndm_ifindex = (int) ifindex;
	ndm->ndm_state = NUD_INCOMPLETE;
	ndm->ndm_flags = NTF_USE;

	raw_addr = bbdd_sockaddr_addrbuf(addr, &addr_len, error);
	if (raw_addr == NULL)
		return -EAFNOSUPPORT;

	mnl_attr_put(nlh, NDA_DST, addr_len, raw_addr);

	rc = mnl_socket_sendto(nl->sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to send RTM_NEWNEIGH: %m");
		return -errno;
	}

	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL, NULL);
	if (rc < 0) {
		if (errno == EEXIST)
			return 0;
		bbdd_util_fmterr(error, "Failed to refresh neighbor: %m");
		return -1;
	}

	return 0;
}

int bbdd_nl_set_channels(struct bbdd_nl *nl, uint32_t ifindex,
			 unsigned int nqueues, char **error)
{
	struct nlattr *header;
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	ssize_t rc;

	nlh = mnl_nlmsg_put_header(bbdd_nl_buf(nl));
	nlh->nlmsg_type = nl->ethtool_family;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = (uint32_t) time(NULL);

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(*genl));
	genl->cmd = ETHTOOL_MSG_CHANNELS_SET;
	genl->version = ETHTOOL_GENL_VERSION;

	header = mnl_attr_nest_start(nlh, ETHTOOL_A_CHANNELS_HEADER);
	mnl_attr_put_u32(nlh, ETHTOOL_A_HEADER_DEV_INDEX, ifindex);
	mnl_attr_nest_end(nlh, header);

	mnl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_TX_COUNT, nqueues);
	mnl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_RX_COUNT, nqueues);
	mnl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_COMBINED_COUNT, 0);

	rc = mnl_socket_sendto(nl->genl_sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to send netlink message: %m");
		return -1;
	}

	rc = bbdd_socket_recv_run(nl, nl->genl_sk, nlh->nlmsg_seq, NULL, NULL);
	if (rc < 0) {
		bbdd_util_fmterr(error,
				 "Failed to set channels on ifindex %u: %m",
				 ifindex);
		return -1;
	}

	return 0;
}
