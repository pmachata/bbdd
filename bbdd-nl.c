// SPDX-License-Identifier: GPL-2.0+
#include "bbdd-nl.h"

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libmnl/libmnl.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

#include "bbdd-sock.h"
#include "bbdd-util.h"

struct bbdd_nl {
	struct mnl_socket *sk;
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

static int bbdd_nl_extack_attr(const struct nlattr *attr, void *data)
{
	struct bbdd_nl_cb *cb = data;

	if (mnl_attr_get_type(attr) == NLMSGERR_ATTR_MSG)
		bbdd_util_fmterr(cb->error, "%s", mnl_attr_get_str(attr));
	return MNL_CB_OK;
}

static int bbdd_mnl_cb_error(const struct nlmsghdr *nlh, void *data)
{
	const struct nlmsgerr *err;
	size_t hdrlen;

	if (mnl_nlmsg_get_payload_len(nlh) < sizeof(*err))
		return MNL_CB_STOP;
	err = mnl_nlmsg_get_payload(nlh);

	/* Netlink subsystems returns the errno value with different signess */
	if (err->error < 0)
		errno = -err->error;
	else
		errno = err->error;

	if (err->error != 0 && (nlh->nlmsg_flags & NLM_F_ACK_TLVS)) {
		hdrlen = sizeof(*err);
		if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
			hdrlen += NLMSG_ALIGN(err->msg.nlmsg_len - NLMSG_HDRLEN);
		mnl_attr_parse(nlh, hdrlen, bbdd_nl_extack_attr, data);
	}

	return err->error == 0 ? MNL_CB_STOP : MNL_CB_ERROR;
}

static int bbdd_mnl_cb_stop(const struct nlmsghdr *nlh, void *data)
{
	int len;

	if (mnl_nlmsg_get_payload_len(nlh) < sizeof(len))
		return MNL_CB_STOP;

	len = *(int *)mnl_nlmsg_get_payload(nlh);
	if (len < 0) {
		errno = -len;
		if (nlh->nlmsg_flags & NLM_F_ACK_TLVS)
			mnl_attr_parse(nlh, sizeof(len),
				       bbdd_nl_extack_attr, data);
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

struct bbdd_nl *bbdd_nl_create(void)
{
	struct bbdd_nl *nl;
	size_t bufsize;
	long sz;

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

	return nl;

free_nl:
	free(nl);
	return NULL;
}

void bbdd_nl_destroy(struct bbdd_nl *nl)
{
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
		     unsigned int nqueues,
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
	mnl_attr_put_u32(nlh, IFLA_NUM_TX_QUEUES, nqueues);
	mnl_attr_put_u32(nlh, IFLA_NUM_RX_QUEUES, nqueues);

	linkinfo = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "veth");

	infodata = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);

	peer_attr = mnl_attr_nest_start(nlh, VETH_INFO_PEER);
	mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	mnl_attr_put_strz(nlh, IFLA_IFNAME, peer_name);
	mnl_attr_put_u32(nlh, IFLA_NUM_TX_QUEUES, nqueues);
	mnl_attr_put_u32(nlh, IFLA_NUM_RX_QUEUES, nqueues);
	mnl_attr_nest_end(nlh, peer_attr);

	mnl_attr_nest_end(nlh, infodata);

	mnl_attr_nest_end(nlh, linkinfo);

	rc = mnl_socket_sendto(nl->sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to send netlink message: %m");
		return -1;
	}

	*error = NULL;
	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL,
				 &(struct bbdd_nl_cb){ .error = error });
	if (rc < 0) {
		bbdd_util_wraperr(error,
				  "Failed to create veth pair `%s'<->`%s': %m, `%s'",
				  name, peer_name, *error ?: "");
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

	*error = NULL;
	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL,
				 &(struct bbdd_nl_cb){ .error = error });
	if (rc < 0) {
		bbdd_util_wraperr(error, "Failed to delete interface `%s': %m, `%s'",
				  name, *error ?: "");
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

	*error = NULL;
	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL,
				 &(struct bbdd_nl_cb){ .error = error });
	if (rc < 0) {
		bbdd_util_wraperr(error,
				  "Failed to bring up interface %u: %m, `%s'",
				  ifindex, *error ?: "");
		return -1;
	}

	return 0;
}

static int __bbdd_nl_add_qdisc(struct bbdd_nl *nl,
			       uint32_t ifindex, uint32_t parent,
			       uint16_t handle, const char *kind,
			       void (*fill_ats_cb)(struct nlmsghdr *nlh),
			       char **error)
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

	if (fill_ats_cb != NULL)
		fill_ats_cb(nlh);

	rc = mnl_socket_sendto(nl->sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to send netlink message: %m");
		return -1;
	}

	*error = NULL;
	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL,
				 &(struct bbdd_nl_cb){ .error = error });
	if (rc < 0) {
		bbdd_util_wraperr(error,
				  "Failed to create `%s' qdisc on ifindex %u: %m, `%s'",
				  kind, ifindex, *error ?: "");
		return -1;
	}

	return 0;
}

int bbdd_nl_add_qdisc(struct bbdd_nl *nl,
		      uint32_t ifindex, uint32_t parent, uint16_t handle,
		      const char *kind, char **error)
{
	return __bbdd_nl_add_qdisc(nl, ifindex, parent, handle, kind, NULL,
				   error);
}

static void bbdd_nl_add_qdisc_fq_fill_ats(struct nlmsghdr *nlh)
{
	struct nlattr *opts = mnl_attr_nest_start(nlh, TCA_OPTIONS);

	mnl_attr_put_u32(nlh, TCA_FQ_ORPHAN_MASK, 0xffffffff);
	mnl_attr_nest_end(nlh, opts);
}

int bbdd_nl_add_qdisc_fq(struct bbdd_nl *nl,
			 uint32_t ifindex, uint32_t parent, uint32_t handle,
			 char **error)
{
	return __bbdd_nl_add_qdisc(nl, ifindex, parent, handle, "fq",
				   bbdd_nl_add_qdisc_fq_fill_ats, error);
}

uint32_t bbdd_nl_tc_h_root(void)
{
	return TC_H_ROOT;
}

struct bbdd_nl_vrf_table_cb {
	struct bbdd_nl_cb base;
	struct bbdd_nl_ifinfo *info;
};

static int bbdd_nl_vrf_infodata_attr(const struct nlattr *attr, void *data)
{
	struct bbdd_nl_vrf_table_cb *cb = data;

	if (mnl_attr_get_type(attr) == IFLA_VRF_TABLE &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) >= 0)
		cb->info->table = mnl_attr_get_u32(attr);
	return MNL_CB_OK;
}

struct bbdd_nl_vrf_linkinfo_ctx {
	const char *kind;
	const struct nlattr *infodata;
};

static int bbdd_nl_vrf_linkinfo_attr(const struct nlattr *attr, void *data)
{
	struct bbdd_nl_vrf_linkinfo_ctx *ctx = data;

	switch (mnl_attr_get_type(attr)) {
	case IFLA_INFO_KIND:
		ctx->kind = mnl_attr_get_str(attr);
		break;
	case IFLA_INFO_DATA:
		ctx->infodata = attr;
		break;
	}
	return MNL_CB_OK;
}

static int bbdd_nl_vrf_link_attr(const struct nlattr *attr, void *data)
{
	struct bbdd_nl_vrf_linkinfo_ctx ctx = {};
	struct bbdd_nl_vrf_table_cb *cb = data;

	switch (mnl_attr_get_type(attr)) {
	case IFLA_MASTER:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) >= 0)
			cb->info->master = mnl_attr_get_u32(attr);
		break;
	case IFLA_LINKINFO:
		mnl_attr_parse_nested(attr, bbdd_nl_vrf_linkinfo_attr, &ctx);
		if (ctx.kind && strcmp(ctx.kind, "vrf") == 0 && ctx.infodata)
			mnl_attr_parse_nested(ctx.infodata,
					      bbdd_nl_vrf_infodata_attr, cb);
		break;
	}
	return MNL_CB_OK;
}

static int bbdd_nl_vrf_table_cb_fn(const struct nlmsghdr *nlh, void *data)
{
	const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*ifi), bbdd_nl_vrf_link_attr, data);
	return MNL_CB_OK;
}

int bbdd_nl_get_ifinfo(struct bbdd_nl *nl, uint32_t ifindex,
		       struct bbdd_nl_ifinfo *info, char **error)
{
	struct bbdd_nl_vrf_table_cb cb = {
		.base = { .error = error },
		.info = info,
	};
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	ssize_t rc;

	*info = (struct bbdd_nl_ifinfo){};

	nlh = mnl_nlmsg_put_header(bbdd_nl_buf(nl));
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = (uint32_t) time(NULL);

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = (int)ifindex;

	rc = mnl_socket_sendto(nl->sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_util_fmterr(error, "Failed to send RTM_GETLINK: %m");
		return -1;
	}

	*error = NULL;
	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq,
				  bbdd_nl_vrf_table_cb_fn, &cb);
	if (rc < 0) {
		bbdd_util_wraperr(error,
				  "Failed to get link info for ifindex %u: %m, `%s'",
				  ifindex, *error ?: "");
		return -1;
	}

	return 0;
}

int bbdd_nl_get_vrf_table(struct bbdd_nl *nl, uint32_t ifindex,
			  uint32_t *table, char **error)
{
	struct bbdd_nl_ifinfo ifinfo;
	int rc;

	rc = bbdd_nl_get_ifinfo(nl, ifindex, &ifinfo, error);
	if (rc != 0)
		return rc;

	if (ifinfo.table == 0) {
		bbdd_util_fmterr(error, "Interface %u is not a VRF device",
				 ifindex);
		return -1;
	}

	*table = ifinfo.table;
	return 0;
}

int bbdd_nl_get_l3_master(struct bbdd_nl *nl, uint32_t ifindex,
			  uint32_t *table, char **error)
{
	uint32_t current = ifindex;

	/* Arbitrarily cut off, because very deep chains are more likely an
	 * error than anything else. A reasonable nesting could be something
	 * like eth-lag-vlan-bridge-vrf, five iterations. I'm giving 2x of that
	 * just to be on the safe side, but I don't really see how this would
	 * look like and still be reasonable. */
	for (int depth = 0; depth < 10; depth++) {
		struct bbdd_nl_ifinfo info;
		int rc;

		rc = bbdd_nl_get_ifinfo(nl, current, &info, error);
		if (rc != 0)
			return rc;

		if (info.table != 0) {
			*table = info.table;
			return 0;
		}

		if (info.master == 0) {
			*table = 0;
			return 0;
		}

		current = info.master;
	}

	bbdd_util_fmterr(error, "Master chain for ifindex %u is too deep",
			 ifindex);
	return -1;
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

	*error = NULL;
	rc = bbdd_socket_recv_run(nl, nl->sk, nlh->nlmsg_seq, NULL,
				 &(struct bbdd_nl_cb){ .error = error });
	if (rc < 0) {
		if (errno == EEXIST) {
			free(*error);
			*error = NULL;
			return 0;
		}
		bbdd_util_wraperr(error, "Failed to refresh neighbor: %m, `%s'",
				  *error ?: "");
		return -1;
	}

	return 0;
}
