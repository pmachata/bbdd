// SPDX-License-Identifier: GPL-2.0+
#include "bbdd-nl.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libmnl/libmnl.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

#include "bbdd-jrpc.h"

struct bbdd_nl {
	struct mnl_socket *sk;
	size_t bufsize;
	char buf[];
};

static char *bbdd_nl_buf(struct bbdd_nl *nl)
{
	return nl->buf;
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

static int bbdd_socket_recv_run(struct bbdd_nl *nl, unsigned int seq,
				mnl_cb_t cb, void *cb_data)
{
	unsigned int portid = mnl_socket_get_portid(nl->sk);
	char *buf = bbdd_nl_buf(nl);
	size_t bufsize = nl->bufsize;
	ssize_t rc;

	do {
		rc = mnl_socket_recvfrom(nl->sk, buf, bufsize);
		if (rc <= 0)
			break;
		rc = mnl_cb_run2(buf, (size_t) rc, seq, portid,
				 cb, cb_data,
				 bbdd_mnl_cb_array,
				 ARRAY_SIZE(bbdd_mnl_cb_array));
	} while (rc > 0);

	return (int) rc;
}

struct bbdd_nl_list_ifs {
	struct bbdd_nl_cb base;
	struct bbdd_nl_if *ifs;
	size_t nifs;
	size_t cap;
};

static int bbdd_nl_list_ifs_attr(const struct nlattr *attr, void *attr_data)
{
	struct bbdd_nl_if *entry = attr_data;

	if (mnl_attr_get_type(attr) == IFLA_IFNAME)
		strncpy(entry->ifname, mnl_attr_get_str(attr),
			sizeof(entry->ifname) - 1);
	return MNL_CB_OK;
}

static int bbdd_nl_list_ifs_cb(const struct nlmsghdr *nlh, void *cb_data)
{
	struct bbdd_nl_list_ifs *data = cb_data;
	struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	struct bbdd_nl_if entry = {
		.ifindex = (uint32_t) ifi->ifi_index,
	};
	struct bbdd_nl_if *new_ifs;
	int rc;

	rc = mnl_attr_parse(nlh, sizeof(struct ifinfomsg),
			    bbdd_nl_list_ifs_attr, &entry);
	if (rc != MNL_CB_OK)
		return rc;

	if (entry.ifname[0] == '\0') {
		bbdd_jrpc_fmterr(data->base.error,
				 "Netlink gave no name for interface with ifindex `%d'",
				 entry.ifindex);
		errno = EPROTO;
		return MNL_CB_ERROR;
	}

	if (data->nifs >= data->cap) {
		size_t new_cap = data->cap ? data->cap * 2 : 8;

		new_ifs = realloc(data->ifs, new_cap * sizeof(*new_ifs));
		if (!new_ifs) {
			errno = ENOMEM;
			return MNL_CB_ERROR;
		}
		data->ifs = new_ifs;
		data->cap = new_cap;
	}

	data->ifs[data->nifs++] = entry;
	return MNL_CB_OK;
}

int bbdd_nl_list_ifs(struct bbdd_nl *nl, struct bbdd_nl_if **p_ifs,
		     size_t *p_nifs, char **error)
{
	struct bbdd_nl_list_ifs cb_data;
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	ssize_t rc;

	nlh = mnl_nlmsg_put_header(bbdd_nl_buf(nl));
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = (uint32_t) time(NULL);

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_PACKET;

	rc = mnl_socket_sendto(nl->sk, nlh, nlh->nlmsg_len);
	if (rc < 0) {
		bbdd_jrpc_fmterr(error, "Failed to send netlink message: %m");
		return -1;
	}

	cb_data = (struct bbdd_nl_list_ifs) {
		.base = {
			.error = error,
		},
	};
	errno = 0;
	rc = bbdd_socket_recv_run(nl, nlh->nlmsg_seq,
				  bbdd_nl_list_ifs_cb, &cb_data);
	if (rc < 0) {
		free(cb_data.ifs);
		if (!errno)
			bbdd_jrpc_fmterr(error, "Failed to obtain list of interfaces: %m");
		return -1;
	}

	*p_ifs = cb_data.ifs;
	*p_nifs = cb_data.nifs;
	return 0;
}

int bbdd_nl_add_veth(struct bbdd_nl *nl, const char *name,
		     const char *peer_name, char **error)
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
		bbdd_jrpc_fmterr(error, "Failed to send netlink message: %m");
		return -1;
	}

	rc = bbdd_socket_recv_run(nl, nlh->nlmsg_seq, NULL, NULL);
	if (rc < 0) {
		bbdd_jrpc_fmterr(error,
				 "Failed to create veth pair `%s'<->`%s': %m",
				 name, peer_name);
		return -1;
	}

	return 0;
}
