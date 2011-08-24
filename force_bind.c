/*
 * Description: Force bind on a specified address
 * Author: Catalin(ux) M. BOIE
 * E-mail: catab at embedromix dot ro
 * Web: http://kernel.embedromix.ro/us/
 */

#define __USE_GNU
#define	_GNU_SOURCE
#define __USE_XOPEN2K
#define __USE_LARGEFILE64
#define __USE_FILE_OFFSET64

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifndef IPV6_FLOWINFO_SEND
#define IPV6_FLOWLABEL_MGR	32
#define IPV6_FLOWINFO_SEND	33

#define IPV6_FL_F_CREATE	1
#define IPV6_FL_A_GET		0
#define IPV6_FL_S_ANY		255

#define IPV6_FLOWINFO_MASK	0x0FFFFFFFUL
#define IPV6_FLOWLABEL_MASK	0x000FFFFFUL

struct in6_flowlabel_req {
	struct in6_addr flr_dst;
	unsigned int	flr_label;
	unsigned char	flr_action;
	unsigned char	flr_share;
	unsigned short	flr_flags;
	unsigned short	flr_expires;
	unsigned short	flr_linger;
	unsigned int	__flr_pad;
};
#endif

#define FB_FLAGS_NETSOCK 		(1 << 0)
#define FB_FLAGS_BIND_CALLED		(1 << 1)
#define FB_FLAGS_FLOWINFO_CALLED	(1 << 2)


struct private
{
	int			domain;
	int			type;
	unsigned int		flags;
	struct sockaddr_storage	dest;
	socklen_t		dest_len;

	/* bandwidth */
	unsigned long long	limit;
	unsigned long long	rest;
	struct timeval		last;
};

struct node
{
	int		fd;
	struct private	priv;
	struct node	*next;
};

struct info
{
	struct node	*head, *tail;
};


static int			(*old_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int			(*old_setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
static int			(*old_socket)(int domain, int type, int protocol);
static int			(*old_close)(int fd);
static ssize_t			(*old_write)(int fd, const void *buf, size_t len);
static ssize_t			(*old_send)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t			(*old_sendto)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
static ssize_t			(*old_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
static int			(*old_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int			(*old_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

static char			*force_address_v4 = NULL;
static char			*force_address_v6 = NULL;
static int			force_port_v4 = -1;
static int			force_port_v6 = -1;
static unsigned int		force_tos = 0, tos;
static unsigned int		force_ttl = 0, ttl;
static unsigned int		force_keepalive = 0, keepalive;
static unsigned int		force_mss = 0, mss;
static unsigned int		force_reuseaddr = 0, reuseaddr;
static unsigned int		force_nodelay = 0, nodelay;
static unsigned long long	bw_limit_per_socket = 0;
static unsigned int		force_flowinfo = 0, flowinfo;
static unsigned int		force_fwmark = 0, fwmark;
static unsigned int		force_prio = 0, prio;
static struct private		bw_global;
static struct info		fdinfo;
static unsigned int		verbose = 0;

/* glibc may not be up-to-date at compile time */
#ifndef SO_MARK
#define SO_MARK			36 /* only on some architectures */
#endif

/* Helper functions */
static int my_syslog(int priority, const char *format, ...)
{
	va_list ap;

	if (verbose == 0)
		return 0;

	va_start(ap, format);
	vsyslog(priority, format, ap);
	va_end(ap);

	return 0;
}

static void dump(const char *title, const void *buf, const unsigned int len)
{
	unsigned int i;
	unsigned char *buf2 = (unsigned char *) buf;
	char out[1024];

	for (i = 0; i < len; i++)
		snprintf(out + i * 3, 4, " %02x", buf2[i]);

	my_syslog(LOG_INFO, "force_bind: %s:%s\n", title, out);
}

static struct node *get(const int fd)
{
	struct node *p;

	p = fdinfo.head;
	while (p != NULL) {
		if (p->fd == fd)
			return p;

		p = p->next;
	}

	return NULL;
}

static void add(const int fd, const struct private *p)
{
	struct node *q;

	/* do we have a copy? */
	q = get(fd);
	if (q == NULL) {
		/* Try to find a free location */
		q = fdinfo.head;
		while (q != NULL) {
			if (q->fd == -1) {
				q->fd = fd;
				break;
			}

			q = q->next;
		}

		if (q == NULL) {
			q = (struct node *) malloc(sizeof(struct node));
			if (q == NULL) {
				my_syslog(LOG_INFO, "force_bind: Cannot alloc memory; ignore fd!\n");
				return;
			}

			q->next = NULL;
			q->fd = fd;
		}
	}
	memcpy(&q->priv, p, sizeof(struct private));

	/* Set bandwidth requirements */
	q->priv.limit = bw_limit_per_socket;
	if (bw_limit_per_socket > 0) {
		q->priv.rest = 0;
		gettimeofday(&q->priv.last, NULL);
	}

	if (fdinfo.tail == NULL) {
		fdinfo.head = q;
	} else {
		fdinfo.tail->next = q;
	}
	fdinfo.tail = q;
}

static void del(const int fd)
{
	struct node *p;

	p = fdinfo.head;
	while (p != NULL) {
		if (p->fd == fd) {
			p->fd = -1;
			return;
		}

		p = p->next;
	}
}


/* Functions */

static void init(void)
{
	static unsigned char inited = 0;
	char *x;

	if (inited == 1)
		return;

	inited = 1;

	fdinfo.head = NULL;
	fdinfo.tail = NULL;

	x = getenv("FORCE_NET_VERBOSE");
	if (x != NULL)
		verbose = strtol(x, NULL, 10);

	my_syslog(LOG_INFO, "force_bind: Init started...\n");

	x = getenv("FORCE_BIND_ADDRESS_V4");
	if (x != NULL) {
		force_address_v4 = x;
		my_syslog(LOG_INFO, "force_bind: Force bind to address %s.\n",
			force_address_v4);
	}

	x = getenv("FORCE_BIND_ADDRESS_V6");
	if (x != NULL) {
		force_address_v6 = x;
		my_syslog(LOG_INFO, "force_bind: Force bind to address %s.\n",
			force_address_v6);
	}

	/* obsolete mode */
	x = getenv("FORCE_BIND_ADDRESS");
	if (x != NULL) {
		force_address_v4 = x;
		force_address_v6 = x;
		my_syslog(LOG_INFO, "force_bind: Force bind to address %s."
			" Obsolete, use FORCE_BIND_ADDRESS_V4/6.\n",
			force_address_v4);
	}

	x = getenv("FORCE_BIND_PORT_V4");
	if (x != NULL) {
		force_port_v4 = strtol(x, NULL, 10);
		my_syslog(LOG_INFO, "force_bind: Force bind to port %d.\n",
			force_port_v4);
	}

	x = getenv("FORCE_BIND_PORT_V6");
	if (x != NULL) {
		force_port_v6 = strtol(x, NULL, 10);
		my_syslog(LOG_INFO, "force_bind: Force bind to port %d.\n",
			force_port_v6);
	}

	/* obsolete mode */
	x = getenv("FORCE_BIND_PORT");
	if (x != NULL) {
		force_port_v4 = strtol(x, NULL, 10);
		force_port_v6 = strtol(x, NULL, 10);
		my_syslog(LOG_INFO, "force_bind: Force bind to port %d."
			" Obsolete, use FORCE_BIND_PORT_V4/6.\n",
			force_port_v4);
	}

	/* tos */
	x = getenv("FORCE_NET_TOS");
	if (x != NULL) {
		force_tos = 1;
		tos = strtoul(x, NULL, 0);
		my_syslog(LOG_INFO, "force_bind: Force TOS to %hhu.\n",
			tos);
	}

	/* ttl */
	x = getenv("FORCE_NET_TTL");
	if (x != NULL) {
		force_ttl = 1;
		ttl = strtoul(x, NULL, 0);
		my_syslog(LOG_INFO, "force_bind: Force TTL to %hhu.\n",
			ttl);
	}

	/* keep alive */
	x = getenv("FORCE_NET_KA");
	if (x != NULL) {
		force_keepalive = 1;
		keepalive = strtoul(x, NULL, 0);
		my_syslog(LOG_INFO, "force_bind: Force KA to %u.\n",
			keepalive);
	}

	/* mss */
	x = getenv("FORCE_NET_MSS");
	if (x != NULL) {
		force_mss = 1;
		mss = strtoul(x, NULL, 0);
		my_syslog(LOG_INFO, "force_bind: Force MSS to %u.\n",
			mss);
	}

	/* REUSEADDR */
	x = getenv("FORCE_NET_REUSEADDR");
	if (x != NULL) {
		force_reuseaddr = 1;
		reuseaddr = strtoul(x, NULL, 0);
		my_syslog(LOG_INFO, "force_bind: Force REUSEADDR to %u.\n",
			reuseaddr);
	}

	/* NODELAY */
	x = getenv("FORCE_NET_NODELAY");
	if (x != NULL) {
		force_nodelay = 1;
		nodelay = strtoul(x, NULL, 0);
		my_syslog(LOG_INFO, "force_bind: Force NODELAY to %u.\n",
			nodelay);
	}

	/* bandwidth */
	x = getenv("FORCE_NET_BW");
	if (x != NULL) {
		bw_global.limit = strtoul(x, NULL, 0);
		gettimeofday(&bw_global.last, NULL);
		bw_global.rest = 0;
		my_syslog(LOG_INFO, "force_bind: Force bandwidth to %llub/s.\n",
			bw_global.limit);
	} else {
		bw_global.limit = 0;
	}

	/* bandwidth per socket */
	x = getenv("FORCE_NET_BW_PER_SOCKET");
	if (x != NULL) {
		if (bw_global.limit > 0) {
			my_syslog(LOG_INFO, "force_bind: Cannot set limit per socket"
				" when global one is set.\n");
		} else {
			bw_limit_per_socket = strtoul(x, NULL, 0);
			my_syslog(LOG_INFO, "force_bind: Force bandwidth per socket to %llub/s.\n",
				bw_limit_per_socket);
		}
	}

	/* IPv6 flowinfo */
	x = getenv("FORCE_NET_FLOWINFO");
	if (x != NULL) {
		force_flowinfo = 1;
		flowinfo = strtoul(x, NULL, 0) & IPV6_FLOWINFO_MASK;
		my_syslog(LOG_INFO, "force_bind: Force FLOWINFO to 0x%x.\n",
			flowinfo);
	}

	/* fwmark */
	x = getenv("FORCE_NET_FWMARK");
	if (x != NULL) {
		force_fwmark = 1;
		fwmark = strtoul(x, NULL, 0);
		my_syslog(LOG_INFO, "force_bind: Force fwmark to 0x%x.\n",
			fwmark);
	}

	/* prio */
	x = getenv("FORCE_NET_PRIO");
	if (x != NULL) {
		force_prio = 1;
		prio = strtoul(x, NULL, 0);
		my_syslog(LOG_INFO, "force_bind: Force prio to %u.\n",
			prio);
	}


	old_bind = dlsym(RTLD_NEXT, "bind");
	if (old_bind == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'bind'!\n");
		exit(1);
	}

	old_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
	if (old_setsockopt == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'setsockopt'!\n");
		exit(1);
	}

	old_socket = dlsym(RTLD_NEXT, "socket");
	if (old_socket == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'socket'!\n");
		exit(1);
	}

	old_close = dlsym(RTLD_NEXT, "close");
	if (old_close == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'close'!\n");
		exit(1);
	}

	old_write = dlsym(RTLD_NEXT, "write");
	if (old_write == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'write'!\n");
		exit(1);
	}

	old_send = dlsym(RTLD_NEXT, "send");
	if (old_send == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'send'!\n");
		exit(1);
	}

	old_sendto = dlsym(RTLD_NEXT, "sendto");
	if (old_sendto == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'sendto'!\n");
		exit(1);
	}

	old_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
	if (old_sendmsg == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'sendmsg'!\n");
		exit(1);
	}

	old_accept = dlsym(RTLD_NEXT, "accept");
	if (old_accept == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'accept'!\n");
		exit(1);
	}

	old_connect = dlsym(RTLD_NEXT, "connect");
	if (old_connect == NULL) {
		my_syslog(LOG_ERR, "force_bind: Cannot resolve 'connect'!\n");
		exit(1);
	}

	my_syslog(LOG_INFO, "force_bind: Init ended.\n");
}

static int set_ka(int sockfd)
{
	int flag, ret;

	if (force_keepalive == 0)
		return 0;

	flag = (keepalive > 0) ? 1 : 0;
	ret = old_setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
	my_syslog(LOG_INFO, "force_bind: changing SO_KEEPALIVE to %d (ret=%d(%s)) [%d].\n",
		flag, ret, strerror(errno), sockfd);

	return ret;
}

static int set_ka_idle(int sockfd)
{
	int ret;

	if (force_keepalive == 0)
		return 0;

	ret = old_setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive, sizeof(keepalive));
	my_syslog(LOG_INFO, "force_bind: changing TCP_KEEPIDLE to %us (ret=%d(%s)) [%d].\n",
		keepalive, ret, strerror(errno), sockfd);

	return ret;
}

static int set_mss(int sockfd)
{
	int ret;

	if (force_mss == 0)
		return 0;

	ret = old_setsockopt(sockfd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
	my_syslog(LOG_INFO, "force_bind: changing MSS to %u (ret=%d(%s)) [%d].\n",
		mss, ret, strerror(errno), sockfd);

	return ret;
}

static int set_tos(int sockfd)
{
	int ret;

	if (force_tos == 0)
		return 0;

	ret = old_setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
	my_syslog(LOG_INFO, "force_bind: changing TOS to %hhu (ret=%d(%s)) [%d].\n",
		tos, ret, strerror(errno), sockfd);

	return ret;
}

static int set_ttl(int sockfd)
{
	int ret;

	if (force_ttl == 0)
		return 0;

	ret = old_setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	my_syslog(LOG_INFO, "force_bind: changing TTL to %hhu (ret=%d(%s)) [%d].\n",
		ttl, ret, strerror(errno), sockfd);

	return ret;
}

static int set_reuseaddr(int sockfd)
{
	int ret;

	if (force_reuseaddr == 0)
		return 0;

	ret = old_setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
	my_syslog(LOG_INFO, "force_bind: changing reuseaddr to %u (ret=%d(%s)) [%d].\n",
		reuseaddr, ret, strerror(errno), sockfd);

	return ret;
}

static int set_nodelay(int sockfd)
{
	int ret;

	if (force_nodelay == 0)
		return 0;

	ret = old_setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
	my_syslog(LOG_INFO, "force_bind: changing nodelay to %u (ret=%d(%s)) [%d].\n",
		nodelay, ret, strerror(errno), sockfd);

	return ret;
}

/*
 * Set IPv6 flowinfo
 */
static void set_flowinfo(int sockfd, struct private *p)
{
	int ret;
	int yes;
	struct in6_flowlabel_req mgr;
	struct sockaddr_in6 *sa6;

	if (force_flowinfo == 0)
		return;

	if (p->domain != AF_INET6)
		return;

	if ((p->flags & FB_FLAGS_FLOWINFO_CALLED) != 0)
		return;

	/* In case of error we cannot do anything, anyway */
	p->flags |= FB_FLAGS_FLOWINFO_CALLED;

	/* Prepare flow */
	memset(&mgr, 0, sizeof(mgr));
	sa6 = (struct sockaddr_in6 *) &p->dest;
	memcpy(&mgr.flr_dst, &sa6->sin6_addr, sizeof(struct in6_addr));
	mgr.flr_label = htonl(flowinfo & IPV6_FLOWLABEL_MASK);
	mgr.flr_action = IPV6_FL_A_GET;
	mgr.flr_share = IPV6_FL_S_ANY;
	mgr.flr_flags = IPV6_FL_F_CREATE;
	ret = old_setsockopt(sockfd, SOL_IPV6, IPV6_FLOWLABEL_MGR, &mgr, sizeof(mgr));
	my_syslog(LOG_INFO, "force_bind: flow mgr (ret=%d(%s)) [%d].\n",
		ret, strerror(errno), sockfd);

	yes = 1;
	ret = old_setsockopt(sockfd, SOL_IPV6, IPV6_FLOWINFO_SEND, &yes, sizeof(yes));
	my_syslog(LOG_INFO, "force_bind: changing flowinfo to 'yes' (ret=%d(%s)) [%d].\n",
		ret, strerror(errno), sockfd);
}

static int set_fwmark(int sockfd)
{
	int ret;

	if (force_fwmark == 0)
		return 0;

	ret = old_setsockopt(sockfd, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark));
	my_syslog(LOG_INFO, "force_bind: changing fwmark to 0x%x (ret=%d(%s)) [%d].\n",
		fwmark, ret, strerror(errno), sockfd);

	return ret;
}

static int set_prio(int sockfd)
{
	int ret;

	if (force_prio == 0)
		return 0;

	ret = old_setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
	my_syslog(LOG_INFO, "force_bind: changing fwmark to 0x%x (ret=%d(%s)) [%d].\n",
		prio, ret, strerror(errno), sockfd);

	return ret;
}

/*
 * Alters a struct sockaddr, based on environment variables
 */
static void alter_sa(const int sockfd, struct sockaddr *sa)
{
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	unsigned short *pport = NULL;
	void *p;
	char *force_address;
	int force_port;
	int err;

	switch (sa->sa_family) {
	case AF_INET:
		sa4 = (struct sockaddr_in *) sa;
		p = &sa4->sin_addr;
		pport = &sa4->sin_port;
		force_address = force_address_v4;
		force_port = force_port_v4;
		break;

	case AF_INET6:
		sa6 = (struct sockaddr_in6 *) sa;
		p = &sa6->sin6_addr.s6_addr;
		pport = &sa6->sin6_port;
		force_address = force_address_v6;
		force_port = force_port_v6;
		break;

	default:
		my_syslog(LOG_INFO, "force_bind: unsupported family=%u [%d]!\n",
			sa->sa_family, sockfd);
		return;
	}

	if (force_address != NULL) {
		err = inet_pton(sa->sa_family, force_address, p);
		if (err != 1) {
			my_syslog(LOG_INFO, "force_bind: cannot convert [%s] (%d) (%s) [%d]!\n",
				force_address, err, strerror(errno), sockfd);
			return;
		}
	}

	if (force_port != -1)
		*pport = htons(force_port);
}

/*
 * Alter destination sa
 */
static void alter_dest_sa(int sockfd, struct sockaddr_storage *ss, socklen_t len)
{
	struct node *q;
	struct sockaddr *sa = (struct sockaddr *) ss;
	struct sockaddr_in6 *sa6;

	init();

	/* We do not touch non network sockets */
	q = get(sockfd);
	if ((q == NULL) || ((q->priv.flags & FB_FLAGS_NETSOCK) == 0))
		return;

	switch (sa->sa_family) {
	case AF_INET6:
		sa6 = (struct sockaddr_in6 *) sa;
		if (force_flowinfo == 1) {
			my_syslog(LOG_INFO, "force_bind: changing flowinfo from 0x%x to 0x%x [%d]!\n",
				ntohl(sa6->sin6_flowinfo), flowinfo, sockfd);
			sa6->sin6_flowinfo = htonl(flowinfo);
		}
		break;
	}

	memcpy(&q->priv.dest, ss, len);
	q->priv.dest_len = len;

	set_flowinfo(sockfd, &q->priv);
}

/*
 * Alter local binding by doing a forced 'bind' call.
 * This is called before calling connect and before using sendto/sendmsg.
 */
static void change_local_binding(int sockfd)
{
	int err;
	struct node *q;
	struct sockaddr_storage tmp;
	socklen_t tmp_len;

	init();

	/* We do not touch non network sockets */
	q = get(sockfd);
	if ((q == NULL) || ((q->priv.flags & FB_FLAGS_NETSOCK) == 0))
		return;

	/* We do not touch already binded sockets */
	if ((q->priv.flags & FB_FLAGS_BIND_CALLED) != 0)
		return;

	tmp_len = sizeof(struct sockaddr_storage);
	err = getsockname(sockfd, (struct sockaddr *) &tmp, &tmp_len);
	if (err != 0) {
		my_syslog(LOG_INFO, "force_bind: Cannot get socket name err=%d (%s) [%d]!\n",
			err, strerror(errno), sockfd);
		return;
	}
	alter_sa(sockfd, (struct sockaddr *) &tmp);
	err = old_bind(sockfd, (struct sockaddr *) &tmp, tmp_len);
	q->priv.flags |= FB_FLAGS_BIND_CALLED;
	if (err != 0)
		my_syslog(LOG_INFO, "force_bind: Cannot bind err=%d (%s)  [%d]!\n",
			err, strerror(errno), sockfd);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct node *q;
	struct sockaddr_storage new;

	memcpy(&new, addr, addrlen);

	init();

	/* We do not touch non network sockets */
	q = get(sockfd);
	if ((q != NULL) && ((q->priv.flags & FB_FLAGS_NETSOCK) != 0)) {
		alter_sa(sockfd, (struct sockaddr *) &new);
		q->priv.flags |= FB_FLAGS_BIND_CALLED;
	}

	return old_bind(sockfd, (struct sockaddr *) &new, addrlen);
}

int setsockopt(int sockfd, int level, int optname, const void *optval,
	socklen_t optlen)
{
	init();

	if (level == SOL_SOCKET) {
		if (optname == SO_KEEPALIVE)
			return set_ka(sockfd);
		if (optname == SO_REUSEADDR)
			return set_reuseaddr(sockfd);
		if (optname == SO_MARK)
			return set_fwmark(sockfd);
		if (optname == SO_PRIORITY)
			return set_prio(sockfd);
	}

	if (level == IPPROTO_IP) {
		if (optname == IP_TOS)
			return set_tos(sockfd);
		if (optname == IP_TTL)
			return set_ttl(sockfd);
	}

	if (level == IPPROTO_TCP) {
		if (optname == TCP_KEEPIDLE)
			return set_ka_idle(sockfd);
		if (optname == TCP_MAXSEG)
			return set_mss(sockfd);
		if (optname == TCP_NODELAY)
			return set_nodelay(sockfd);
	}

	return old_setsockopt(sockfd, level, optname, optval, optlen);
}

/*
 * Helper called when a socket is created: socket, accept
 */
void socket_create_callback(const int sockfd, int domain, int type)
{
	struct private p;

	init();

	set_tos(sockfd);
	set_ttl(sockfd);
	set_ka(sockfd);
	if (type == SOCK_STREAM)
		set_ka_idle(sockfd);
	set_mss(sockfd);
	set_reuseaddr(sockfd);
	set_nodelay(sockfd);
	set_fwmark(sockfd);
	set_prio(sockfd);

	p.domain = domain;
	p.type = type;
	p.flags = FB_FLAGS_NETSOCK;
	memset(&p.dest, 0, sizeof(struct sockaddr_storage));
	p.dest_len = 0;
	add(sockfd, &p);
}

/*
 * 'socket' is hijacked to be able to call setsockopt on it.
 */
int socket(int domain, int type, int protocol)
{
	int sockfd;

	init();

	sockfd = old_socket(domain, type, protocol);
	if (sockfd == -1)
		return -1;

	socket_create_callback(sockfd, domain, type);

	return sockfd;
}

/*
 * Enforce bandwidth
 */
static void bw(const int sockfd, const ssize_t bytes)
{
	struct timeval now;
	struct timespec ts, rest;
	long long allowed;
	long long diff_ms, sleep_ms;
	int err;
	struct node *q;
	struct private *p;

	if (bytes <= 0)
		return;

	/* Is a network socket? */
	q = get(sockfd);
	if (q == NULL)
		return;

	p = &q->priv;
	if ((p->flags & FB_FLAGS_NETSOCK) == 0)
		return;

	if (p->limit == 0) {
		if (bw_global.limit == 0)
			return;
		p = &bw_global;
	}

	gettimeofday(&now, NULL);

	diff_ms = (now.tv_sec - p->last.tv_sec) * 1000
		+ (now.tv_usec - p->last.tv_usec) / 1000;
	if (diff_ms < 0)
		return;

	allowed = p->rest + p->limit * diff_ms / 1000;
	p->last = now;

	/*
	printf("diff_ms=%lld rest=%llu bytes=%u allowed=%llub\n",
		diff_ms, p->rest, bytes, allowed);
	*/

	if (bytes <= allowed) {
		p->rest = allowed - bytes;
		/*printf("\tInside limit, rest=%llu.\n", p->rest);*/
		return;
	}

	p->rest = 0;
	sleep_ms = (bytes - allowed) * 1000 / p->limit;

	/* Do not count, next time, the time spent in sleep! */
	p->last.tv_sec += sleep_ms / 1000;
	p->last.tv_usec += (sleep_ms % 1000) * 1000;

	ts.tv_sec = sleep_ms / 1000;
	ts.tv_nsec = (sleep_ms % 1000) * 1000 * 1000;
	/*printf("\tWe will sleep %lus %lunsec.\n", ts.tv_sec, ts.tv_nsec);*/

	/* We try to sleep even if we are interrupted by signals */
	while (1) {
		err = nanosleep(&ts, &rest);
		if (err == -1) {
			if (errno == EINTR) {
				ts = rest;
				continue;
			}

			my_syslog(LOG_INFO, "force_bind: nanosleep returned error"
				" (%d) (%s).\n",
				err, strerror(errno));
		}

		break;
	}
}

int close(int fd)
{
	init();

	del(fd);

	return old_close(fd);
}

ssize_t write(int fd, const void *buf, size_t len)
{
	ssize_t n;

	n = old_write(fd, buf, len);
	bw(fd, n);

	return n;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	ssize_t n;

	n = old_send(sockfd, buf, len, flags);
	bw(sockfd, n);

	return n;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t n;
	struct sockaddr_storage new_dest;

	change_local_binding(sockfd);

	memcpy(&new_dest, dest_addr, addrlen);
	alter_dest_sa(sockfd, &new_dest, addrlen);

	n = old_sendto(sockfd, buf, len, flags, (struct sockaddr *) &new_dest, addrlen);
	bw(sockfd, n);

	return n;
}

/*
 * TODO: Add sendmmsg
 */
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	ssize_t n;
	/* see below
	struct sockaddr_storage new_dest;
	*/

	change_local_binding(sockfd);

	/* TODO: how do we alter flowinfo in this case?!
	memcpy(&new_dest, dest, addrlen);
	alter_dest_sa(sockfd, &new_dest, addrlen);
	*/

	n = old_sendmsg(sockfd, msg, flags);
	bw(sockfd, n);

	return n;
}

/*
 * We have to hijack accept because this program may be a daemon.
 * TODO: accept4 should also be hijacked.
 */
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int new_sock;
	struct node *q;
	struct private *p;

	init();

	new_sock = old_accept(sockfd, addr, addrlen);
	if (new_sock == -1)
		return -1;

	/* We must find out domain and type for accepting socket */
	q = get(sockfd);
	if (q != NULL) {
		p = &q->priv;

		socket_create_callback(new_sock, p->domain, p->type);
	}

	return new_sock;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_storage new_dest;

	change_local_binding(sockfd);

	memcpy(&new_dest, addr, addrlen);
	alter_dest_sa(sockfd, &new_dest, addrlen);

	return old_connect(sockfd, (struct sockaddr *) &new_dest, addrlen);
}

