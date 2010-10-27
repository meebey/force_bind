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
#include <errno.h>
#include <dirent.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>


static int	(*old_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static char	*force_address = NULL;
static int	force_port = -1;

/* Functions */

void init(void)
{
	static unsigned char inited = 0;
	char *x;

	if (inited == 1)
		return;

	inited = 1;

	x = getenv("FORCE_BIND_ADDRESS");
	if (x != NULL)
		force_address = x;

	x = getenv("FORCE_BIND_PORT");
	if (x != NULL)
		force_port = strtol(x, NULL, 10);

	syslog(LOG_INFO, "force_bind: Force bind to %s/%d.\n",
		force_address, force_port);

	old_bind = dlsym(RTLD_NEXT, "bind");
	if (old_bind == NULL) {
		syslog(LOG_ERR, "force_bind: Cannot resolve 'bind'!\n");
		exit(1);
	}
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int err;
	struct sockaddr new;
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	void *p = NULL;
	unsigned short *pport = NULL;

	init();

	if ((addr->sa_family != AF_INET) && (addr->sa_family != AF_INET6)) {
		syslog(LOG_INFO, "force_bind: unsupported family=%u!\n",
			addr->sa_family);
		return old_bind(sockfd, addr, addrlen);
	}

	memcpy(&new, addr, sizeof(struct sockaddr));

	switch (new.sa_family) {
		case AF_INET:
			sa4 = (struct sockaddr_in *) &new;
			p = &sa4->sin_addr;
			pport = &sa4->sin_port;
			break;

		case AF_INET6:
			sa6 = (struct sockaddr_in6 *) &new;
			p = &sa6->sin6_addr.s6_addr;
			pport = &sa6->sin6_port;
			break;
	}

	if (force_address != NULL) {
		err = inet_pton(new.sa_family, force_address, p);
		if (err != 1) {
			syslog(LOG_INFO, "force_bind: cannot convert [%s] (%d)!\n",
				force_address, err);
			return old_bind(sockfd, addr, addrlen);
		}
	}

	if (force_port != -1)
		*pport = htons(force_port);

	return old_bind(sockfd, &new, addrlen);
}
