/*
 * This program test IPv6 stuff: flowinfo.
 * Copyright: Catalin(ux) M. BOIE
 * Part of force_bind package
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
	int sock, err;
	struct sockaddr_storage ss;
	struct sockaddr_in6 sa, *sa2 = (struct sockaddr_in6 *) &ss;
	socklen_t ss_len;
	int port = 4444;
	char junk[128];
	char *dest = "::1";

	ss_len = sizeof(struct sockaddr_storage);

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket");
		return 1;
	}

	if (argc >= 2)
		dest = argv[1];

	if (argc >= 3)
		port = strtol(argv[2], NULL, 10);

	err = getsockname(sock, (struct sockaddr *) &ss, &ss_len);
	if (err != 0) {
		perror("getsockname");
		return 1;
	}
	fprintf(stderr, "Socket bound to %s/%d, flowinfo 0x%x.\n",
		inet_ntop(sa2->sin6_family, &sa2->sin6_addr, junk, ss_len),
		ntohs(sa2->sin6_port), ntohl(sa2->sin6_flowinfo));

	memset(&sa, 0, sizeof(struct sockaddr_in6));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(port);
	err = inet_pton(AF_INET6, dest, &sa.sin6_addr);
	if (err != 1) {
		perror("inet_pton");
		return 1;
	}

	err = connect(sock, (struct sockaddr *) &sa, sizeof(sa));
	if (err == -1) {
		perror("connect");
		/* ignore error */
	}

	err = getsockname(sock, (struct sockaddr *) &ss, &ss_len);
	if (err != 0) {
		perror("getsockname");
		return 1;
	}
	fprintf(stderr, "Socket bound to %s/%d, flowinfo 0x%x (after connect called).\n",
		inet_ntop(sa2->sin6_family, &sa2->sin6_addr, junk, ss_len),
		ntohs(sa2->sin6_port), ntohl(sa2->sin6_flowinfo));

	close(sock);

	return 0;
}
