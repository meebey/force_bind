/*
 * This program test socket->connect binding
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
	struct sockaddr_in sa, sa2;
	socklen_t sa_len;
	int port = 4444;
	char junk[128];
	char *dest = "127.0.0.1";

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket");
		return 1;
	}

	if (argc >= 2)
		dest = argv[1];

	if (argc >= 3)
		port = strtol(argv[2], NULL, 10);

	err = getsockname(sock, (struct sockaddr *) &sa2, &sa_len);
	if (err != 0) {
		perror("getsockname");
		return 1;
	}
	fprintf(stderr, "Socket bound to %s/%d.\n",
		inet_ntop(sa2.sin_family, &sa2.sin_addr, junk, sa_len),
		ntohs(sa2.sin_port));

	memset(&sa, 0, sizeof(struct sockaddr));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	err = inet_pton(AF_INET, dest, &sa.sin_addr);
	if (err != 1) {
		perror("inet_pton");
		return 1;
	}

	err = connect(sock, (struct sockaddr *) &sa, sizeof(sa));
	if (err == -1) {
		perror("connect");
		/* ignore error */
	}

	err = getsockname(sock, (struct sockaddr *) &sa2, &sa_len);
	if (err != 0) {
		perror("getsockname");
		return 1;
	}
	fprintf(stderr, "Socket bound to %s/%d (after connect called).\n",
		inet_ntop(sa2.sin_family, &sa2.sin_addr, junk, sa_len),
		ntohs(sa2.sin_port));

	close(sock);

	return 0;
}
