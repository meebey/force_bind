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
	unsigned char tos;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket");
		return 1;
	}

	if (argc >= 2)
		port = strtol(argv[1], NULL, 10);

	memset(&sa, 0, sizeof(struct sockaddr));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	sa_len = sizeof(struct sockaddr_in);
	err = bind(sock, (struct sockaddr *) &sa, sa_len);
	if (err != 0) {
		perror("bind");
		return 1;
	}

	err = getsockname(sock, (struct sockaddr *) &sa2, &sa_len);
	if (err != 0) {
		perror("getsockname");
		return 1;
	}

	fprintf(stderr, "Socket bound to %s/%d.\n",
		inet_ntop(sa2.sin_family, &sa2.sin_addr, junk, sa_len),
		ntohs(sa2.sin_port));

	tos = 0x00;
	err = setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, 1);
	if (err != 0)
		perror("setsockopt");

	close(sock);

	return 0;
}
