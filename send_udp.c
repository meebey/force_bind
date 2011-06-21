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
	struct sockaddr_in sa;
	int port = 123;
	unsigned char buf[4096];
	unsigned int bytes = 100000, rest, max;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket");
		return 1;
	}

	if (argc >= 2)
		port = strtol(argv[1], NULL, 10);

	if (argc >= 3)
		bytes = strtol(argv[2], NULL, 10);

	memset(&sa, 0, sizeof(struct sockaddr));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	memset(buf, 'A', sizeof(buf));

	rest = bytes;
	while (rest > 0) {
		max = sizeof(buf);
		if (rest < max)
			max = rest;
		printf("Sending %u bytes...\n", max);
		err = sendto(sock, buf, max, 0, (struct sockaddr *) &sa, sizeof(sa));
		if (err == -1) {
			perror("sendto");
			break;
		}

		rest -= err;
	}

	close(sock);

	return 0;
}
