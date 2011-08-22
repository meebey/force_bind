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
	int sock[10], err;
	struct sockaddr_in sa;
	int port = 123;
	unsigned char buf[4096 * 100];
	unsigned int bytes = 100000, rest, max;
	unsigned int chunk_len = 1000;
	unsigned int i, connections = 2;

	for (i = 0; i < connections; i++) {
		sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock[i] == -1) {
			perror("socket");
			return 1;
		}
	}

	if (argc >= 2)
		port = strtol(argv[1], NULL, 10);

	if (argc >= 3)
		bytes = strtol(argv[2], NULL, 10);

	if (argc >= 4)
		chunk_len = strtol(argv[3], NULL, 10);

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
		if (max > chunk_len)
			max = chunk_len;

		for (i = 0; i < connections; i++) {
			printf("Sending %u bytes to connection %u...\n", max, i);
			err = sendto(sock[i], buf, max, 0, (struct sockaddr *) &sa, sizeof(sa));
			if (err == -1) {
				perror("sendto");
				break;
			}
		}

		rest -= err;
	}

	for (i = 0; i < connections; i++)
		close(sock[i]);

	return 0;
}
