#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main()
{
	struct pollfd pfd;
	char buf[255];
	int wfd;

	unlink("fifo");

	if (mkfifo("fifo", 0600))
		err(EXIT_FAILURE, "mkfifo");

	pfd.fd = open("fifo", O_RDONLY | O_NONBLOCK);
	if (pfd.fd < 0)
		err(EXIT_FAILURE, "open for read");

	wfd = open("fifo", O_WRONLY);
	if (wfd < 0)
		err(EXIT_FAILURE, "open for write");

	/* close to generate a POLLHUP */
	close(wfd);

	pfd.events = POLLIN;

	do {
		int r = poll(&pfd, 1, -1);

		printf("poll() = %d, revents: POLLIN %d, POLLERR %d, "
		       "POLLHUP %d, POLLNVAL %d\n",
			r, pfd.revents & POLLIN, pfd.revents & POLLERR,
			pfd.revents & POLLHUP, pfd.revents & POLLNVAL);

		if (pfd.revents & POLLIN) {
			r = read(pfd.fd, buf, sizeof buf);
			printf("read() = %d\n", r);
		}
	} while (!(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)));

	return 0;
}
