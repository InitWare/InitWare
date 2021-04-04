/*******************************************************************

        PUBLIC DOMAIN NOTICE

The coded instructions and statements in this file are likely too
trivial to be  protected by copyright law, and therefore they are
released into the Public Domain.

*********************************************************************/
/**
 * Opens a named pipe at path argv[1], and waits for a byte to be written
 * thereto, following which it exits with the byte received for its status code.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "compat.h"

int main(int argc, char **argv) {
        int fd;
        char retcode;
        int r;

        if (argc != 2) {
                fprintf(stderr, "Usage: wait4pipe /path/to/fifo\n");
                exit(EXIT_FAILURE);
        }

        fd = open(argv[1], O_RDONLY);
        if (fd < 0)
                err(EXIT_FAILURE, "Failed to open named pipe at path %s", argv[1]);

        r = read(fd, &retcode, 1);
        if (r < 0)
                err(EXIT_FAILURE, "Failed to read from named pipe at path %s", argv[1]);

        printf("retcode: %d\n", retcode);

        return retcode;
}