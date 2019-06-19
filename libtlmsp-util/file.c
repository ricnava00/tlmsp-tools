/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* assumes errbuf and errbuf_len are in scope */
#define ERRBUF(...)							\
	do {								\
		size_t size;						\
		int errnum = errno;					\
									\
		size = snprintf(errbuf, errbuf_len, __VA_ARGS__);	\
		if ((size >= 0) && (size < errbuf_len))			\
			size += snprintf(&errbuf[size], errbuf_len - size, \
			    ": %s", strerror(errnum));			\
	} while (0)

bool
tlmsp_util_load_file(const char *filename, const uint8_t **buf, size_t *len,
    char *errbuf, size_t errbuf_len)
{
	int fd;
	off_t file_size;
	size_t remaining;
	ssize_t bytes_read;
	uint8_t *p;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		ERRBUF("Failed to open file %s", filename);
		return (false);
	}
	file_size = lseek(fd, 0, SEEK_END);
	if (file_size == -1) {
		ERRBUF("Unable to seek to end of file %s", filename);
		close(fd);
		return (false);
	}
	lseek(fd, 0, SEEK_SET);

	if (file_size > 0) {
		p = malloc(file_size);
		if (p == NULL) {
			ERRBUF("Failed to allocate %jd bytes for file %s",
			    file_size, filename);
			close (fd);
			return (false);
		}

		remaining = file_size;
		while ((remaining > 0) &&
		    (((bytes_read = read(fd, &p[file_size - remaining],
				remaining)) != -1) || (errno == EINTR))) {
			remaining -= bytes_read;
		}
		do {
			bytes_read = read(fd, &p[file_size - remaining],
			    remaining);
			if (bytes_read == -1) {
				if (errno != EINTR)
					break;
			} else
				remaining -= bytes_read;
		} while (remaining > 0);
		if (bytes_read == -1) {
			ERRBUF("Error reading from payload file %s", filename);
			close(fd);
			return (false);
		}
	} else
		p = NULL;

	*buf = p;
	*len = file_size;
	close(fd);

	return (true);
}
