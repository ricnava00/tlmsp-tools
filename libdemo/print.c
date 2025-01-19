/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#ifdef __FreeBSD__
#define _WITH_DPRINTF
#endif

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "connection.h"
#include "splice.h"
#include "print.h"


#define BUF_PRINT_BYTES_PER_LINE	16
#define BUF_PRINT_BYTE_LIMIT		(20 * BUF_PRINT_BYTES_PER_LINE)


static void demo_conn_print_ssl_errq(struct demo_connection *conn);
static void demo_base_print_preamble(int fd);
static void demo_base_print(int fd, const char *fmt, ...);
static void demo_base_vprint(int fd, const char *fmt, va_list ap);
static void demo_conn_base_print_preamble(struct demo_connection *conn, int fd,
                                          bool present);
static void demo_conn_base_print(struct demo_connection *conn, int fd,
                                 bool present, const char *fmt, ...);
static void demo_conn_base_vprint(struct demo_connection *conn, int fd,
                                  bool present, const char *fmt, va_list ap);
static void demo_base_print_sockaddr(int fd, const char *msg,
                                     struct sockaddr *sa);
static void demo_conn_base_print_sockaddr(struct demo_connection *conn, int fd,
                                          const char *msg, struct sockaddr *sa);
static void demo_sockaddr_to_string(struct sockaddr *sa, char *buf, size_t len);
static void demo_base_vprint_buf(int fd, const uint8_t *buf, size_t len,
                                 bool limit, const char *fmt, va_list ap);
static void demo_conn_base_vprint_buf(struct demo_connection *conn, int fd,
                                      bool present, const uint8_t *buf,
                                      size_t len, bool limit, bool alongside,
                                      const char *fmt, va_list ap);
static void demo_buf_to_line_string(char *line_string, size_t line_string_len,
                                    const uint8_t *buf, size_t len);
static const char *demo_ssl_error_str(int ssl_error);

int demo_error_fd = STDERR_FILENO;
pid_t demo_pid;
const char *demo_progname;
const char *demo_tag;
unsigned int demo_verbose;


void
demo_print_errno(const char *fmt, ...)
{
	va_list ap;
	int errnum = errno;

	va_start(ap, fmt);
	demo_base_vprint(demo_error_fd, fmt, ap);
	va_end(ap);
	dprintf(demo_error_fd, ": %s\n", strerror(errnum));
}

void
demo_conn_print_errno(struct demo_connection *conn, const char *fmt, ...)
{
	va_list ap;
	int errnum = errno;

	va_start(ap, fmt);
	demo_conn_base_vprint(conn, demo_error_fd, false, fmt, ap);
	va_end(ap);
	dprintf(demo_error_fd, ": %s\n", strerror(errnum));
}

void
demo_print_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	demo_base_vprint(demo_error_fd, fmt, ap);
	va_end(ap);
	dprintf(demo_error_fd, "\n");
}

void
demo_print_error_ssl_errq(const char *fmt, ...)
{
	va_list ap;
	unsigned int num_ssl_errors;
	unsigned long ssl_error;
	char buf[256];

	va_start(ap, fmt);
	demo_base_vprint(demo_error_fd, fmt, ap);
	va_end(ap);
	dprintf(demo_error_fd, "\n");
	num_ssl_errors = 0;
	while ((ssl_error = ERR_get_error()) != 0) {
		num_ssl_errors++;
		ERR_error_string_n(ssl_error, buf, sizeof(buf));
		demo_base_print(demo_error_fd, "    openssl %s\n", buf);
	}
	if (num_ssl_errors == 0) {
		demo_base_print(demo_error_fd,
		    "    The openssl error queue is empty\n");
	}
}

void
demo_conn_print_error(struct demo_connection *conn, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	demo_conn_base_vprint(conn, demo_error_fd, false, fmt, ap);
	va_end(ap);
	dprintf(demo_error_fd, "\n");
}

void
demo_conn_print_error_ssl(struct demo_connection *conn, int ssl_error,
    const char *fmt, ...)
{
	va_list ap;
	int errnum = errno;

	va_start(ap, fmt);
	demo_conn_base_vprint(conn, demo_error_fd, false, fmt, ap);
	va_end(ap);
	dprintf(demo_error_fd, "\n");
	demo_conn_base_print(conn, demo_error_fd, false, "    ssl error %s\n",
	    demo_ssl_error_str(ssl_error));
	if (ssl_error == SSL_ERROR_SYSCALL) {
		demo_conn_base_print(conn, demo_error_fd, false, "    errno: %s\n",
		    strerror(errnum));
	}
	if ((ssl_error == SSL_ERROR_SYSCALL) || (ssl_error == SSL_ERROR_SSL)) {
		demo_conn_print_ssl_errq(conn);
	}
}

void
demo_conn_print_error_ssl_errq(struct demo_connection *conn, const char *fmt,
    ...)
{
	va_list ap;

	va_start(ap, fmt);
	demo_conn_base_vprint(conn, demo_error_fd, false, fmt, ap);
	va_end(ap);
	dprintf(demo_error_fd, "\n");
	demo_conn_print_ssl_errq(conn);
}

static void
demo_conn_print_ssl_errq(struct demo_connection *conn)
{
	unsigned int num_ssl_errors;
	unsigned long ssl_error;
	const char *file, *data;
	int line, flags;
	char buf[256];

	num_ssl_errors = 0;
	while ((ssl_error = ERR_get_error_line_data(&file, &line, &data,
		    &flags)) != 0) {
		num_ssl_errors++;
		ERR_error_string_n(ssl_error, buf, sizeof(buf));
		demo_conn_base_print(conn, demo_error_fd, false,
		    "    openssl %s:%s:%d%s%s\n", buf, file, line,
		    (flags & ERR_TXT_STRING) ? ":" : "",
		    (flags & ERR_TXT_STRING) ? data : "");
	}
	if (num_ssl_errors == 0) {
		demo_conn_base_print(conn, demo_error_fd, false,
		    "    The openssl error queue is empty\n");
	}
}

void
demo_print_error_sockaddr(const char *msg, struct sockaddr *sa)
{

	demo_base_print_sockaddr(demo_error_fd, msg, sa);
	dprintf(demo_error_fd, "\n");
}

void
demo_conn_print_error_sockaddr(struct demo_connection *conn, const char *msg,
    struct sockaddr *sa)
{

	demo_conn_base_print_sockaddr(conn, demo_error_fd, msg, sa);
	dprintf(demo_error_fd, "\n");
}

void
demo_log_msg(unsigned int level, const char *fmt, ...)
{
	va_list ap;

	if (demo_verbose >= level) {
		va_start(ap, fmt);
		demo_base_vprint(STDOUT_FILENO, fmt, ap);
		va_end(ap);
		dprintf(STDOUT_FILENO, "\n");
	}
}

void
demo_conn_log(unsigned int level, struct demo_connection *conn, const char *fmt,
    ...)
{
	va_list ap;

	if (demo_verbose >= level) {
		va_start(ap, fmt);
		demo_conn_base_vprint(conn, STDOUT_FILENO, false, fmt, ap);
		va_end(ap);
		dprintf(STDOUT_FILENO, "\n");
	}
}

void
demo_log_sockaddr(unsigned int level, const char *msg, struct sockaddr *sa)
{

	if (demo_verbose >= level) {
		demo_base_print_sockaddr(STDOUT_FILENO, msg, sa);
		dprintf(STDOUT_FILENO, "\n");
	}
}

void
demo_conn_log_sockaddr(unsigned int level, struct demo_connection *conn,
    const char *msg, struct sockaddr *sa)
{

	if (demo_verbose >= level) {
		demo_conn_base_print_sockaddr(conn, STDOUT_FILENO, msg, sa);
		dprintf(STDOUT_FILENO, "\n");
	}
}

void
demo_log_buf(unsigned int level, const uint8_t *buf, size_t len,
    bool limit, const char *fmt, ...)
{
	va_list ap;

	if (demo_verbose >= level) {
		va_start(ap, fmt);
		demo_base_vprint_buf(STDOUT_FILENO, buf, len, limit, fmt, ap);
		va_end(ap);
	}
}

void
demo_conn_log_buf(unsigned int level, struct demo_connection *conn,
    const uint8_t *buf, size_t len, bool limit, const char *fmt, ...)
{
	va_list ap;

	if (demo_verbose >= level) {
		va_start(ap, fmt);
		demo_conn_base_vprint_buf(conn, STDOUT_FILENO, false, buf, len,
		    limit, false, fmt, ap);
		va_end(ap);
	}
}

static void
demo_base_print_preamble(int fd)
{

	if (demo_tag != NULL)
		dprintf(fd, "%s[%d:%s]: ", demo_progname, demo_pid, demo_tag);
	else
		dprintf(fd, "%s[%d]: ", demo_progname, demo_pid);
}

static void
demo_base_print(int fd, const char *fmt, ...)
{
	va_list ap;

	demo_base_print_preamble(fd);
	va_start(ap, fmt);
	vdprintf(fd, fmt, ap);
	va_end(ap);
}

static void
demo_base_vprint(int fd, const char *fmt, va_list ap)
{

	demo_base_print_preamble(fd);
	vdprintf(fd, fmt, ap);
}

static void
demo_conn_base_print_preamble(struct demo_connection *conn, int fd, bool present)
{

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	if (conn->splice != NULL) {
		if (demo_tag != NULL) {
			dprintf(fd, "%ld%09ld %s[%d:%s]: splice %" PRIu64 " (%s): ",
				ts.tv_sec, ts.tv_nsec,
				demo_progname, demo_pid, demo_tag, conn->splice->id,
				conn->to_client ? "client-side" : "server-side");
		} else {
			dprintf(fd, "%ld%09ld %s[%d]: splice %" PRIu64 " (%s): ",
				ts.tv_sec, ts.tv_nsec,
			    demo_progname, demo_pid, conn->splice->id,
			    conn->to_client ? "client-side" : "server-side");
		}
	} else {
		if (demo_tag != NULL) {
			dprintf(fd, "%ld%09ld %s[%d:%s]: connection %" PRIu64 ": ",
				ts.tv_sec, ts.tv_nsec,
			    demo_progname, demo_pid, demo_tag, conn->id);
		} else {
			dprintf(fd, "%ld%09ld %s[%d]: connection %" PRIu64 ": ",
				ts.tv_sec, ts.tv_nsec,
			    demo_progname, demo_pid, conn->id);
		}
	}
}

static void
demo_conn_base_print(struct demo_connection *conn, int fd, bool present,
    const char *fmt, ...)
{
	va_list ap;

	demo_conn_base_print_preamble(conn, fd, present);
	va_start(ap, fmt);
	vdprintf(fd, fmt, ap);
	va_end(ap);
}

static void
demo_conn_base_vprint(struct demo_connection *conn, int fd, bool present,
    const char *fmt, va_list ap)
{

	demo_conn_base_print_preamble(conn, fd, present);
	vdprintf(fd, fmt, ap);
}

static void
demo_base_print_sockaddr(int fd, const char *msg, struct sockaddr *sa)
{
	char buf[INET6_ADDRSTRLEN + 16];

	demo_sockaddr_to_string(sa, buf, sizeof(buf));
	demo_base_print(fd, "%s%s", msg, buf);
}

static void
demo_conn_base_print_sockaddr(struct demo_connection *conn, int fd,
    const char *msg, struct sockaddr *sa)
{
	char buf[INET6_ADDRSTRLEN + 16];

	demo_sockaddr_to_string(sa, buf, sizeof(buf));
	demo_conn_base_print(conn, fd, false, "%s%s", msg, buf);
}

static void
demo_sockaddr_to_string(struct sockaddr *sa, char *str, size_t len)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	char buf[INET6_ADDRSTRLEN];

	switch (sa->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)sa;
		inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
		snprintf(str, len, "%s:%u", buf, ntohs(sin->sin_port));
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
		snprintf(str, len, "[%s]:%u", buf, ntohs(sin6->sin6_port));
		break;
	case 0:
		snprintf(str, len, "<not set>");
		break;
	default:
		snprintf(str, len, "<unknown address family %u>", sa->sa_family);
		break;
	}
}

void
demo_conn_present(struct demo_connection *conn, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	demo_conn_base_vprint(conn, STDOUT_FILENO, true, fmt, ap);
	va_end(ap);
	dprintf(STDOUT_FILENO, "\n");
}

void
demo_conn_present_buf(struct demo_connection *conn, const uint8_t *buf,
    size_t len, bool limit, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	demo_conn_base_vprint_buf(conn, STDOUT_FILENO, true, buf, len, limit,
	    true, fmt, ap);
	va_end(ap);
}

static void
demo_base_vprint_buf(int fd, const uint8_t *buf, size_t len, bool limit,
    const char *fmt, va_list ap)
{
	char line_string[BUF_PRINT_BYTES_PER_LINE * 3 + BUF_PRINT_BYTES_PER_LINE + 2 + 1];
	size_t offset;
	unsigned int full_lines;
	unsigned int remainder;
	unsigned int i;
	bool limited;

	limited = false;
	if (limit && (len > BUF_PRINT_BYTE_LIMIT)) {
		len = BUF_PRINT_BYTE_LIMIT;
		limited = true;
	}
	
	full_lines = len / BUF_PRINT_BYTES_PER_LINE;
	remainder = len % BUF_PRINT_BYTES_PER_LINE;

	demo_base_vprint(fd, fmt, ap);
	if (limited)
		dprintf(fd, " (truncated to %zu bytes): \n", len);
	else
		dprintf(fd, ": \n");
	offset = 0;
	for (i = 0; i < full_lines; i++) {
		demo_buf_to_line_string(line_string, sizeof(line_string),
		    &buf[offset], BUF_PRINT_BYTES_PER_LINE);
		demo_base_print(fd, "%s\n", line_string);
		offset += BUF_PRINT_BYTES_PER_LINE;
	}
	if ((remainder > 0) || (full_lines == 0)) {
		demo_buf_to_line_string(line_string, sizeof(line_string),
		    &buf[offset], remainder);
		demo_base_print(fd, "%s\n", line_string);
	}
}

static void
demo_conn_base_vprint_buf(struct demo_connection *conn, int fd, bool present,
    const uint8_t *buf, size_t len, bool limit, bool alongside, const char *fmt,
    va_list ap)
{
	char line_string[BUF_PRINT_BYTES_PER_LINE * 3 + BUF_PRINT_BYTES_PER_LINE + 2 + 1];
	size_t offset;
	unsigned int full_lines;
	unsigned int remainder;
	unsigned int i;
	bool limited;

	limited = false;
	if (limit && (len > BUF_PRINT_BYTE_LIMIT)) {
		len = BUF_PRINT_BYTE_LIMIT;
		limited = true;
	}

	full_lines = len / BUF_PRINT_BYTES_PER_LINE;
	remainder = len % BUF_PRINT_BYTES_PER_LINE;

	if (!alongside) {
		demo_conn_base_vprint(conn, fd, present, fmt, ap);
		if (limited)
			dprintf(fd, " (truncated to %zu bytes): \n", len);
		else
			dprintf(fd, ": \n");
	}
	offset = 0;
	for (i = 0; i < full_lines; i++) {
		demo_buf_to_line_string(line_string, sizeof(line_string),
		    &buf[offset], BUF_PRINT_BYTES_PER_LINE);
		demo_conn_base_print(conn, fd, present, "%s", line_string);
		if (alongside) {
			dprintf(fd, " ");
			vdprintf(fd, fmt, ap);
			if (limited)
				dprintf(fd, " (truncated to %zu bytes)", len);
			alongside = false;
		}
		dprintf(fd, "\n");
		offset += BUF_PRINT_BYTES_PER_LINE;
	}
	if ((remainder > 0) || (full_lines == 0)) {
		demo_buf_to_line_string(line_string, sizeof(line_string),
		    &buf[offset], remainder);
		demo_conn_base_print(conn, fd, present, "%s", line_string);
		if (alongside) {
			dprintf(fd, " ");
			vdprintf(fd, fmt, ap);
			if (limited)
				dprintf(fd, " (truncated to %zu bytes)", len);
		}
		dprintf(fd, "\n");
	}
}

static void
demo_buf_to_line_string(char *line_string, size_t line_string_len,
    const uint8_t *buf, size_t len)
{
	size_t offset;
	ssize_t remaining;
	unsigned int i;
	int size;
	
	if (len > BUF_PRINT_BYTES_PER_LINE)
		len = BUF_PRINT_BYTES_PER_LINE;

	offset = 0;
	remaining = line_string_len;

	/* print hex */
	for (i = 0; (i < len) && (remaining > 0); i++) {
		size = snprintf(&line_string[offset], remaining, "%02x ",
		    buf[i]);
		if ((size < 0) || (size > remaining))
			remaining = 0;
		else {
			remaining -= size;
			offset += size;
		}
	}

	/* pad out hex print */
	for (i = 0; (i < (BUF_PRINT_BYTES_PER_LINE - len)) && (remaining > 0);
	     i++) {
		size = snprintf(&line_string[offset], remaining, "   ");
		if ((size < 0) || (size > remaining))
			remaining = 0;
		else {
			remaining -= size;
			offset += size;
		}
	}

	if (remaining > 0) {
		size = snprintf(&line_string[offset], remaining, "|");
		if ((size < 0) || (size > remaining))
			remaining = 0;
		else {
			remaining -= size;
			offset += size;
		}
	}

	/* print chars */
	for (i = 0; (i < len) && (remaining > 0); i++) {
		size = snprintf(&line_string[offset], remaining, "%c",
		    isprint(buf[i]) ? buf[i] : '.');
		if ((size < 0) || (size > remaining))
			remaining = 0;
		else {
			remaining -= size;
			offset += size;
		}
	}

	/* pad out char print */
	for (i = 0; (i < (BUF_PRINT_BYTES_PER_LINE - len)) && (remaining > 0);
	     i++) {
		size = snprintf(&line_string[offset], remaining, ".");
		if ((size < 0) || (size > remaining))
			remaining = 0;
		else {
			remaining -= size;
			offset += size;
		}
	}

	if (remaining > 0) {
		size = snprintf(&line_string[offset], remaining, "|");
		if ((size < 0) || (size > remaining))
			remaining = 0;
		else {
			remaining -= size;
			offset += size;
		}
	}
}

static const char *
demo_ssl_error_str(int ssl_error)
{
#define TOSTR(x) #x
#define HANDLE(x) case x: return (TOSTR(x))

	switch (ssl_error) {
		HANDLE(SSL_ERROR_NONE);
		HANDLE(SSL_ERROR_SSL);
		HANDLE(SSL_ERROR_WANT_READ);
		HANDLE(SSL_ERROR_WANT_WRITE);
		HANDLE(SSL_ERROR_WANT_X509_LOOKUP);
		HANDLE(SSL_ERROR_SYSCALL);
		HANDLE(SSL_ERROR_ZERO_RETURN);
		HANDLE(SSL_ERROR_WANT_CONNECT);
		HANDLE(SSL_ERROR_WANT_ACCEPT);
		HANDLE(SSL_ERROR_WANT_ASYNC);
		HANDLE(SSL_ERROR_WANT_ASYNC_JOB);
		HANDLE(SSL_ERROR_WANT_CLIENT_HELLO_CB);
		HANDLE(SSL_ERROR_WANT_CLIENT_WRITE);
		HANDLE(SSL_ERROR_WANT_SERVER_WRITE);
	default:
		return ("unknown SSL_ERROR value");
	}

#undef HANDLE
#undef TOSTR
}
