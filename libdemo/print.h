/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBDEMO_PRINT_H_
#define _LIBDEMO_PRINT_H_

#include <stdint.h>
#include <unistd.h>

#include <sys/types.h>

#define DEMO_ERRBUF_SIZE	256


struct demo_connection;
struct sockaddr;

void demo_print_errno(const char *fmt, ...);
void demo_conn_print_errno(struct demo_connection *conn, const char *fmt, ...);
void demo_print_error(const char *fmt, ...);
void demo_print_error_ssl_errq(const char *fmt, ...);
void demo_conn_print_error(struct demo_connection *conn, const char *fmt, ...);
void demo_conn_print_error_ssl(struct demo_connection *conn, int ssl_error,
                               const char *fmt, ...);
void demo_conn_print_error_ssl_errq(struct demo_connection *conn,
                                    const char *fmt, ...);
void demo_print_error_sockaddr(const char *msg, struct sockaddr *sa);
void demo_conn_print_error_sockaddr(struct demo_connection *conn,
                                    const char *msg, struct sockaddr *sa);
void demo_log_msg(unsigned int level, const char *fmt, ...);
void demo_conn_log(unsigned int level, struct demo_connection *conn,
                   const char *fmt, ...);
void demo_log_sockaddr(unsigned int level, const char *msg, struct sockaddr *sa);
void demo_conn_log_sockaddr(unsigned int level, struct demo_connection *conn,
                            const char *msg, struct sockaddr *sa);
void demo_log_buf(unsigned int level, const uint8_t *buf, size_t len,
                  bool limit, const char *fmt, ...);
void demo_conn_log_buf(unsigned int level, struct demo_connection *conn,
                       const uint8_t *buf, size_t len, bool limit,
                       const char *fmt, ...);
void demo_conn_present(struct demo_connection *conn, const char *fmt, ...);
void demo_conn_present_buf(struct demo_connection *conn, const uint8_t *buf,
    size_t len, bool limit, const char *fmt, ...);

extern int demo_error_fd;
extern pid_t demo_pid;
extern const char *demo_progname;
extern const char *demo_tag;
extern unsigned int demo_verbose;

#endif /* _LIBDEMO_PRINT_H_ */
