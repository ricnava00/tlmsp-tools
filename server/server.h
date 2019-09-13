/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _SERVER_H_
#define _SERVER_H_

#include <ev.h>
#include <libtlmsp-cfg.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <libdemo/connection.h>
#include <libdemo/print.h>
#include <openssl/tlmsp.h>


struct demo_app;
struct server_state;


struct connection_state {
	struct server_state *server;
	struct demo_connection *conn;
	uint8_t *read_buffer;
	size_t read_buffer_size;
};

struct server_state {
	struct ev_loop *loop;
	struct demo_app *app;
	const struct tlmsp_cfg_server *cfg;
	SSL_CTX *ssl_ctx;
	struct sockaddr *listen_addr;
	int port_shift;
	bool reflect;
	bool use_stream_api;
	unsigned int accept_batch_limit;
	int listen_socket;
	ev_io listen_watcher;
	uint64_t connection_counter;
};

#endif /* _SERVER_H_ */
