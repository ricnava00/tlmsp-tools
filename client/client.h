/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _CLIENT_H_
#define _CLIENT_H_

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
struct client_state;


struct connection_state {
	struct client_state *client;
	struct demo_connection *conn;
	uint8_t *read_buffer;
	size_t read_buffer_size;
	const TLMSP_ReconnectState *reconnect_state;
};

struct client_state {
	struct ev_loop *loop;
	struct demo_app *app;
	const struct tlmsp_cfg_client *cfg;
	SSL_CTX *ssl_ctx;
	int port_shift;
	bool use_stream_api;
	uint64_t connection_counter;
};

#endif /* _CLIENT_H_ */
