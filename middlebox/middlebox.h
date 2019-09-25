/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _MIDDLEBOX_H_
#define _MIDDLEBOX_H_

#include <ev.h>
#include <libtlmsp-cfg.h>
#include <libtlmsp-util.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <libdemo/connection.h>
#include <libdemo/container_queue.h>
#include <libdemo/print.h>
#include <openssl/tlmsp.h>


struct demo_app;
struct splice_state;

struct connection_state {
	struct splice_state *splice;
	struct context_state *context[TLMSP_UTIL_CONTEXT_ID_LUT_SIZE];
	bool is_dead;
};

struct middlebox_state;

struct splice_state {
	struct middlebox_state *middlebox;
	struct demo_splice *splice;
	struct connection_state *to_client;
	struct connection_state *to_server;
	const TLMSP_ReconnectState *reconnect_state;

	int next_hop_addr_type;
	uint8_t *next_hop_addr;
	size_t next_hop_addr_len;
	
	/*
	 * We maintain separate context state for each context in each
	 * direction. All of the context states are stored here, with
	 * references into this array from the context lookup tables in each
	 * connection state.
	 */
	unsigned int num_contexts;
	struct context_state *contexts;
};

struct middlebox_state {
	/* XXX
	  context config - needs to agree with what's on the wire
	  need to retrieve middlebox list, or at last next middlebox from openssl as it may change during the handshake, and that determines next hop
	  fault config table
          index state by context id
              when processing a container, look context id up in state table
              a state can refer to multiple faults, a given fault can be referenced by multiple contexts
	 */
	struct ev_loop *loop;
	struct demo_app *app;
	const struct tlmsp_cfg_middlebox *cfg;
	SSL_CTX *ssl_ctx;
	struct sockaddr *listen_addr;
	unsigned int accept_batch_limit;
	size_t read_buffer_limit;
	bool next_is_transparent;
	struct sockaddr *next_addr;	/* only used if next_is_transparent */
	socklen_t next_addr_len;	/* only used if next_is_transparent */
	int listen_socket;
	ev_io listen_watcher;
	int port_shift;
	uint64_t splice_counter;
};

#endif /* _MIDDLEBOX_H_ */
