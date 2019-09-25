/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBDEMO_SPLICE_H_
#define _LIBDEMO_SPLICE_H_


#include <stdbool.h>

#include <libdemo/connection.h>

struct demo_app;
struct tlmsp_cfg_activity;

typedef void (*demo_splice_free_cb_t)(void *);
typedef void (*demo_splice_show_info_cb_t)(void *);

struct demo_splice {
	uint64_t id;
	struct demo_app *app;
	void *app_data;
	struct demo_connection *to_client;
	struct demo_connection *to_server;
	demo_splice_free_cb_t free_cb;
	demo_splice_show_info_cb_t show_info_cb;
	struct demo_splice *next;
	struct demo_splice *prev;
};


struct demo_splice *demo_splice_create(struct demo_app *app,
                                       demo_splice_free_cb_t free_cb,
                                       demo_splice_show_info_cb_t show_info_cb,
                                       void *app_data, uint64_t id,
                                       struct tlmsp_cfg_activity **activities_to_client,
                                       unsigned int num_activities_to_client,
                                       struct tlmsp_cfg_activity **activities_to_server,
                                       unsigned int num_activities_to_server);
bool demo_splice_handshake_complete(struct demo_splice *splice);
bool demo_splice_init_io_to_client(struct demo_splice *splice, SSL_CTX *ssl_ctx,
                                   int sock, struct ev_loop *loop,
                                   demo_connection_failed_cb_t fail_cb,
                                   demo_connection_connected_cb_t connected_cb,
                                   demo_connection_cb_t cb, int initial_events);
bool demo_splice_start_io_to_client(struct demo_splice *splice);
bool demo_splice_init_io_to_server(struct demo_splice *splice, SSL_CTX *ssl_ctx,
                                   int sock, struct ev_loop *loop,
                                   demo_connection_failed_cb_t fail_cb,
                                   demo_connection_connected_cb_t connected_cb,
                                   demo_connection_cb_t cb, int initial_events);
bool demo_splice_start_io_to_server(struct demo_splice *splice);
void demo_splice_pause_io(struct demo_splice *splice);
void demo_splice_stop_io(struct demo_splice *splice);
void demo_splice_resume_io(struct demo_splice *splice);
void demo_splice_free(struct demo_splice *splice);
void demo_splice_show_info(struct demo_splice *splice,
                           bool trailing_separator);

#endif /* _LIBDEMO_SPLICE_H_ */
