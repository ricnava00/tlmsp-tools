/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBDEMO_CONNECTION_H_
#define _LIBDEMO_CONNECTION_H_

#include <ev.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <libdemo/container_queue.h>
#include <openssl/tlmsp.h>


struct demo_app;
struct demo_splice;
struct tlmsp_cfg_activity;

typedef void (*demo_connection_cb_t)(EV_P_ struct ev_io *w, int revents);
typedef void (*demo_connection_failed_cb_t)(void *cb_data);
typedef void (*demo_connection_free_cb_t)(void *);
typedef void (*demo_connection_show_info_cb_t)(void *);

enum demo_connection_phase {
	DEMO_CONNECTION_PHASE_UNKNOWN,
	DEMO_CONNECTION_PHASE_HANDSHAKE,
	DEMO_CONNECTION_PHASE_APPLICATION
};

struct demo_connection {
	struct ev_loop *loop;
	struct demo_app *app;
	void *app_data;
	demo_connection_failed_cb_t fail_cb;
	void *cb_data;
	struct demo_splice *splice; /* only used by middlebox */
	struct demo_connection *other_side; /* only used when there is a splice */
	bool to_client; /* only used when there is a splice */
	bool is_connected;
	struct sockaddr_storage local_name;
	struct sockaddr_storage remote_name;
	uint64_t id;
	enum demo_connection_phase phase; /* only used by middlebox */
	int socket;
	int wait_events;
	SSL *ssl;
	ev_io connected_watcher;
	ev_io watcher;
	struct container_queue read_queue;
	struct container_queue write_queue;
	bool queues_initialized;
	/*
	 * These are the activities that pattern match against the read
	 * queue for this connection.  Where containers generated by these
	 * activities (time-triggered or otherwise) get transmitted depends
	 * on whether this connection is part of a splice or not.
	 */
	struct tlmsp_cfg_activity **activities;
	unsigned int num_activities;
	struct demo_activity_match_state *activity_states;
	struct demo_time_triggered_msg {
		struct demo_connection *conn;
		ev_timer timer;
		struct tlmsp_cfg_activity *activity;
		ev_tstamp interval;
		struct demo_time_triggered_msg *next;
	} *time_triggered_messages;
	demo_connection_free_cb_t free_cb;
	demo_connection_show_info_cb_t show_info_cb;
	struct demo_connection *next;
	struct demo_connection *prev;
};


struct demo_connection *demo_connection_create(struct demo_app *app,
                                               demo_connection_free_cb_t free_cb,
                                               demo_connection_show_info_cb_t show_info_cb,
                                               void *app_data, uint64_t id,
                                               struct tlmsp_cfg_activity **activities,
                                               unsigned int num_activities);
void demo_connection_set_phase(struct demo_connection *conn,
                               enum demo_connection_phase phase);
bool demo_connection_handshake_complete(struct demo_connection *conn);
bool demo_connection_init_io(struct demo_connection *conn, SSL_CTX *ssl_ctx,
                             int sock, struct ev_loop *loop,
                             demo_connection_failed_cb_t fail_cb,
                             demo_connection_cb_t cb, int initial_events);
bool demo_connection_start_io(struct demo_connection *conn);
void demo_connection_pause_io(struct demo_connection *conn);
void demo_connection_stop_io(struct demo_connection *conn);
void demo_connection_events_arrived(struct demo_connection *conn, int events);
bool demo_connection_writes_pending(struct demo_connection *conn);
void demo_connection_wait_for(struct demo_connection *conn, int events);
void demo_connection_wait_for_none(struct demo_connection *conn);
int demo_connection_wait_events(struct demo_connection *conn);
void demo_connection_resume_io(struct demo_connection *conn);
void demo_connection_free(struct demo_connection *conn);
void demo_connection_show_info(struct demo_connection *conn,
                               bool trailing_separator);

const char *demo_connection_phase_to_str(enum demo_connection_phase phase);

#endif /* _LIBDEMO_CONNECTION_H_ */
