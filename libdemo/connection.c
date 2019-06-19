/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#include <string.h>
#include <unistd.h>

#include <libtlmsp-cfg.h>

#include "activity.h"
#include "app.h"
#include "connection.h"
#include "splice.h"
#include "print.h"

static void demo_conn_connected_cb(EV_P_ ev_io *w, int revents);


struct demo_connection *
demo_connection_create(struct demo_app *app, demo_connection_free_cb_t free_cb,
    demo_connection_show_info_cb_t show_info_cb, void *app_data, uint64_t id,
    struct tlmsp_cfg_activity **activities, unsigned int num_activities)
{
	struct demo_connection *conn;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		demo_print_errno("Failed to allocate connection");
		return (NULL);
	}

	conn->app = app;
	conn->free_cb = free_cb;
	conn->show_info_cb = show_info_cb;
	conn->app_data = app_data;
	conn->id = id;
	conn->phase = DEMO_CONNECTION_PHASE_UNKNOWN;
	/*
	 * so the close path in the machinery can be applied at any
	 * point during initialization
	 */
	conn->socket = -1;
	conn->activities = activities;
	conn->num_activities = num_activities;

	conn->activity_states =
	    demo_activity_create_match_state(activities, num_activities);
	if (conn->activity_states == NULL) {
		demo_print_errno(
		    "Failed to allocate activities state for connection");
		free(conn);
		return (NULL);
	}
	
	if (!app->uses_splices)
		demo_app_add_connection(app, conn);

	return (conn);
}


void
demo_connection_set_phase(struct demo_connection *conn,
    enum demo_connection_phase phase)
{

	conn->phase = phase;
}

bool
demo_connection_init_io(struct demo_connection *conn, SSL_CTX *ssl_ctx, int sock,
    struct ev_loop *loop, demo_connection_failed_cb_t fail_cb,
    demo_connection_cb_t cb, int initial_events)
{
	
	conn->ssl = SSL_new(ssl_ctx);
	if (conn->ssl == NULL) {
		demo_print_error_ssl_errq("Could not allocate SSL for connection");
		return (false);
	}
	conn->socket = sock;
	conn->loop = loop;
	conn->fail_cb = fail_cb;
	conn->cb_data = conn;
	
	ev_io_init(&conn->connected_watcher, demo_conn_connected_cb,
	    conn->socket, EV_WRITE);
	conn->connected_watcher.data = conn;
	conn->wait_events = initial_events;

	if (!SSL_set_fd(conn->ssl, conn->socket)) {
		demo_conn_print_error_ssl_errq(conn, "Setting ssl fd failed");
		return (false);
	}

	container_queue_init(&conn->read_queue, conn->ssl);
	container_queue_init(&conn->write_queue, conn->ssl);

	if (!demo_activity_conn_queue_initial(conn)) {
		demo_conn_print_error(conn,
		    "Failed to queue initial send data for write");
		return (false);
	}

	if (!demo_activity_conn_set_up_time_triggered(conn)) {
		demo_conn_print_error(conn,
		    "Failed to set up time-triggered messages");
		return (false);
	}

	ev_io_init(&conn->watcher, cb, conn->socket, conn->wait_events);
	conn->watcher.data = conn->cb_data;

	return (true);
}

bool
demo_connection_start_io(struct demo_connection *conn)
{
	struct ev_loop *loop = conn->loop;
	
	ev_io_start(EV_A_ &conn->connected_watcher);

	return (true);
}

static void
demo_conn_connected_cb(EV_P_ ev_io *w, int revents)
{
	struct demo_connection *conn = w->data;
	socklen_t len;

	len = sizeof(conn->local_name);
	if (getsockname(conn->socket, (struct sockaddr *)&conn->local_name,
		&len) == -1) {
		demo_conn_print_errno(conn, "Could not get local address");
		conn->fail_cb(conn->cb_data);
		return;
	}
	len = sizeof(conn->remote_name);
	if (getpeername(conn->socket, (struct sockaddr *)&conn->remote_name,
		&len) == -1) {
		demo_conn_print_errno(conn, "Could not get remote address");
		conn->fail_cb(conn->cb_data);
		return;
	}
	demo_conn_log_sockaddr(1, conn, "Local  address is ",
	    (struct sockaddr *)&conn->local_name);
	demo_conn_log_sockaddr(1, conn, "Remote address is ",
	    (struct sockaddr *)&conn->remote_name);

	if (!demo_activity_conn_start_time_triggered(conn))
		demo_conn_print_error(conn,
		    "Failed to start time-triggered messages");

	conn->is_connected = true;
	ev_io_stop(EV_A_ &conn->connected_watcher);
	ev_io_start(EV_A_ &conn->watcher);
}

void
demo_connection_stop_io(struct demo_connection *conn)
{
	struct ev_loop *loop = conn->loop;

	if (conn->socket != -1) {
		if (!conn->is_connected)
			ev_io_stop(EV_A_ &conn->connected_watcher);
		else
			ev_io_stop(EV_A_ &conn->watcher);
	}
}

void
demo_connection_events_arrived(struct demo_connection *conn, int events)
{

	if (events & EV_ERROR)
		demo_conn_log(3, conn, "ERROR event");
	if (events & EV_READ)
		demo_conn_log(3, conn, "READ event");
	if (events & EV_WRITE)
		demo_conn_log(3, conn, "WRITE event");

	conn->wait_events &= ~events;
}

bool
demo_connection_writes_pending(struct demo_connection *conn)
{

	return (container_queue_head(&conn->write_queue) != NULL);
}

void
demo_connection_wait_for(struct demo_connection *conn, int events)
{

	if (events & EV_READ)
		demo_conn_log(3, conn, "wait for readable");
	if (events & EV_WRITE)
		demo_conn_log(3, conn, "wait for writable");

	conn->wait_events |= events;
}

void
demo_connection_wait_for_none(struct demo_connection *conn)
{

	conn->wait_events = 0;
}

int
demo_connection_wait_events(struct demo_connection *conn)
{

	return (conn->wait_events);
}

void
demo_connection_resume_io(struct demo_connection *conn)
{
	struct ev_loop *loop = conn->loop;

	/* assumes watcher is currently stopped */
	if ((conn->socket != -1) && conn->wait_events) {
		ev_io_set(&conn->watcher, conn->socket, conn->wait_events);
		ev_io_start(EV_A_ &conn->watcher);
	}
}

void
demo_connection_free(struct demo_connection *conn)
{

	demo_conn_log(1, conn, "Shutting down");

	if (!conn->app->uses_splices)
		demo_app_remove_connection(conn->app, conn);
	if (conn->free_cb != NULL)
		conn->free_cb(conn->app_data);
	
	container_queue_drain(&conn->read_queue);
	container_queue_drain(&conn->write_queue);
	if (conn->socket != -1)
		close(conn->socket);
	if (conn->ssl)
		SSL_free(conn->ssl);

	demo_activity_conn_tear_down_time_triggered(conn);
	
	free(conn);
}

void
demo_connection_show_info(struct demo_connection *conn, bool trailing_separator)
{

	demo_print_error("...................................................");
	demo_conn_print_error_sockaddr(conn, "local-address : ",
	    (struct sockaddr *)&conn->local_name);
	demo_conn_print_error_sockaddr(conn, "remote-address: ",
	    (struct sockaddr *)&conn->remote_name);
	demo_conn_print_error(conn, "containers-sent    : %12" PRIu64, conn->read_queue.container_counter);
	demo_conn_print_error(conn, "containers-received: %12" PRIu64, conn->write_queue.container_counter);
	if (conn->show_info_cb != NULL)
		conn->show_info_cb(conn->app_data);
	if (trailing_separator)
		demo_print_error("...................................................");
}

const char *
demo_connection_phase_to_str(enum demo_connection_phase phase)
{

	switch (phase) {
	default:  /* satisfy compiler */
	case DEMO_CONNECTION_PHASE_UNKNOWN:	return ("UNKNOWN");
	case DEMO_CONNECTION_PHASE_HANDSHAKE:	return ("HANDSHAKE");
	case DEMO_CONNECTION_PHASE_APPLICATION:	return ("APPLICATION");
	}
}

