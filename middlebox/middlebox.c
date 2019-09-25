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

#include <ev.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <libtlmsp-cfg.h>
#include <libtlmsp-util.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libdemo/activity.h>
#include <libdemo/app.h>
#include <libdemo/splice.h>
#include <libdemo/pki.h>
#include <libdemo/print.h>
#include <libdemo/signal.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "middlebox.h"


#define DEFAULT_ACCEPT_BATCH_LIMIT	16
#define DEFAULT_READ_BUFFER_LIMIT	(1*1024*1024)

#define SET_LOG_TAG(mb)							\
	demo_tag = (mb) ? ((struct middlebox_state *)(mb))->cfg->tag : NULL

enum {
	OPT_CONFIG_ALL_TAGS  = 'a',
	OPT_CONFIG_FILE      = 'c',
	OPT_ERROR_FILE       = 'e',
	OPT_HELP             = 'h',
	OPT_PRESENTATION     = 'P',
	OPT_PORT_SHIFT       = 'p',
	OPT_CONFIG_TAG       = 't',
	OPT_VERBOSE          = 'v'
};


static void usage(bool is_error);
static void show_middlebox_info_cb(void *app_data);
static struct middlebox_state *new_middlebox(struct ev_loop *loop,
                                             const char *cfg_file,
                                             const char *tag,
                                             bool force_presentation,
                                             int port_shift);
static void free_middlebox_cb(void *app_data);
static void accept_cb(EV_P_ ev_io *w, int revents);
static bool new_splice(struct middlebox_state *middlebox, int sock);
static void free_splice_cb(void *app_data);
static void connection_died(struct demo_connection *conn);
static bool check_connection(struct demo_connection *conn);
static void connected_cb(struct demo_connection *conn);
static void conn_cb(EV_P_ ev_io *w, int revents);
static int read_containers(struct demo_connection *conn);
static int write_containers(struct demo_connection *conn);
static bool new_outbound_connection(struct demo_splice *splice,
				    const TLMSP_ReconnectState *reconnect_state);
static int address_match_cb(SSL *ssl, int type, const uint8_t *addr, size_t, void *arg);


static struct option options[] =
{
	{"all",            no_argument,       0, OPT_CONFIG_ALL_TAGS},
	{"config",         required_argument, 0, OPT_CONFIG_FILE},
	{"errors",         required_argument, 0, OPT_ERROR_FILE},
	{"help",           no_argument,       0, OPT_HELP},
	{"port-shift",     required_argument, 0, OPT_PORT_SHIFT},
	{"presentation",   no_argument,       0, OPT_PRESENTATION},
	{"tag",            required_argument, 0, OPT_CONFIG_TAG},
	{"verbose",        no_argument,       0, OPT_VERBOSE},
	{NULL, 0, NULL, 0}
};


static void
usage(bool is_error)
{
	int fd = is_error ? demo_error_fd : STDOUT_FILENO;
	int exit_code = is_error ? 1 : 0;

	dprintf(fd, "\n");
	dprintf(fd, "Usage: %s [options] (-c <file> | --config <file>) [-a | (-t <tag> | --tag <tag>)]\n", demo_progname);
	dprintf(fd, "\n");
	dprintf(fd, "Options:\n");
	dprintf(fd, "  -a                          Use all middlebox configurations\n");
	dprintf(fd, "  -c <file>, --config <file>  TLMSP config file\n");
	dprintf(fd, "  -e <file>, --errors <file>  Send error messages to file (- means stdout). List\n");
	dprintf(fd, "                              first to redirect all errors [default: stderr]\n");
	dprintf(fd, "  -h, --help                  Print this message\n");
	dprintf(fd, "  -P, --presentation          Force presentation of activities\n");
	dprintf(fd, "  -p, --port-shift <delta>    Shift all port numbers in configuration by this amount [default: 0]\n");
	dprintf(fd, "  -t <tag>, --tag <tag>       Tag of middlebox configuration to be used (can be used multiple times)\n");
	dprintf(fd, "  -v, --verbose               Raise verbosity level by one [default: 0]\n");
	dprintf(fd, "\n");
	exit(exit_code);
}

static void
show_middlebox_info_cb(void *app_data)
{
	struct middlebox_state *middlebox = app_data;

	demo_print_error_sockaddr("listen-address: ", middlebox->listen_addr);
	demo_print_error("next-is-transparent: ",
	    middlebox->next_is_transparent ? "true" : "false");
}

static struct middlebox_state *
new_middlebox(struct ev_loop *loop, const char *cfg_file, const char *tag,
    bool force_presentation, int port_shift)
{
	struct middlebox_state *middlebox;
	struct demo_app *app;
	const struct tlmsp_cfg_middlebox *cfg;
	const struct tlmsp_cfg_middlebox *next_mb;
	socklen_t addr_len;
	int optval;
	
	middlebox = calloc(1, sizeof(*middlebox));
	if (middlebox == NULL) {
		demo_print_errno("Middlebox state allocation failed");
		return (NULL);
	}

	app = demo_app_create(false, free_middlebox_cb, show_middlebox_info_cb,
	    middlebox, 0, cfg_file, force_presentation);
	if (app == NULL) {
		free(middlebox);
		return (NULL);
	}
	middlebox->app = app;

	demo_log_msg(1, "Looking up configuration for middlebox '%s'", tag);
	cfg = tlmsp_cfg_get_middlebox_by_tag(app->cfg, tag);
	if (cfg == NULL) {
		demo_print_error("Middlebox configuration with tag '%s' not found",
		    tag);
		goto error;
	}

	demo_log_msg(1, "Looking up configuration for next-hop middlebox, if any");
	next_mb = tlmsp_cfg_get_next_middlebox(app->cfg, cfg);

	middlebox->cfg = cfg;
	demo_log_msg(1, "Creating middlebox '%s' at '%s'", cfg->tag, cfg->address);
	SET_LOG_TAG(middlebox);
	middlebox->loop = loop;
	middlebox->accept_batch_limit = DEFAULT_ACCEPT_BATCH_LIMIT;
	middlebox->read_buffer_limit = DEFAULT_READ_BUFFER_LIMIT;
	middlebox->port_shift = port_shift;
	middlebox->listen_socket = -1;
	
	middlebox->listen_addr =
	    tlmsp_util_address_to_sockaddr(TLMSP_UTIL_ADDRESS_UNKNOWN,
		(uint8_t *)cfg->address, strlen(cfg->address), &addr_len,
		middlebox->port_shift, middlebox->app->errbuf,
		sizeof(middlebox->app->errbuf));
	if (middlebox->listen_addr == NULL) {
		demo_print_error("Could not convert middlebox address '%s' to "
		    "sockaddr: %s", cfg->address, middlebox->app->errbuf);
		goto error;
	}

	/*
	 * When there is a next middlebox in the configuration file, there
	 * are two cases where, due to emulation of transparency at the IP
	 * layer, we need to determine the next hop address from the
	 * configuration of that next middlebox:
	 *
	 *  1. The next middlebox is marked as transparent.  In this case,
	 *     we need to connect to its configured address.
	 *
	 *  2. We are configured to be transparent.  In this case, we cannot
	 *     use the destination IP of the inbound connection as the next
	 *     hop address as an actually transparent middlebox would.
	 */
	if ((next_mb != NULL) && (cfg->transparent || next_mb->transparent)) {
		if (next_mb->transparent)
			middlebox->next_is_transparent = true;
		middlebox->next_addr =
		    tlmsp_util_address_to_sockaddr(TLMSP_UTIL_ADDRESS_UNKNOWN,
			(uint8_t *)next_mb->address, strlen(next_mb->address),
			&addr_len, middlebox->port_shift, middlebox->app->errbuf,
			sizeof(middlebox->app->errbuf));
		if (middlebox->next_addr == NULL) {
			demo_print_error("Could not convert next middlebox "
			    "address %s to sockaddr: %s", next_mb->address,
			    middlebox->app->errbuf);
			goto error;
		}
	}

	middlebox->ssl_ctx = SSL_CTX_new(TLMSP_middlebox_method());
	if (middlebox->ssl_ctx == NULL) {
		demo_print_error_ssl_errq("Failed to create SSL_CTX\n");
		goto error;
	}
	if (SSL_CTX_set_ecdh_auto(middlebox->ssl_ctx, 1) != 1) {
		demo_print_error_ssl_errq("Failed to enable temporary ECDH keys");
		goto error;
	}
	if (SSL_CTX_set_dh_auto(middlebox->ssl_ctx, 1) != 1) {
		demo_print_error_ssl_errq("Failed to enable temporary DH keys");
		goto error;
	}
	if (!demo_pki_set_key_and_certificate(middlebox->ssl_ctx,
		cfg->cert_key_file, cfg->cert_file))
		goto error;
	if (cfg->transparent) {
		/*
		 * Set the TLMSP middlebox mode to transparent and configure
		 * the address that will be inserted into the ClientHello
		 * middlebox list.
		 */
		if (!TLMSP_set_transparent(middlebox->ssl_ctx,
			tlmsp_util_address_type(cfg->address), (const void *)cfg->address,
			strlen(cfg->address))) {
			demo_print_error_ssl_errq(
			    "Could not configure transparent middlebox address.");
			goto error;
		}
	}
	
	middlebox->listen_socket = socket(middlebox->listen_addr->sa_family,
	    SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (middlebox->listen_socket == -1) {
		demo_print_errno("Listen socket creation failed");
		goto error;
	}

	optval = 1;
	if (setsockopt(middlebox->listen_socket, SOL_SOCKET, SO_REUSEADDR,
		&optval, sizeof(optval)) == -1) {
		demo_print_errno("Set SO_REUSEADDR on listen socket failed");
		goto error;
	}
	
	if (bind(middlebox->listen_socket, middlebox->listen_addr, addr_len) == -1) {
		demo_print_errno("Listen socket bind failed");
		demo_print_error_sockaddr("Listen address is ", middlebox->listen_addr);
		goto error;
	}

	if (listen(middlebox->listen_socket, SOMAXCONN) == -1) {
		demo_print_errno("Listen failed");
		goto error;
	}

	demo_log_sockaddr(1, "Listening on ", middlebox->listen_addr);
	
	ev_io_init(&middlebox->listen_watcher, accept_cb,
	    middlebox->listen_socket, EV_READ);
	middlebox->listen_watcher.data = middlebox;
	ev_io_start(EV_A_ &middlebox->listen_watcher);

	return (middlebox);

error:
	demo_app_free(middlebox->app);
	return (NULL);
}

static void
free_middlebox_cb(void *app_data)
{
	struct middlebox_state *middlebox = app_data;

	demo_log_msg(1, "Shutting down listen socket");
	
	if (middlebox->listen_socket != -1)
		close(middlebox->listen_socket);
	
	if (middlebox->listen_addr != NULL)
		free(middlebox->listen_addr);
	if (middlebox->next_addr != NULL)
		free(middlebox->next_addr);

	if (middlebox->ssl_ctx != NULL)
		SSL_CTX_free(middlebox->ssl_ctx);

	free(middlebox);
}

static void
accept_cb(EV_P_ ev_io *w, int revents)
{
	struct middlebox_state *middlebox = w->data;
	int sock;
	unsigned int i;

	SET_LOG_TAG(middlebox);

	for (i = 0; i < middlebox->accept_batch_limit; i++) {
		sock = accept4(middlebox->listen_socket, NULL, NULL, SOCK_NONBLOCK);
		if (sock == -1)
			break;
		
		if (!new_splice(middlebox, sock))
			continue;
	}
}

static bool
new_splice(struct middlebox_state *middlebox, int sock)
{
	struct splice_state *splice_state;
	struct demo_splice *splice;

	splice_state = calloc(1, sizeof(*splice_state));
	if (splice_state == NULL) {
		demo_print_errno("Failed to allocate splice state");
		return (false);
	}
	splice_state->middlebox = middlebox;

	splice  = demo_splice_create(middlebox->app, free_splice_cb,
	    NULL, splice_state, middlebox->splice_counter++,
	    middlebox->cfg->activities_to_client,
	    middlebox->cfg->num_activities_to_client,
	    middlebox->cfg->activities_to_server,
	    middlebox->cfg->num_activities_to_server);
	if (splice == NULL) {
		free(splice_state);
		return (false);
	}
	splice_state->splice = splice;
	
	if (!demo_splice_init_io_to_client(splice, middlebox->ssl_ctx, sock,
		middlebox->loop, connection_died, connected_cb, conn_cb,
		EV_READ))
		goto error;
	TLMSP_set_address_match_cb_instance(splice->to_client->ssl, address_match_cb,
	    middlebox);
	demo_splice_start_io_to_client(splice);

	return (splice_state);

error:
	demo_splice_free(splice);
	return (NULL);
}

static void
free_splice_cb(void *app_data)
{
	struct splice_state *splice_state = app_data;

	if (splice_state->next_hop_addr != NULL)
		OPENSSL_free(splice_state->next_hop_addr);

	TLMSP_reconnect_state_free(splice_state->reconnect_state);
	free(splice_state);
}

static void
connection_died(struct demo_connection *conn)
{
	struct demo_splice *splice = conn->splice;
	
	demo_splice_stop_io(splice);
	demo_splice_free(splice);
}

static bool
check_connection(struct demo_connection *conn)
{
	struct demo_splice *splice = conn->splice;
	struct splice_state *splice_state = splice->app_data;
	
	/*
	 * If we arrived here due to SSL_ERROR_WANT_RECONNECT, there will be
	 * reconnect state to use to create the new connection that will
	 * replace this one.
	 */
	if (splice_state->reconnect_state != NULL) {
		/* XXX not yet supported */
		connection_died(conn);
		return (false);
	} else if (!conn->read_eof) {
		connection_died(conn);
		return (false);
	} else { /* read_eof is set */
		if (conn->other_side->read_eof) {
			connection_died(conn);
			return (false);
		}

		/*
		 * Stop this connection
		 */
		demo_connection_stop_io(conn);

		/*
		 * If the other side is alive flush all containers in this
		 * connection's read queue to it.
		 */
		if (conn->other_side->is_connected) {
			/*
			 * Give match action a chance to operate on the read
			 * queue as it may now have new containers that were
			 * just added.
			 */
			if (!demo_activity_process_read_queue(conn))
				demo_conn_print_error(conn,
				    "Pre-flush activity processing failed");

			/*
			 * Flush any containers not claimed by match-action
			 * through to the other side.
			 */
			demo_conn_log(2, conn, "Flushing all containers in "
			    "read queue to other side");
			/*
			 * container_queue_drain() will always arrange a
			 * callback for the next writable event on the
			 * other_side, which will then drive whatever write
			 * queue drain and shutdown behavior is required.
			 */
			container_queue_drain(&conn->read_queue,
			    &conn->other_side->write_queue);
		}
	}

	return (true);
}

static void
connected_cb(struct demo_connection *conn)
{
	struct demo_splice *splice = conn->splice;
	struct splice_state *splice_state = splice->app_data;
	struct middlebox_state *middlebox = splice_state->middlebox;

	SET_LOG_TAG(middlebox);
}

static void
conn_cb(EV_P_ ev_io *w, int revents)
{
	struct demo_connection *conn = w->data;
	struct demo_splice *splice = conn->splice;
	struct splice_state *splice_state = splice->app_data;
	struct middlebox_state *middlebox = splice_state->middlebox;
	struct demo_connection *conn_to_client = splice->to_client;
	struct demo_connection *conn_to_server = splice->to_server;
	int result;
	int ssl_error;
	bool pending_writes;

	SET_LOG_TAG(middlebox);

	demo_splice_pause_io(splice);
	demo_connection_events_arrived(conn, revents);

	if (revents & EV_ERROR) {
		demo_conn_print_error(conn, "Socket error");
		connection_died(conn);
		return;
	}

	switch (conn->phase) {
	case DEMO_CONNECTION_PHASE_HANDSHAKE:
do_handshake:
		result = TLMSP_middlebox_handshake(conn_to_client->ssl,
		    conn_to_server->ssl, &ssl_error);
		switch (result) {
		case 0:
			demo_conn_print_error(conn, "Handshake terminated by protocol");
			connection_died(conn);
			return;
			break;
		case 1:
			demo_conn_log(1, conn, "Handshake complete");
			demo_connection_wait_for(conn, EV_READ);
			if (!demo_splice_handshake_complete(splice)) {
				connection_died(conn);
				return;
			}
			break;
		default:
			switch (ssl_error) {
			case SSL_ERROR_WANT_OUTBOUND_CONN:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_OUTBOUND_CONN");
				/*
				 * Establish outbound connection and
				 * re-enter handshake.
				 */
				if (!new_outbound_connection(splice, NULL)) {
					connection_died(conn);
					return;
				} else
					goto do_handshake;
				break;
			case SSL_ERROR_WANT_RECONNECT:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_RECONNECT");
				/*
				 * Re-establish outbound connection and
				 * re-enter handshake.
				 */
				splice_state->reconnect_state =
				    TLMSP_get_reconnect_state(conn->ssl);
				if (!check_connection(splice->to_server))
					return;
				break;
			case SSL_ERROR_WANT_READ:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_READ");
				demo_connection_wait_for(conn_to_client, EV_READ);
				demo_connection_wait_for(conn_to_server, EV_READ);
				break;
			case SSL_ERROR_WANT_CLIENT_WRITE:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_CLIENT_WRITE");
				demo_connection_wait_for(conn_to_client, EV_WRITE);
				break;
			case SSL_ERROR_WANT_SERVER_WRITE:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_SERVER_WRITE");
				demo_connection_wait_for(conn_to_server, EV_WRITE);
				break;
			default:
				demo_conn_print_error_ssl(conn, ssl_error,
				    "Handshake terminated due to fatal error");
				connection_died(conn);
				return;
				break;
			}
			break;
		}
		break;
	case DEMO_CONNECTION_PHASE_APPLICATION:

		/*
		 * Try to process any pending writes
		 */
		pending_writes = demo_connection_writes_pending(conn);
		if (pending_writes) {
			switch (write_containers(conn)) {
			case -1:
				if (!check_connection(conn))
					return;
				break;
			case 1:
				demo_connection_set_phase(conn,
				    DEMO_CONNECTION_PHASE_HANDSHAKE);
				goto do_handshake;
				break;
			}
			/*
			 * Update pending_writes - we may have drained them all.
			 */
			pending_writes = demo_connection_writes_pending(conn);
		}
		/*
		 * Propagate upstream read-side shutdown downstream.
		 * demo_connection_shutdown() is idempotent, so we don't
		 * need to sort out whether it's been invoked already.
		 */
		if (!pending_writes && conn->other_side->read_eof)
			demo_connection_shutdown(conn);

		/*
		 * If we are out of pending write data, do some reading.
		 */
		if (!pending_writes) {
			switch (read_containers(conn)) {
			case -1:
				if (!check_connection(conn))
					return;
				break;
			case 1:
				demo_connection_set_phase(conn,
				    DEMO_CONNECTION_PHASE_HANDSHAKE);
				goto do_handshake;
				break;
			}
		}

		/*
		 * If none of the above processing requires a further read
		 * or write event, wait for new data to arrive.
		 */
		if (demo_connection_wait_events(conn) == 0)
			demo_connection_wait_for(conn, EV_READ);
		break;
	default:
		demo_conn_print_error(conn,
		    "Unexpected connection phase %d", conn->phase);
		connection_died(conn);
		return;
		break;
	}

	demo_splice_resume_io(splice);
}

/*
 * Return values:
 *  -1 - fatal error
 *   0 - stay in application phase (wait_events will be modified)
 *   1 - move to handshake phase
 */
static int
read_containers(struct demo_connection *conn)
{
	struct demo_splice *splice = conn->splice;
	struct splice_state *splice_state = splice->app_data;
	struct middlebox_state *middlebox = splice_state->middlebox;
	SSL *ssl = conn->ssl;
	TLMSP_Container *container;
	int result;
	int ssl_result;
	int ssl_error;

	/*
	 * Approach:
	 *   - Read all available, or until the read queue fills
	 *   - If no fatal errors, process the read queue
	 */

	/*
	 * Always do at least one read.  We should never have a full read
	 * queue on entry as the receive qeueue processing that follows the
	 * read loop ensures it is not left in a full state.
	 */
	result = 0;
	do {
		ssl_result = TLMSP_container_read(ssl, &container);
		if (ssl_result > 0) {
			demo_conn_log(2, conn, "Received container (length=%u) "
			    "in context %u",
			    TLMSP_container_length(container),
			    TLMSP_container_context(container));
			if (TLMSP_container_deleted(container))
				demo_conn_log(3, conn, "Container marked deleted");
			else if (!TLMSP_container_readable(container))
				demo_conn_log(3, conn, "Container is opaque");
			else if (TLMSP_container_alert(container, NULL) == 1)
				demo_conn_log(3, conn, "Container is an alert");
			else
				demo_conn_log_buf(3, conn,
				    TLMSP_container_get_data(container),
				    TLMSP_container_length(container), true,
				    "Container data");
			if (!container_queue_add(&conn->read_queue, container)) {
				TLMSP_container_free(ssl, container);
				result = -1;
				break; /* leave loop */
			}
		} else {
			ssl_error = SSL_get_error(conn->ssl, ssl_result);
			switch (ssl_error) {
			case SSL_ERROR_WANT_HANDSHAKE:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_HANDSHAKE");
				result = 1;
				break;
			case SSL_ERROR_WANT_READ:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_READ");
				demo_connection_wait_for(conn, EV_READ);
				break;
			case SSL_ERROR_WANT_WRITE:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_WRITE");
				demo_connection_wait_for(conn, EV_WRITE);
				break;
			case SSL_ERROR_ZERO_RETURN:
				demo_conn_log(5, conn, "SSL_ERROR_ZERO_RETURN");
				conn->read_eof = true;
				result = -1;
				break;
			default:
				demo_conn_print_error_ssl(conn, ssl_error,
				    "Connection terminated due to fatal read error");
				conn->read_eof = true;
				result = -1;
				break;
			}

			break; /* leave loop */
		}
	} while (conn->read_queue.length < middlebox->read_buffer_limit);

	if (result >= 0)
		if (!demo_activity_process_read_queue(conn))
			result = -1;

	return (result);
}

/*
 * Return values:
 *  -1 - fatal error
 *   0 - stay in application phase (wait_events will be modified)
 *   1 - move to handshake phase
 */
static int
write_containers(struct demo_connection *conn)
{
	SSL *ssl = conn->ssl;
	TLMSP_Container *container;
	int result;
	int ssl_result;
	int ssl_error;

	result = 0;
	while ((container = container_queue_head(&conn->write_queue)) != NULL) {
		demo_conn_log(2, conn, "Sending container (length=%u) "
		    "in context %u",
		    TLMSP_container_length(container),
		    TLMSP_container_context(container));
		if (TLMSP_container_deleted(container))
			demo_conn_log(3, conn, "Container marked deleted");
		else if (!TLMSP_container_readable(container))
			demo_conn_log(3, conn, "Container is opaque");
		else if (TLMSP_container_alert(container, NULL) == 1)
			demo_conn_log(3, conn, "Container is an alert");
		else
			demo_conn_log_buf(3, conn,
			    TLMSP_container_get_data(container),
			    TLMSP_container_length(container), true,
			    "Container data");
		ssl_result = TLMSP_container_write(ssl, container);
		if (ssl_result > 0) {
			demo_conn_log(2, conn, "Container send complete (result = %d)", ssl_result);
			container_queue_remove_head(&conn->write_queue);
		} else {
			ssl_error = SSL_get_error(ssl, ssl_result);
			switch (ssl_error) {
			case SSL_ERROR_WANT_HANDSHAKE:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_HANDSHAKE");
				result = 1;
				break;
			case SSL_ERROR_WANT_READ:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_READ");
				demo_connection_wait_for(conn, EV_READ);
				break;
			case SSL_ERROR_WANT_WRITE:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_WRITE");
				demo_connection_wait_for(conn, EV_WRITE);
				break;
			default:
				demo_conn_print_error_ssl(conn, ssl_error,
				    "Connection terminated due to fatal write error");
				result = -1;
				break;
			}

			break; /* leave loop */
		}
	}
	
	return (result);
}


static bool
new_outbound_connection(struct demo_splice *splice,
    const TLMSP_ReconnectState *reconnect_state)
{
	struct demo_connection *inbound_conn = splice->to_client;
	struct splice_state *splice_state = splice->app_data;
	struct middlebox_state *middlebox = splice_state->middlebox;
	struct sockaddr *outbound_addr;
	socklen_t outbound_addr_len;
	int sock;
	bool result = false;

	if (reconnect_state == NULL) {
		/*
		 * First round outbound connection.
		 */
		if (middlebox->cfg->transparent) {
			/*
			 * If we are a transparent middlebox, then normally
			 * the next hop would be determined by the
			 * destination IP of the inbound connection.  In
			 * this demo, transparency at the IP layer is
			 * emulated, not actual, so the destination IP of
			 * the inbound connection does not indicate the next
			 * hop.  The next hop is instead determined by the
			 * address of the next middlebox in the
			 * configuration file (if present, now in
			 * middlebox->next_addr), or if there was not a next
			 * middlebox in the configuration, the address of
			 * the server from the ClientHello.
			 */
			if (middlebox->next_addr == NULL)
				if (!TLMSP_get_server_address_instance(
					inbound_conn->ssl,
					&splice_state->next_hop_addr_type,
					&splice_state->next_hop_addr,
					&splice_state->next_hop_addr_len))
					return (false);
		} else {
			/*
			 * If we are not a transparent middlebox, then the
			 * next hop will come from the next entry in the
			 * middlebox list present in the ClientHello, or if
			 * there is no next entry in the middlebox list,
			 * then from the server address in the ClientHello.
			 */
			if (!TLMSP_get_next_hop_address_instance(
				inbound_conn->ssl,
				&splice_state->next_hop_addr_type,
				&splice_state->next_hop_addr,
				&splice_state->next_hop_addr_len))
				return (false);
		}
	} else {
		/*
		 * Second round (post-discovery with changed next hop)
		 * connection attempt.  Normally, a middlebox would call
		 * TLMSP_get_next_hop_address_reconnect() to determine the
		 * address to connect the transport to based on the
		 * middlebox list contained in the reconnect state.  Here,
		 * we call TLMSP_get_next_hop_address_reconnect_ex() in
		 * order to support emulated transparency, under which the
		 * next hop may be a discovered transparent middlebox which
		 * normally would not be considered the next hop to connect
		 * to.
		 */
		if (!TLMSP_get_next_hop_address_reconnect(
			splice_state->reconnect_state,
			&splice_state->next_hop_addr_type,
			&splice_state->next_hop_addr,
			&splice_state->next_hop_addr_len))
			return (false);
	}

	if (middlebox->next_addr != NULL) {
		outbound_addr = middlebox->next_addr;
		middlebox->next_addr = NULL;  /* we will free it via outbound_addr */
		outbound_addr_len = middlebox->next_addr_len;
	} else {
		outbound_addr =
		    tlmsp_util_address_to_sockaddr(splice_state->next_hop_addr_type,
			splice_state->next_hop_addr, splice_state->next_hop_addr_len,
			&outbound_addr_len, middlebox->port_shift,
			middlebox->app->errbuf, sizeof(middlebox->app->errbuf));
		if (outbound_addr == NULL) {
			demo_print_error("Could not convert outbound address "
			    "'%s' to sockaddr: %s", outbound_addr,
			    middlebox->app->errbuf);
			return (false);
		}
	}

	sock = socket(outbound_addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (sock == -1) {
		demo_print_errno("Outbound socket creation failed");
		goto error;
	}

	if ((connect(sock, outbound_addr, outbound_addr_len) == -1) &&
	    (errno != EINPROGRESS)) {
		demo_print_errno("Outbound connect failed");
		goto error;
	}

	if (!demo_splice_init_io_to_server(splice, middlebox->ssl_ctx, sock,
		middlebox->loop, connection_died, connected_cb, conn_cb,
		EV_READ))
		goto error;
	demo_splice_start_io_to_server(splice);

	result = true;
	
 error:
	free(outbound_addr);
	return (result);
}

static int
address_match_cb(SSL *ssl, int type, const uint8_t *addr, size_t len, void *arg)
{
	struct middlebox_state *middlebox = arg;

	if (type != TLMSP_ADDRESS_URL || len == 0)
		return (0);

	if (middlebox->cfg->transparent) {
		/*
		 * If we are a transparent middleboxes, we are looking for a
		 * match to the next hop identity, which in practice would
		 * be built based on the destination IP of the inbound
		 * connection.  In this demo, we've built it based on the
		 * configuration file contents, as transparent behavior at
		 * the IP level is emulated, not actual.
		 */
	} else {
		/*
		 * If we are a non-transparent middlebox, we are looking for
		 * a match to our own sense of self.
		 */
		if (strlen(middlebox->cfg->address) != len ||
		    memcmp(middlebox->cfg->address, addr, len) != 0)
			return (0);
		return (1);
	}

	return (0);
}

int main(int argc, char **argv)
{
	int opt_index;
	int opt_code;
	const char *cfg_file;
	int port_shift;
	bool all_tags;
	bool force_presentation;
	bool has_config;
	bool has_tag;
	const char *tags[TLMSP_UTIL_MAX_MIDDLEBOXES];
	unsigned int num_tags;
	unsigned int i;
	struct ev_loop *loop;
	const struct tlmsp_cfg *cfg;
	struct middlebox_state *middleboxes[TLMSP_UTIL_MAX_MIDDLEBOXES];
	unsigned int num_middleboxes;

	/*
	 * argv[0] may be modified by basename(), and future calls to
	 * basename() may modify the memory the result pointer refers to.
	 */
	demo_progname = strdup(basename(argv[0]));
	demo_pid = getpid();
	demo_signal_handling_init();

	port_shift = 0;
	all_tags = false;
	force_presentation = false;
	has_config = false;
	has_tag = false;
	num_tags = 0;
	opterr = 0; /* prevent getopt from printing its own error messages */
	for (;;) {
		opt_index = 0;
		opt_code = getopt_long(argc, argv, ":ac:e:hPp:t:v", options,
		    &opt_index);

		if (opt_code == -1)
			break;

		switch (opt_code)
		{
		case OPT_CONFIG_ALL_TAGS:
			all_tags = true;
			has_tag = true;
			break;
		case OPT_CONFIG_FILE:
			cfg_file = optarg;
			has_config = true;
			break;
		case OPT_ERROR_FILE:
			if (strcmp(optarg, "-") == 0)
				demo_error_fd = STDOUT_FILENO;
			else {
				demo_error_fd = open(optarg,
				    O_CREAT | O_WRONLY | O_APPEND,
				    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				if (demo_error_fd == -1) {
					demo_error_fd = STDERR_FILENO;
					usage(true);
				}
			}
			break;
		case OPT_PORT_SHIFT:
			port_shift = strtol(optarg, NULL, 10);
			break;
		case OPT_PRESENTATION:
			force_presentation = true;
			break;
		case OPT_CONFIG_TAG:
			if (num_tags == TLMSP_UTIL_MAX_MIDDLEBOXES) {
				demo_print_error("There can be no more than %u "
				    "middleboxes", TLMSP_UTIL_MAX_MIDDLEBOXES);
				exit(1);
			}
			for (i = 0; i < num_tags; i++) {
				if (strcmp(tags[i], optarg) == 0) {
					demo_print_error("Duplicate tag '%s'",
					    optarg);
					exit(1);
				}
			}
			tags[num_tags] = optarg;
			num_tags++;
			has_tag = true;
			break;
		case OPT_HELP:
			usage(false);
			break;
		case OPT_VERBOSE:
			demo_verbose++;
			break;
		case ':':
			demo_print_error("Missing argument to option %s",
			    argv[optind - 1]);
			usage(true);
		case '?':
			demo_print_error("Unknown option %s", argv[optind - 1]);
			usage(true);
			break;
		default:
			/*
			 * known but unhandled option - should never
			 * happen
			 */
			demo_print_error("Internal error: unhandled option %s",
			    argv[optind - 1]);
			usage(true);
			break;
		}
	}

	if (!has_config || !has_tag) {
		demo_print_error("config file and tag must be specified");
		usage(true);
	}
	
	loop = ev_default_loop(EVFLAG_AUTO);

	if (all_tags) {
		char errbuf[DEMO_ERRBUF_SIZE];

		cfg = tlmsp_cfg_parse_file(cfg_file, errbuf,  sizeof(errbuf));
		if (cfg == NULL) {
			demo_print_error("Failed to parse config file: %s",
			    errbuf);
			exit(1);
		}
		num_tags = cfg->num_middleboxes;
		if (num_tags > TLMSP_UTIL_MAX_MIDDLEBOXES) {
			demo_print_error("There can be no more than %u "
			    "middleboxes", TLMSP_UTIL_MAX_MIDDLEBOXES);
			exit(1);
		}
		for (i = 0; i < num_tags; i++)
			tags[i] = cfg->middleboxes[i].tag;
	}

	num_middleboxes = num_tags;
	for (i = 0; i < num_middleboxes; i++) {
		SET_LOG_TAG(NULL);
		middleboxes[i] = new_middlebox(loop, cfg_file, tags[i],
		    force_presentation, port_shift);
		if (middleboxes[i] == NULL) {
			demo_print_error("Failed to created new middlebox '%s'",
			    tags[i]);
			exit(1);
		}
	}

	if (all_tags)
		tlmsp_cfg_free(cfg);

	demo_signal_monitor_start(EV_A);

	ev_run(EV_A_ 0);
	/*
	 * Now that the event loop has exited, all log messages are
	 * process-level.
	 */
	SET_LOG_TAG(NULL);

	for (i = 0; i < num_middleboxes; i++) {
		SET_LOG_TAG(middleboxes[i]);
		demo_app_free(middleboxes[i]->app);
	}
	SET_LOG_TAG(NULL);
	if ((demo_error_fd != STDERR_FILENO) && (demo_error_fd != STDOUT_FILENO))
		close(demo_error_fd);
	demo_log_msg(0, "Clean shutdown complete.\n");
	free((void *)demo_progname);
	
	return (0);
}
