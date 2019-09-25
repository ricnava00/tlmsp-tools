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
#include <libtlmsp-cfg-openssl.h>
#include <libtlmsp-util.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libdemo/activity.h>
#include <libdemo/app.h>
#include <libdemo/connection.h>
#include <libdemo/print.h>
#include <libdemo/signal.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "client.h"


enum {
	OPT_CONFIG_FILE    = 'c',
	OPT_ERROR_FILE     = 'e',
	OPT_HELP           = 'h',
	OPT_PRESENTATION   = 'P',
	OPT_PORT_SHIFT     = 'p',
	OPT_STREAM_API     = 's',
	OPT_VERBOSE        = 'v'
};


static void usage(bool is_error);
static void show_client_info_cb(void *app_data);
static struct client_state *new_client(struct ev_loop *loop,
                                       const char *cfg_file,
                                       bool use_stream_api,
                                       bool force_presentation,
                                       int port_shift);
static void free_client_cb(void *app_data);
static bool new_connection(struct client_state *client,
	                   const TLMSP_ReconnectState *reconnect_state);
static void show_connection_info(void *app_data);
static int validate_discovery_results(SSL *ssl, void *arg,
                                      TLMSP_Middleboxes *middleboxes);
static void free_connection_cb(void *app_data);
static void connection_died(struct demo_connection *conn);
static void conn_cb(EV_P_ ev_io *w, int revents);
static bool read_containers(struct demo_connection *conn);
static bool write_containers(struct demo_connection *conn);


static struct option options[] =
{
	{"config",         required_argument, 0, OPT_CONFIG_FILE},
	{"errors",         required_argument, 0, OPT_ERROR_FILE},
	{"help",           no_argument,       0, OPT_HELP},
	{"port-shift",     required_argument, 0, OPT_PORT_SHIFT},
	{"presentation",   no_argument,       0, OPT_PRESENTATION},
	{"stream-api",     no_argument,       0, OPT_STREAM_API},
	{"verbose",        no_argument,       0, OPT_VERBOSE},
	{NULL, 0, NULL, 0}
};


static void
usage(bool is_error)
{
	int fd = is_error ? demo_error_fd : STDOUT_FILENO;
	int exit_code = is_error ? 1 : 0;

	dprintf(fd, "\n");
	dprintf(fd, "Usage: %s [options] (-c <file> | --config <file>)\n", demo_progname);
	dprintf(fd, "\n");
	dprintf(fd, "Options:\n");
	dprintf(fd, "  -c <file>, --config <file>  TLMSP config file\n");
	dprintf(fd, "  -e <file>, --errors <file>  Send error messages to file (- means stdout). List\n");
	dprintf(fd, "                              first to redirect all errors [default: stderr]\n");
	dprintf(fd, "  -h, --help                  Print this message\n");
	dprintf(fd, "  -P, --presentation          Force presentation of activities\n");
	dprintf(fd, "  -p, --port-shift <delta>    Shift all port numbers in configuration by this amount [default: 0]\n");
	dprintf(fd, "  -s, --stream-api            Use stream read/write API [default: container API]\n");
	dprintf(fd, "  -v, --verbose               Raise verbosity level by one [default: 0]\n");
	dprintf(fd, "\n");
	exit(exit_code);
}

static void
show_client_info_cb(void *app_data)
{
	struct client_state *client = app_data;

	demo_print_error("read-write-api: %s",
	    client->use_stream_api ? "stream" : "container");
}

static struct client_state *
new_client(struct ev_loop *loop, const char *cfg_file, bool use_stream_api,
    bool force_presentation, int port_shift)
{
	struct client_state *client;
	struct demo_app *app;
	const struct tlmsp_cfg_client *cfg;
	TLMSP_Contexts *tlmsp_contexts = NULL;
	TLMSP_Middleboxes *tlmsp_middleboxes = NULL;
	int address_type;

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		demo_print_errno("Client state allocation failed");
		return (NULL);
	}

	app = demo_app_create(false, free_client_cb, show_client_info_cb,
	    client, 0, cfg_file, force_presentation);
	if (app == NULL) {
		free(client);
		return (NULL);
	}
	client->app = app;

	client->cfg = &app->cfg->client;
	cfg = client->cfg;
	demo_log_msg(1, "Creating client '%s'", cfg->address);
	client->loop = loop;
	client->port_shift = port_shift;
	client->use_stream_api = use_stream_api;

	client->ssl_ctx = SSL_CTX_new(TLMSP_client_method());
	if (client->ssl_ctx == NULL) {
		demo_print_error_ssl_errq("Failed to create SSL_CTX");
		goto error;
	}

	/*
	 * Configure contexts
	 */
	tlmsp_contexts = tlmsp_cfg_contexts_to_openssl(app->cfg);
	if (tlmsp_contexts == NULL) {
		demo_print_error("No contexts are defined");
		goto error;
	}
	if (!TLMSP_set_contexts(client->ssl_ctx, tlmsp_contexts)) {
		demo_print_error_ssl_errq("Failed to set contexts");
		goto error;
	}
	TLMSP_contexts_free(tlmsp_contexts);
	tlmsp_contexts = NULL;
	
	/*
	 * Configure client and server addresses
	 */
	address_type = tlmsp_util_address_type(cfg->address);
	if (address_type == TLMSP_UTIL_ADDRESS_UNKNOWN) {
		demo_print_error("Failed to determine address type for client "
		    "(address '%s')", cfg->address);
		goto error;
	}
	if (!TLMSP_set_client_address(client->ssl_ctx, address_type,
		(const uint8_t *)cfg->address, strlen(cfg->address))) {
		demo_print_error_ssl_errq("Failed to set client address '%s'",
		    cfg->address);
		goto error;
	}

	address_type = tlmsp_util_address_type(app->cfg->server.address);
	if (address_type == TLMSP_UTIL_ADDRESS_UNKNOWN) {
		demo_print_error("Failed to determine address type for server "
		    "(address '%s')", app->cfg->server.address);
		goto error;
	}
	if (!TLMSP_set_server_address(client->ssl_ctx, address_type,
		(const uint8_t *)app->cfg->server.address,
		strlen(app->cfg->server.address))) {
		demo_print_error_ssl_errq("Failed to set server address '%s'",
		    app->cfg->server);
		goto error;
	}
		
	/*
	 * Configure initial middlebox list
	 */
	tlmsp_middleboxes = tlmsp_cfg_initial_middlebox_list_to_openssl(app->cfg);
	if (tlmsp_middleboxes != NULL) {
		if (!TLMSP_set_initial_middleboxes(client->ssl_ctx,
			tlmsp_middleboxes)) {
			demo_print_error_ssl_errq("Failed to set middlebox list");
			goto error;
		}
		TLMSP_middleboxes_free(tlmsp_middleboxes);
	}

	if (!new_connection(client, NULL)) {
		demo_print_error("Failed to create connection");
		goto error;
	}
	
	return (client);

error:
	TLMSP_contexts_free(tlmsp_contexts);
	TLMSP_middleboxes_free(tlmsp_middleboxes);
	demo_app_free(client->app);
	return (NULL);
}

static void
free_client_cb(void *app_data)
{
	struct client_state *client = app_data;

	if (client->ssl_ctx != NULL)
		SSL_CTX_free(client->ssl_ctx);

	free(client);
}

static bool
new_connection(struct client_state *client,
    const TLMSP_ReconnectState *reconnect_state)
{
	struct connection_state *conn_state;
	struct demo_connection *conn;
	struct sockaddr *addr = NULL;
	socklen_t addr_len;
	uint8_t *first_hop_addr = NULL;
	char *first_hop_addr_str;
	size_t first_hop_addr_len;
	int first_hop_addr_type;
	int sock;

	conn_state = calloc(1, sizeof(*conn_state));
	if (conn_state == NULL) {
		demo_print_errno("Failed to allocate connection state");
		return (false);
	}
	conn_state->client = client;

	conn = demo_connection_create(client->app, free_connection_cb,
	    show_connection_info, conn_state, client->connection_counter++,
	    client->cfg->activities, client->cfg->num_activities);
	if (conn == NULL) {
		free(conn_state);
		return (false);
	}
	conn_state->conn = conn;

	/*
	 * The maximum amount of new application data from an SSL_read()
	 * TLMSP_CONTAINER_MAX_SIZE less the minimum overhead of a
	 * container.
	 */
	conn_state->read_buffer_size = TLMSP_CONTAINER_MAX_SIZE;
	conn_state->read_buffer = malloc(conn_state->read_buffer_size);
	if (conn_state->read_buffer == NULL) {
		demo_print_errno("Failed to allocate read buffer");
		goto error;
	}
	
	if (reconnect_state == NULL) {
		/*
		 * First round TLMSP connection attempt.  Normally, a client
		 * would call TLMSP_get_first_hop_address() to determine the
		 * address to connect the transport to based on the
		 * SSL_CTX's configured middlebox list and server.  In order
		 * to support emulated transparency, we determine the first
		 * hop address using the configuration file, as the first
		 * hop may be a transparent middlebox that is to be
		 * discovered and is thus not in the SSL_CTX's configured
		 * middlebox list.
		 */
		first_hop_addr_str = tlmsp_cfg_get_client_first_hop_address(
		    client->app->cfg, false, true, &first_hop_addr_type);
		if (first_hop_addr_str == NULL) {
			demo_print_error("Could not determine first hop address");
			goto error;
		}
		first_hop_addr_len = strlen(first_hop_addr_str);
		/*
		 * Align allocator with the other branch so common code can
		 * be used from this point on.
		 */
		first_hop_addr = OPENSSL_memdup(first_hop_addr_str,
		    first_hop_addr_len);
		free(first_hop_addr_str);
		if (first_hop_addr == NULL) {
			demo_print_error("Failed to change first hop address "
			    "allocator");
			goto error;
		}
	} else {
		/*
		 * Second round (post-discovery with changed first hop)
		 * TLMSP connection attempt.  Normally, a client would call
		 * TLMSP_get_first_hop_address_reconnect() to determine the
		 * address to connect the transport to based on the
		 * middlebox list contained in the reconnect state.  Here,
		 * we call TLMSP_get_first_hop_address_reconnect_ex() in
		 * order to support emulated transparency, under which the
		 * first hop may be a discovered transparent middlebox which
		 * normally would not be considered the first hop to connect
		 * to.
		 */
		if (!TLMSP_get_first_hop_address_reconnect_ex(reconnect_state,
			&first_hop_addr_type, &first_hop_addr,
			&first_hop_addr_len, 1)) {
			demo_print_error_ssl_errq(
			    "Failed to get first hop address");
			goto error;
		}
	}
	addr = tlmsp_util_address_to_sockaddr(first_hop_addr_type,
	    first_hop_addr, first_hop_addr_len, &addr_len, client->port_shift,
	    client->app->errbuf, sizeof(client->app->errbuf));
	if (addr == NULL) {
		demo_print_error("Could not convert next hop address '%.*s' to "
		    "sockaddr: %s", first_hop_addr_len, first_hop_addr,
		    client->app->errbuf);
		goto error;
	}
	demo_conn_log_sockaddr(1, conn, "First hop address is ", addr);
	OPENSSL_free(first_hop_addr);

	sock = socket(addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (sock == -1) {
		demo_print_errno("Socket creation failed");
		goto error;
	}

	if ((connect(sock, addr, addr_len) == -1) &&
	    (errno != EINPROGRESS)) {
		demo_print_errno("Connect failed");
		goto error;
	}
	free(addr);
	addr = NULL;

	if (!demo_connection_init_io(conn, client->ssl_ctx, sock, client->loop,
		connection_died, NULL, conn_cb, EV_WRITE))
		goto error;

	SSL_set_connect_state(conn->ssl);

	TLMSP_set_discovery_cb_instance(conn->ssl, validate_discovery_results,
	    conn);

	if (reconnect_state != NULL) {
		if (!TLMSP_set_reconnect_state(conn->ssl, reconnect_state)) {
			demo_print_error_ssl_errq("Failed to set reconnect state");
			goto error;
		}
	}

	demo_connection_start_io(conn);

	return (true);

error:
	free(addr);
	OPENSSL_free(first_hop_addr);
	demo_connection_free(conn);
	return (false);
}

static void
show_connection_info(void *app_data)
{
	struct connection_state *conn_state = app_data;

	demo_conn_print_error(conn_state->conn, "has-reconnect-state: %s",
	    (conn_state->reconnect_state != NULL) ? "yes" : "no");
}

static void
free_connection_cb(void *app_data)
{
	struct connection_state *conn_state = app_data;

	TLMSP_reconnect_state_free(conn_state->reconnect_state);
	free(conn_state->read_buffer);
	free(conn_state);
}

static int
validate_discovery_results(SSL *ssl, void *arg, TLMSP_Middleboxes *middleboxes)
{
	struct demo_connection *conn = arg;
	const struct tlmsp_cfg *cfg = conn->app->cfg;
	int result;

	result = tlmsp_cfg_validate_middlebox_list_client_openssl(cfg,
		middleboxes);
	return (result);
}

static void
connection_died(struct demo_connection *conn)
{
	struct connection_state *conn_state = conn->app_data;
	struct client_state *client = conn_state->client;

	demo_connection_stop_io(conn);

	/*
	 * If we arrived here due to SSL_ERROR_WANT_RECONNECT, there will be
	 * reconnect state to use to create the new connection that will
	 * replace this one.
	 */
	if (conn_state->reconnect_state != NULL) {
		if (!new_connection(client, conn_state->reconnect_state))
			demo_conn_print_error(conn,
			    "Failed to create replacement connection");
	}

	demo_connection_free(conn);
}

static void
conn_cb(EV_P_ ev_io *w, int revents)
{
	struct demo_connection *conn = w->data;
	struct connection_state *conn_state = conn->app_data;
	int result;
	int ssl_error;
	bool pending_writes;

	demo_connection_pause_io(conn);
	demo_connection_events_arrived(conn, revents);

	switch (conn->phase) {
	case DEMO_CONNECTION_PHASE_HANDSHAKE:
		result = SSL_connect(conn->ssl);
		switch (result) {
		case 0:
			demo_conn_print_error(conn, "Handshake terminated by protocol");
			connection_died(conn);
			return;
			break;
		case 1:
			demo_conn_log(1, conn, "Handshake complete");
			demo_connection_wait_for(conn, EV_READ);
			if (!demo_connection_handshake_complete(conn)) {
				connection_died(conn);
				return;
			}
			break;
		default:
			ssl_error = SSL_get_error(conn->ssl, result);
			switch (ssl_error) {
			case SSL_ERROR_WANT_RECONNECT:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_RECONNECT");
				/*
				 * Re-establish outbound connection and
				 * re-enter handshake.
				 */
				conn_state->reconnect_state =
				    TLMSP_get_reconnect_state(conn->ssl);
				if (conn_state->reconnect_state == NULL)
					demo_conn_print_error_ssl_errq(conn,
					    "Reconnect state retrieval failed");
				connection_died(conn);
				return;
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
		 * The general approach is that we prioritize writes over
		 * reads - we work on pending write data until it is all
		 * sent, then we return to reading.
		 *
		 * In the midst of all this, OpenSSL may ask us to wait for
		 * read or write events on the socket either directly
		 * related to reads or writes that we are trying to do, or
		 * related to internal handling of protocol details (e.g.,
		 * renegotiation).
		 */

		/*
		 * Handle pending writes
		 */
		pending_writes = demo_connection_writes_pending(conn);
		if (pending_writes) {
			if (!write_containers(conn)) {
				connection_died(conn);
				return;
			}
			/*
			 * Update pending_writes - we may have drained them all.
			 */
			pending_writes = demo_connection_writes_pending(conn);
		}

		/*
		 * If we are out of pending write data, do some reading.
		 */
		if (!pending_writes) {
			if (!read_containers(conn)) {
				connection_died(conn);
				return;
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

	demo_connection_resume_io(conn);
}

/*
 * Return values:
 *   true  - successful read (wait_events may be modified)
 *   false - fatal error
 */
static bool
read_containers(struct demo_connection *conn)
{
	struct connection_state *conn_state = conn->app_data;
	struct client_state *client = conn_state->client;
	SSL *ssl = conn->ssl;
	int result;
	int ssl_result;
	int ssl_error;
	TLMSP_Container *container;
	size_t length;
	tlmsp_context_id_t context_id;

	/*
	 * Perform the read using the chosen API.  All received data goes
	 * into a container queue, so when using the stream API, a new
	 * container is allocated to hold the received data.
	 */
	if (client->use_stream_api) {
		ssl_result = SSL_read(ssl, conn_state->read_buffer,
		    conn_state->read_buffer_size);
		if (ssl_result > 0) {
			if (!TLMSP_get_last_read_context(ssl, &context_id))
				return (false);
			demo_conn_log(2, conn, "Received container (length=%u) "
			    "in context %u using stream API", ssl_result,
			    context_id);
			if (!TLMSP_container_create(ssl, &container, context_id,
				conn_state->read_buffer, ssl_result))
				return (false);
			if (!container_queue_add(&conn->read_queue, container)) {
				TLMSP_container_free(ssl, container);
				return (false);
			}
		}
	} else {
		ssl_result = TLMSP_container_read(ssl, &container);
		if (ssl_result > 0) {
			context_id = TLMSP_container_context(container);
			length = TLMSP_container_length(container);
			if (TLMSP_container_deleted(container)) {
				demo_conn_log(2, conn, "Received deleted "
				    "container in context %u using container API",
				    context_id);
				TLMSP_container_free(ssl, container);
				return (true);
			} else if (!TLMSP_container_readable(container)) {
				demo_conn_print_error(conn,
				    "Opaque container unexpectedly received in "
				    "context %d using container API", context_id);
				TLMSP_container_free(ssl, container);
				return (false);
			} else {
				demo_conn_log(2, conn, "Received container "
				    "(length=%u) in context %u using container "
				    "API", length, context_id);
				if (!container_queue_add(&conn->read_queue,
					container)) {
					TLMSP_container_free(ssl, container);
					return (false);
				}
			}
		}
	}
	
	/*
	 * Handle all error cases - same treatment for both read APIs.
	 */
	if (ssl_result <= 0) {
		result = true;
		ssl_error = SSL_get_error(ssl, ssl_result);
		switch (ssl_error) {
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
			    "Connection terminated due to fatal read error");
			result = false;
			break;
		}
		return (result);
	}

	demo_conn_log_buf(3, conn, TLMSP_container_get_data(container),
	    TLMSP_container_length(container), true, "Container data");

	if (!demo_activity_process_read_queue(conn))
		return (false);
	
	return (true);
}

/*
 * Return values:
 *   true  - successful write (wait_events may be modified)
 *   false - fatal error
 */
static bool
write_containers(struct demo_connection *conn)
{
	struct connection_state *conn_state = conn->app_data;
	struct client_state *client = conn_state->client;
	SSL *ssl = conn->ssl;
	TLMSP_Container *container;
	size_t length;
	tlmsp_context_id_t context_id;
	int result;
	int ssl_result;
	int ssl_error;

	container = container_queue_head(&conn->write_queue);
	while (container != NULL) {
		context_id = TLMSP_container_context(container);
		length = TLMSP_container_length(container);
		demo_conn_log(2, conn, "Sending container (length=%u) "
		    "in context %u using %s API", length, context_id,
		    client->use_stream_api ? "stream" : "container");
		demo_conn_log_buf(3, conn, TLMSP_container_get_data(container),
		    length, true, "Container data");
		if (client->use_stream_api) {
			if (!TLMSP_set_current_context(ssl, context_id)) {
				demo_conn_print_error(conn,
				    "Failed to set current context to %d",
				    context_id);
				return (false);
			}
			ssl_result = SSL_write(ssl,
			    TLMSP_container_get_data(container), length);
			if (ssl_result > 0) {
				TLMSP_container_free(ssl, container);
			}
		} else {
			ssl_result = TLMSP_container_write(ssl, container);
		}
		if (ssl_result > 0) {
			demo_conn_log(2, conn,
			    "Container send complete (result=%d)", ssl_result);
			container_queue_remove_head(&conn->write_queue);
			container = container_queue_head(&conn->write_queue);
		} else {
			demo_conn_log(2, conn, "Channel not ready");
			break;
		}
	}
	result = true;
	if (ssl_result <= 0) {
		ssl_error = SSL_get_error(ssl, ssl_result);
		switch (ssl_error) {
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
			result = false;
			break;
		}
	}
	
	return (result);
}

int main(int argc, char **argv)
{
	int opt_index;
	int opt_code;
	const char *cfg_file;
	int port_shift;
	bool force_presentation;
	bool has_config;
	bool use_stream_api;
	struct ev_loop *loop;
	struct client_state *single_client;
	
	/*
	 * argv[0] may be modified by basename(), and future calls to
	 * basename() may modify the memory the result pointer refers to.
	 */
	demo_progname = strdup(basename(argv[0]));
	demo_pid = getpid();
	demo_signal_handling_init();

	port_shift = 0;
	force_presentation = false;
	has_config = false;
	use_stream_api = false;
	opterr = 0; /* prevent getopt from printing its own error messages */
	for (;;) {
		opt_index = 0;
		opt_code = getopt_long(argc, argv, ":c:e:hPp:sv", options,
		    &opt_index);

		if (opt_code == -1)
			break;

		switch (opt_code)
		{
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
		case OPT_STREAM_API:
			use_stream_api = true;
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

	if (!has_config) {
		demo_print_error("config file must be specified");
		usage(true);
	}
	
	loop = ev_default_loop(EVFLAG_AUTO);

	single_client = new_client(loop, cfg_file, use_stream_api,
	    force_presentation, port_shift);
	if (single_client == NULL)
	{
		demo_print_error("Failed to create new client");
		exit(1);
	}
	
	demo_signal_monitor_start(EV_A);

	ev_run(EV_A_ 0);

	demo_app_free(single_client->app);
	if ((demo_error_fd != STDERR_FILENO) && (demo_error_fd != STDOUT_FILENO))
		close(demo_error_fd);
	demo_log_msg(0, "Clean shutdown complete.\n");
	free((void *)demo_progname);
	
	return (0);
}
