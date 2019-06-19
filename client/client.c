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
#include <libdemo/connection.h>
#include <libdemo/print.h>
#include <libdemo/signal.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "client.h"


enum {
	OPT_CONFIG_FILE = 'c',
	OPT_ERROR_FILE  = 'e',
	OPT_HELP        = 'h',
	OPT_STREAM_API  = 's',
	OPT_VERBOSE     = 'v'
};


static void usage(bool is_error);
static void show_client_info_cb(void *app_data);
static struct client_state *new_client(struct ev_loop *loop,
                                       const char *cfg_file,
                                       bool use_stream_api);
static void free_client_cb(void *app_data);
static bool new_connection(struct client_state *client,
	                   const TLMSP_ReconnectState *reconnect_state);
static void show_connection_info(void *app_data);
static int validate_discovery_results(SSL *ssl, int unused,
                                      TLMSP_Middleboxes *middleboxes, void *arg);
static void free_connection_cb(void *app_data);
static void connection_died(struct demo_connection *conn);
static void conn_cb(EV_P_ ev_io *w, int revents);
static bool read_containers(struct demo_connection *conn);
static bool write_containers(struct demo_connection *conn);


static struct option options[] =
{
	{"config",     required_argument, 0, OPT_CONFIG_FILE},
	{"help",       no_argument,       0, OPT_HELP},
	{"errors",     required_argument, 0, OPT_ERROR_FILE},
	{"stream-api", no_argument,       0, OPT_STREAM_API},
	{"verbose",    no_argument,       0, OPT_VERBOSE},
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
new_client(struct ev_loop *loop, const char *cfg_file, bool use_stream_api)
{
	struct client_state *client;
	struct demo_app *app;
	const struct tlmsp_cfg_client *cfg;
	TLMSP_Contexts *tlmsp_contexts = NULL;
	TLMSP_ContextAccess *contexts_access = NULL;
	TLMSP_Middleboxes *tlmsp_middleboxes = NULL;
	struct tlmsp_cfg_middlebox *cfg_middlebox;
	struct tlmsp_middlebox_configuration tmc;
	int address_type;
	unsigned int i;

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		demo_print_errno("Client state allocation failed");
		return (NULL);
	}

	app = demo_app_create(false, free_client_cb, show_client_info_cb,
	    client, 0, cfg_file);
	if (app == NULL) {
		free(client);
		return (NULL);
	}
	client->app = app;

	client->cfg = &app->cfg->client;
	cfg = client->cfg;
	demo_log_msg(1, "Creating client '%s'", cfg->address);
	client->loop = loop;
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
	for (i = 0; i < app->cfg->num_middleboxes; i++) {
		cfg_middlebox = &app->cfg->middleboxes[i];

		if (cfg_middlebox->discovered)
			continue;

		/*
		 * Build context access list
		 */
		if (cfg_middlebox->num_contexts > 0) {
			contexts_access =
			    tlmsp_cfg_middlebox_contexts_to_openssl(cfg_middlebox);
			if (contexts_access == NULL) {
				demo_print_error("Failed to build contexts "
				    "access for middlebox '%s'",
				    cfg_middlebox->tag);
				goto error;
			}
		} else
			contexts_access = NULL;

		address_type = tlmsp_util_address_type(cfg_middlebox->address);
		if (address_type == TLMSP_UTIL_ADDRESS_UNKNOWN) {
			demo_print_error("Failed to determine address type for "
			    "middlebox '%s' (address '%s')",
			    cfg_middlebox->tag, cfg_middlebox->address);
			goto error;
		}
		
		tmc.address_type = address_type;
		tmc.address = cfg_middlebox->address;
		tmc.transparent = cfg_middlebox->transparent;
		tmc.contexts = contexts_access;
		tmc.ca_file_or_dir = NULL;
		if (!TLMSP_middlebox_add(&tlmsp_middleboxes, &tmc)) {
			demo_print_error_ssl_errq("Failed to add middlebox '%s'",
			    cfg_middlebox->tag);
			goto error;
		}
		TLMSP_context_access_free(contexts_access);
		contexts_access = NULL;
	}
	if (tlmsp_middleboxes != NULL)
		if (!TLMSP_set_initial_middleboxes(client->ssl_ctx,
			tlmsp_middleboxes)) {
			demo_print_error_ssl_errq("Failed to set middlebox list");
			goto error;
		}
	TLMSP_middleboxes_free(tlmsp_middleboxes);

	/*
	 * The validation we do just ensures that all list members are in
	 * the demo config file, so we can set the callback at the SSL_CTX
	 * level.
	 */
	TLMSP_set_discovery_cb(client->ssl_ctx, validate_discovery_results,
	    client);
	
	if (!new_connection(client, NULL)) {
		demo_print_error("Failed to create connection");
		goto error;
	}
	
	return (client);

error:
	TLMSP_context_access_free(contexts_access);
	TLMSP_contexts_free(tlmsp_contexts);
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
	struct sockaddr *addr;
	socklen_t addr_len;
	uint8_t *next_hop_addr = NULL;
	size_t next_hop_addr_len;
	int next_hop_addr_type;
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
	
	if (!TLMSP_get_next_hop_address(client->ssl_ctx, &next_hop_addr_type,
		&next_hop_addr, &next_hop_addr_len)) {
		demo_print_error_ssl_errq("Failed to get next hop address");
		goto error;
	}
	addr = tlmsp_util_address_to_sockaddr(next_hop_addr_type,
	    next_hop_addr, next_hop_addr_len, &addr_len, client->app->errbuf,
	    sizeof(client->app->errbuf));
	if (addr == NULL) {
		demo_print_error("Could not convert next hop address '%.*s' to "
		    "sockaddr: %s", next_hop_addr_len, next_hop_addr,
		    client->app->errbuf);
		goto error;
	}
	OPENSSL_free(next_hop_addr);
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

	if (!demo_connection_init_io(conn, client->ssl_ctx, sock, client->loop,
		(demo_connection_failed_cb_t)connection_died, conn_cb, EV_WRITE))
		goto error;

	SSL_set_connect_state(conn->ssl);
	if (reconnect_state != NULL) {
		if (!TLMSP_set_reconnect_state(conn->ssl, reconnect_state)) {
			demo_print_error_ssl_errq("Failed to set reconnect state");
			goto error;
		}
		TLMSP_reconnect_state_free(reconnect_state);
	}
	demo_connection_start_io(conn);

	return (true);

error:
	OPENSSL_free(next_hop_addr);
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

	free(conn_state);
}

static int
validate_discovery_results(SSL *ssl, int unused, TLMSP_Middleboxes *middleboxes,
    void *arg)
{
	struct client_state *client = arg;
	TLMSP_Middlebox *mb;
	const struct tlmsp_cfg_middlebox *cfg_mb;
	const TLMSP_ContextAccess *contexts;
	uint8_t *address;
	size_t address_len;
	char *address_string;
	int address_type;

	/*
	 * For each entry in the middlebox list, look up the middlebox
	 * config if found, validate the access list
	 */
	mb = TLMSP_middleboxes_first(middleboxes);
	while (mb != NULL) {
		if (!TLMSP_get_middlebox_address(mb, &address_type, &address, &address_len))
			return (0);
		address_string = malloc(address_len + 1);
		if (address_string == NULL) {
			OPENSSL_free(address);
			return (0);
		}
		memcpy(address_string, address, address_len);
		OPENSSL_free(address);
		address_string[address_len] = '\0';

		cfg_mb = tlmsp_cfg_get_middlebox_by_address(client->app->cfg, address_string);
		if (cfg_mb == NULL) {
			free(address_string);
			return (0);
		}
		free(address_string);

		contexts = TLMSP_middlebox_context_access(mb);
		if (!tlmsp_cfg_middlebox_contexts_match_openssl(cfg_mb,
			contexts)) {
			return (0);
		}

		mb = TLMSP_middleboxes_next(middleboxes, mb);
	}

	return (1);
}

static void
connection_died(struct demo_connection *conn)
{
	struct connection_state *conn_state = conn->app_data;
	struct client_state *client = conn_state->client;

	demo_connection_stop_io(conn);
	demo_connection_wait_for_none(conn);

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
	bool pending_writes;

	demo_connection_stop_io(conn);
	demo_connection_events_arrived(conn, revents);

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
		/*
		 * As processing read data above may have added to an
		 * otherwise empty write queue, ensure response to EV_WRITE.
		 */
		if (demo_connection_writes_pending(conn))
			demo_connection_wait_for(conn, EV_WRITE);
	}

	/*
	 * If none of the above processing requires a further read
	 * or write event, wait for new data to arrive.
	 */
	if (demo_connection_wait_events(conn) == 0)
		demo_connection_wait_for(conn, EV_READ);
	
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
			demo_conn_log(3, conn, "received container (length=%u) "
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
			demo_conn_log(3, conn, "received container (length=%u) "
			    "in context %u using container API",
			    TLMSP_container_length(container),
			    TLMSP_container_context(container));
			if (!container_queue_add(&conn->read_queue, container)) {
				TLMSP_container_free(ssl, container);
				return (false);
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
			demo_connection_wait_for(conn, EV_READ);
			break;
		case SSL_ERROR_WANT_WRITE:
			demo_connection_wait_for(conn, EV_WRITE);
			break;
		case SSL_ERROR_WANT_RECONNECT:
			conn_state->reconnect_state =
			    TLMSP_get_reconnect_state(ssl);
			result = false;
			break;
		default:
			demo_conn_print_error_ssl(conn, ssl_error,
			    "Connection terminated due to fatal read error");
			result = false;
			break;
		}
		return (result);
	}

	demo_conn_log_buf(4, conn, "Container data",
	    TLMSP_container_get_data(container),
	    TLMSP_container_length(container), true);

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
	tlmsp_context_id_t context_id;
	int result;
	int ssl_result;
	int ssl_error;

	container = container_queue_head(&conn->write_queue);
	while (container != NULL) {
		context_id = TLMSP_container_context(container);
		demo_conn_log(3, conn, "sending container (length=%u) "
		    "in context %u using %s API",
		    TLMSP_container_length(container), context_id,
		    client->use_stream_api ? "stream" : "container");
		demo_conn_log_buf(4, conn, "Container data",
		    TLMSP_container_get_data(container),
		    TLMSP_container_length(container), true);
		if (client->use_stream_api) {
			if (!TLMSP_set_current_context(ssl, context_id)) {
				demo_conn_print_error(conn,
				    "Failed to set current context to %d",
				    context_id);
				return (false);
			}
			ssl_result = SSL_write(ssl,
			    TLMSP_container_get_data(container),
			    TLMSP_container_length(container));
			if (ssl_result > 0) {
				TLMSP_container_free(ssl, container);
			}
		} else {
			ssl_result = TLMSP_container_write(ssl, container);
		}
		if (ssl_result > 0) {
			demo_conn_log(3, conn, "container send complete (result=%d)", ssl_result);
			container_queue_remove_head(&conn->write_queue);
			container = container_queue_head(&conn->write_queue);
		} else
			break;
	}
	result = true;
	if (ssl_result <= 0) {
		ssl_error = SSL_get_error(ssl, ssl_result);
		switch (ssl_error) {
		case SSL_ERROR_WANT_READ:
			demo_conn_log(4, conn, "SSL_ERROR_WANT_READ");
			demo_connection_wait_for(conn, EV_READ);
			break;
		case SSL_ERROR_WANT_WRITE:
			demo_conn_log(4, conn, "SSL_ERROR_WANT_WRITE");
			demo_connection_wait_for(conn, EV_WRITE);
			break;
		case SSL_ERROR_WANT_RECONNECT:
			demo_conn_log(4, conn, "SSL_ERROR_WANT_RECONNECT");
			conn_state->reconnect_state = TLMSP_get_reconnect_state(ssl);
			result = false;
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

	has_config = false;
	use_stream_api = false;
	opterr = 0; /* prevent getopt from printing its own error messages */
	for (;;) {
		opt_index = 0;
		opt_code = getopt_long(argc, argv, ":c:e:hsv", options,
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
			demo_print_error("Unknown option %s", argv[optind]);
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

	single_client = new_client(loop, cfg_file, use_stream_api);
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
