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

#include "server.h"


enum {
	OPT_CONFIG_FILE = 'c',
	OPT_ERROR_FILE  = 'e',
	OPT_HELP        = 'h',
	OPT_REFLECT     = 'r',
	OPT_STREAM_API  = 's',
	OPT_VERBOSE     = 'v'
};


static void usage(bool is_error);
static void show_server_info_cb(void *app_data);
static struct server_state *new_server(struct ev_loop *loop,
                                       const char *cfg_file,
                                       bool reflect, bool use_stream_api);
static void free_server_cb(void *app_data);
static void accept_cb(EV_P_ ev_io *w, int revents);
static bool new_connection(struct server_state *server, int sock);
static int discovery_check_and_edit(SSL *ssl, int unused,
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
	{"reflect",    no_argument,       0, OPT_REFLECT},
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
	dprintf(fd, "  -r, --reflect               Send everything received back to the client [default: respond per config file]\n");
	dprintf(fd, "  -s, --stream-api            Use stream read/write API [default: container API]\n");
	dprintf(fd, "  -v, --verbose               Raise verbosity level by one [default: 0]\n");
	dprintf(fd, "\n");
	exit(exit_code);
}

static void
show_server_info_cb(void *app_data)
{
	struct server_state *server = app_data;

	demo_print_error("read-write-api: %s",
	    server->use_stream_api ? "stream" : "container");
	demo_print_error("reflect: %s", server->reflect ? "on" : "off");
	demo_print_error_sockaddr("listen-address: ", server->listen_addr);
}

static struct server_state *
new_server(struct ev_loop *loop, const char *cfg_file, bool reflect,
    bool use_stream_api)
{
	struct server_state *server;
	struct demo_app *app;
	const struct tlmsp_cfg_server *cfg;
	socklen_t addr_len;
	int optval;
	
	server = calloc(1, sizeof(*server));
	if (server == NULL) {
		demo_print_errno("Server state allocation failed");
		return (NULL);
	}

	app = demo_app_create(false, free_server_cb, show_server_info_cb,
	    server, 0, cfg_file);
	if (app == NULL) {
		free(server);
		return (NULL);
	}
	server->app = app;

	server->cfg = &app->cfg->server;
	cfg = server->cfg;
	demo_log_msg(1, "Creating server '%s'", cfg->address);
	server->loop = loop;
	server->reflect = reflect;
	server->use_stream_api = use_stream_api;
	server->accept_batch_limit = 16;
	server->listen_socket = -1;

	server->listen_addr =
	    tlmsp_util_address_to_sockaddr(TLMSP_UTIL_ADDRESS_UNKNOWN,
		(uint8_t *)cfg->address, strlen(cfg->address), &addr_len,
		server->app->errbuf, sizeof(server->app->errbuf));
	if (server->listen_addr == NULL) {
		demo_print_error("Could not convert server address '%s' to "
		    "sockaddr: %s", cfg->address, server->app->errbuf);
		goto error;
	}

	server->ssl_ctx = SSL_CTX_new(TLMSP_server_method());
	if (server->ssl_ctx == NULL) {
		demo_print_error_ssl_errq("Failed to create SSL_CTX\n");
		goto error;
	}
	if (SSL_CTX_set_ecdh_auto(server->ssl_ctx, 1) != 1) {
		demo_print_error_ssl_errq("Failed to enable temporary ECDH keys");
		goto error;
	}
	if (SSL_CTX_set_dh_auto(server->ssl_ctx, 1) != 1) {
		demo_print_error_ssl_errq("Failed to enable temporary DH keys");
		goto error;
	}
	if (SSL_CTX_use_certificate_file(server->ssl_ctx, cfg->cert_file,
		SSL_FILETYPE_PEM) != 1) {
		demo_print_error_ssl_errq("Failed to load certificate file '%s'",
		    cfg->cert_file);
		goto error;
	}
	if (SSL_CTX_use_PrivateKey_file(server->ssl_ctx, cfg->cert_key_file,
		SSL_FILETYPE_PEM) != 1) {
		demo_print_error_ssl_errq("Failed to load certificate key file '%s'",
			cfg->cert_key_file);
		goto error;
	}
	/* XXX This may already be checked during key load */
        if (!SSL_CTX_check_private_key(server->ssl_ctx)) {
		demo_print_error_ssl_errq(
		    "Certificate private key does not match the public key");
		goto error;
        }

	server->listen_socket = socket(server->listen_addr->sa_family,
	    SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (server->listen_socket == -1) {
		demo_print_errno("Listen socket creation failed");
		goto error;
	}

	optval = 1;
	if (setsockopt(server->listen_socket, SOL_SOCKET, SO_REUSEADDR,
		&optval, sizeof(optval)) == -1) {
		demo_print_errno("Set SO_REUSEADDR on listen socket failed");
		goto error;
	}
	
	if (bind(server->listen_socket, server->listen_addr, addr_len) == -1) {
		demo_print_errno("Listen socket bind failed");
		demo_print_error_sockaddr("Listen address is ", server->listen_addr);
		goto error;
	}

	if (listen(server->listen_socket, SOMAXCONN) == -1) {
		demo_print_errno("Listen failed");
		goto error;
	}

	demo_log_sockaddr(1, "Listening on ", server->listen_addr);
	
	ev_io_init(&server->listen_watcher, accept_cb,
	    server->listen_socket, EV_READ);
	server->listen_watcher.data = server;
	ev_io_start(EV_A_ &server->listen_watcher);

	return (server);

error:
	demo_app_free(server->app);
	return (NULL);
}

static void
free_server_cb(void *app_data)
{
	struct server_state *server = app_data;

	demo_log_msg(1, "Shutting down listen socket");
	
	if (server->listen_socket != -1)
		close(server->listen_socket);
	
	if (server->listen_addr != NULL)
		free(server->listen_addr);

	if (server->ssl_ctx != NULL)
		SSL_CTX_free(server->ssl_ctx);

	free(server);
}

static void
accept_cb(EV_P_ ev_io *w, int revents)
{
	struct server_state *server = w->data;
	int sock;
	unsigned int i;

	for (i = 0; i < server->accept_batch_limit; i++) {
		sock = accept4(server->listen_socket, NULL, NULL, SOCK_NONBLOCK);
		if (sock == -1)
			break;
		
		if (!new_connection(server, sock))
			continue;
	}
}

static bool
new_connection(struct server_state *server, int sock)
{
	struct connection_state *conn_state;
	struct demo_connection *conn;

	conn_state = calloc(1, sizeof(*conn_state));
	if (conn_state == NULL) {
		demo_print_errno("Failed to allocate connection state");
		return (false);
	}
	conn_state->server = server;

	conn = demo_connection_create(server->app, free_connection_cb,
	    NULL, conn_state, server->connection_counter++,
	    server->cfg->activities, server->cfg->num_activities);
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

	/*
	 * Discovery responses are handled based entirely on the config file
	 * contents, so we can set the callback at the SSL_CTX level.
	 */
	TLMSP_set_discovery_cb(server->ssl_ctx, discovery_check_and_edit,
	    server);

	if (!demo_connection_init_io(conn, server->ssl_ctx, sock, server->loop,
		(demo_connection_failed_cb_t)connection_died, conn_cb, EV_READ))
		goto error;
	SSL_set_accept_state(conn->ssl);
	demo_connection_start_io(conn);

	return (conn_state);

error:
	demo_connection_free(conn);
	return (NULL);
}

static void
free_connection_cb(void *app_data)
{
	struct connection_state *conn_state = app_data;

	free(conn_state);
}

int
discovery_check_and_edit(SSL *ssl, int unused, TLMSP_Middleboxes *middleboxes,
    void *arg)
{
	struct server_state *server = arg;
	TLMSP_Middlebox *mb;
	const struct tlmsp_cfg_middlebox *cfg_mb;
	struct tlmsp_middlebox_configuration tmc;
	unsigned int i;
	int address_type;
	uint8_t *address;
	size_t address_len;
	char *address_string;

	/*
	 * Walk the middlebox list, checking that the contents are as
	 * expected per the config file and inserting non-transparent
	 * middleboxes from the config file that are marked as discovered.
	 * The current logic assumes that the client is working straight
	 * from the config file and isn't doing any sort of middlebox list
	 * caching from prior connections.
	 */
	mb = TLMSP_middleboxes_first(middleboxes);
	for (i = 0; i < server->app->cfg->num_middleboxes; i++) {
		cfg_mb = &server->app->cfg->middleboxes[i];

		if (cfg_mb->discovered && !cfg_mb->transparent) {
			TLMSP_ContextAccess *contexts = NULL;

			/*
			 * Insert this config file middlebox before the
			 * current discovery list entry.
			 */
			contexts = tlmsp_cfg_middlebox_contexts_to_openssl(cfg_mb);
			if (contexts == NULL)
				return (0);
			address_type = tlmsp_util_address_type(cfg_mb->address);
			if (address_type == TLMSP_UTIL_ADDRESS_UNKNOWN) {
				TLMSP_context_access_free(contexts);
				return (0);
			}
			tmc.address_type = address_type;
			tmc.address = cfg_mb->address;
			tmc.transparent = cfg_mb->transparent;
			tmc.contexts = contexts;
			tmc.ca_file_or_dir = NULL;
			if (!TLMSP_middleboxes_insert_before(middleboxes, mb, &tmc)) {
				return (0);
			}
		} else {
			const TLMSP_ContextAccess *contexts = NULL;

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

			/*
			 * Check that the current discovery list entry
			 * matches the current config file entry.
			 * 
			 * XXX Could use memcmp and avoid the extra allocation.
			 */
			if (strcmp(address_string, cfg_mb->address) != 0) {
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
	}
	if (mb != NULL)
		return (0);

	return (1);
}

static void
connection_died(struct demo_connection *conn)
{

	demo_connection_stop_io(conn);
	demo_connection_wait_for_none(conn);

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
	struct server_state *server = conn_state->server;
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
	if (server->use_stream_api) {
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
			if (!container_queue_add(&conn->read_queue,
				container)) {
				TLMSP_container_free(ssl, container);
				return (false);
			}
		}
	} else {
		ssl_result = TLMSP_container_read(ssl, &container);
		if (ssl_result > 0) {
			demo_conn_log(2, conn, "Received container (length=%u) "
			    "in context %u using container API",
			    TLMSP_container_length(container),
			    TLMSP_container_context(container));
			if (!container_queue_add(&conn->read_queue,
				container)) {
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

	demo_conn_log_buf(3, conn, "Container data",
	    TLMSP_container_get_data(container),
	    TLMSP_container_length(container), true);
	
	if (server->reflect) {
		container = container_queue_remove_head(&conn->read_queue);
		if (!container_queue_add(&conn->write_queue, container))
			return (false);
		demo_conn_log(2, conn, "Queued echoed container (length=%u) "
		    "in context %u", TLMSP_container_length(container),
		    TLMSP_container_context(container));
		demo_connection_wait_for(conn, EV_WRITE);
	} else if (!demo_activity_process_read_queue(conn))
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
	struct server_state *server = conn_state->server;
	SSL *ssl = conn->ssl;
	TLMSP_Container *container;
	tlmsp_context_id_t context_id;
	int result;
	int ssl_result;
	int ssl_error;

	container = container_queue_head(&conn->write_queue);
	while (container != NULL) {
		context_id = TLMSP_container_context(container);
		demo_conn_log(2, conn, "Sending container (length=%u) "
		    "in context %u using %s API",
		    TLMSP_container_length(container), context_id,
		    server->use_stream_api ? "stream" : "container");
		demo_conn_log_buf(3, conn, "Container data",
		    TLMSP_container_get_data(container),
		    TLMSP_container_length(container), true);
		if (server->use_stream_api) {
			if (!TLMSP_set_current_context(ssl, context_id)) {
				demo_conn_print_error(conn,
				    "Failed to set current context to %d",
				    context_id);
				return (false);
			}
			ssl_result = SSL_write(ssl,
			    TLMSP_container_get_data(container),
			    TLMSP_container_length(container));
			if (ssl_result > 0)
				TLMSP_container_free(ssl, container);
		} else {
			ssl_result = TLMSP_container_write(ssl, container);
		}
		if (ssl_result > 0) {
			demo_conn_log(2, conn, "Container send complete (result=%d)", ssl_result);
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
	bool has_config;
	bool reflect;
	bool use_stream_api;
	struct ev_loop *loop;
	struct server_state *single_server;

	/*
	 * argv[0] may be modified by basename(), and future calls to
	 * basename() may modify the memory the result pointer refers to.
	 */
	demo_progname = strdup(basename(argv[0]));
	demo_pid = getpid();
	demo_signal_handling_init();

	has_config = false;
	reflect = false;
	use_stream_api = false;
	opterr = 0; /* prevent getopt from printing its own error messages */
	for (;;) {
		opt_index = 0;
		opt_code = getopt_long(argc, argv, ":c:e:hrsv", options,
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
		case OPT_REFLECT:
			reflect = true;
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

	single_server = new_server(loop, cfg_file, reflect, use_stream_api);
	if (single_server == NULL)
	{
		demo_print_error("Failed to create new server");
		exit(1);
	}
	
	demo_signal_monitor_start(EV_A);

	ev_run(EV_A_ 0);

	demo_app_free(single_server->app);
	if ((demo_error_fd != STDERR_FILENO) && (demo_error_fd != STDOUT_FILENO))
		close(demo_error_fd);
	demo_log_msg(0, "Clean shutdown complete.\n");
	free((void *)demo_progname);
	
	return (0);
}
