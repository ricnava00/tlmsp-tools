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
#include <libdemo/print.h>
#include <libdemo/signal.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "middlebox.h"


#define DEFAULT_ACCEPT_BATCH_LIMIT	16
#define DEFAULT_READ_BUFFER_LIMIT	(1*1024*1024)
enum {
	OPT_CONFIG_FILE = 'c',
	OPT_ERROR_FILE  = 'e',
	OPT_HELP        = 'h',
	OPT_CONFIG_TAG  = 't',
	OPT_VERBOSE     = 'v'
};


static void usage(bool is_error);
static void show_middlebox_info_cb(void *app_data);
static struct middlebox_state *new_middlebox(struct ev_loop *loop,
                                             const char *cfg_file);
static void free_middlebox_cb(void *app_data);
static void accept_cb(EV_P_ ev_io *w, int revents);
static bool new_splice(struct middlebox_state *middlebox, int sock);
static void free_splice_cb(void *app_data);
static void connection_died(struct demo_connection *conn);
static void conn_cb(EV_P_ ev_io *w, int revents);
static int read_containers(struct demo_connection *conn);
static int write_containers(struct demo_connection *conn);
static bool new_outbound_connection(struct demo_splice *splice);
static int address_match_cb(SSL *ssl, int type, const uint8_t *addr, size_t, void *arg);


static struct option options[] =
{
	{"config",  required_argument, 0, OPT_CONFIG_FILE},
	{"help",    no_argument,       0, OPT_HELP},
	{"errors",  required_argument, 0, OPT_ERROR_FILE},
	{"tag",     required_argument, 0, OPT_CONFIG_TAG},
	{"verbose", no_argument,       0, OPT_VERBOSE},
	{NULL, 0, NULL, 0}
};


static void
usage(bool is_error)
{
	int fd = is_error ? demo_error_fd : STDOUT_FILENO;
	int exit_code = is_error ? 1 : 0;

	dprintf(fd, "\n");
	dprintf(fd, "Usage: %s [options] (-c <file> | --config <file>) (-t <tag> | --tag <tag>)\n", demo_progname);
	dprintf(fd, "\n");
	dprintf(fd, "Options:\n");
	dprintf(fd, "  -c <file>, --config <file>  TLMSP config file\n");
	dprintf(fd, "  -e <file>, --errors <file>  Send error messages to file (- means stdout). List\n");
	dprintf(fd, "                              first to redirect all errors [default: stderr]\n");
	dprintf(fd, "  -h, --help                  Print this message\n");
	dprintf(fd, "  -t <tag>, --tag <tag>       Tag of middlebox configuration to be used\n");
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
new_middlebox(struct ev_loop *loop, const char *cfg_file)
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
	    middlebox, 0, cfg_file);
	if (app == NULL) {
		free(middlebox);
		return (NULL);
	}
	middlebox->app = app;

	demo_log_msg(1, "Looking up configuration for middlebox '%s'", demo_tag);
	cfg = tlmsp_cfg_get_middlebox_by_tag(app->cfg, demo_tag);
	if (cfg == NULL) {
		demo_print_error("Middlebox configuration with tag '%s' not found",
		    demo_tag);
		goto error;
	}

	demo_log_msg(1, "Looking up configuration for next-hop middlebox, if any");
	next_mb = tlmsp_cfg_get_next_middlebox(app->cfg, cfg);

	middlebox->cfg = cfg;
	demo_log_msg(1, "Creating middlebox '%s'", cfg->address);
	middlebox->loop = loop;
	middlebox->accept_batch_limit = DEFAULT_ACCEPT_BATCH_LIMIT;
	middlebox->read_buffer_limit = DEFAULT_READ_BUFFER_LIMIT;
	middlebox->listen_socket = -1;
	
	middlebox->listen_addr =
	    tlmsp_util_address_to_sockaddr(TLMSP_UTIL_ADDRESS_UNKNOWN,
		(uint8_t *)cfg->address, strlen(cfg->address), &addr_len,
		middlebox->app->errbuf, sizeof(middlebox->app->errbuf));
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
			&addr_len, middlebox->app->errbuf,
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
	if (SSL_CTX_use_certificate_file(middlebox->ssl_ctx, cfg->cert_file,
		SSL_FILETYPE_PEM) != 1) {
		demo_print_error_ssl_errq("Failed to load certificate file '%s'",
		    cfg->cert_file);
		goto error;
	}
	if (SSL_CTX_use_PrivateKey_file(middlebox->ssl_ctx, cfg->cert_key_file,
		SSL_FILETYPE_PEM) != 1) {
		demo_print_error_ssl_errq("Failed to load certificate key file '%s'",
			cfg->cert_key_file);
		goto error;
	}
	/* XXX This may already be checked during key load */
        if (!SSL_CTX_check_private_key(middlebox->ssl_ctx)) {
		demo_print_error_ssl_errq(
		    "Certificate private key does not match the public key");
		goto error;
        }
	if (cfg->transparent) {
		/*
		 * Set the TLMSP middlebox mode to transparent and configure
		 * the address that will be inserted into the ClientHello
		 * middlebox list.
		 */
		TLMSP_set_transparent(middlebox->ssl_ctx,
		    tlmsp_util_address_type(cfg->address), cfg->address);
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
		middlebox->loop, (demo_connection_failed_cb_t)connection_died,
		conn_cb, EV_READ))
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
	free(splice_state);
}

static void
connection_died(struct demo_connection *conn)
{
	struct demo_splice *splice = conn->splice;
	
	/*
	 * Stop both connections
	 */
	demo_splice_stop_io(splice);
	demo_connection_wait_for_none(splice->to_client);
	demo_connection_wait_for_none(splice->to_server);
	
	demo_splice_free(splice);
}

static void
conn_cb(EV_P_ ev_io *w, int revents)
{
	struct demo_connection *conn = w->data;
	struct demo_splice *splice = conn->splice;
	struct demo_connection *conn_to_client = splice->to_client;
	struct demo_connection *conn_to_server = splice->to_server;
	int result;
	int ssl_error;
	bool pending_writes;
	
	demo_splice_stop_io(splice);
	demo_connection_events_arrived(conn, revents);

	if (revents & EV_ERROR) {
		demo_conn_print_error(conn, "Socket error");
		connection_died(conn);
		goto done;
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
			break;
		case 1:
			demo_conn_log(1, conn, "Handshake complete");
			demo_connection_set_phase(conn, DEMO_CONNECTION_PHASE_APPLICATION);
			demo_connection_wait_for(conn, EV_READ);
			break;
		default:
			switch (ssl_error) {
			case SSL_ERROR_WANT_OUTBOUND_CONN:
				demo_conn_log(5, conn, "SSL_ERROR_WANT_OUTBOUND_CONN");
				/*
				 * Establish outbound connection and
				 * re-enter handshake.
				 */
				if (!new_outbound_connection(splice))
					connection_died(conn);
				else
					goto do_handshake;
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
				connection_died(conn);
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
		 * If we are out of pending write data, do some reading.
		 */
		if (!pending_writes) {
			switch (read_containers(conn)) {
			case -1:
				connection_died(conn);
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
		break;
	}

done:
	/*
	 * If connection_died() was called, this will do nothing.
	 */
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
			demo_conn_log_buf(3, conn, "Container data",
			    TLMSP_container_get_data(container),
			    TLMSP_container_length(container), true);
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
			default:
				demo_conn_print_error_ssl(conn, ssl_error,
				    "Connection terminated due to fatal read error");
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
		demo_conn_log_buf(3, conn, "Container data",
		    TLMSP_container_get_data(container),
		    TLMSP_container_length(container), true);
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
new_outbound_connection(struct demo_splice *splice)
{
	struct demo_connection *inbound_conn = splice->to_client;
	struct splice_state *splice_state = splice->app_data;
	struct middlebox_state *middlebox = splice_state->middlebox;
	struct sockaddr *outbound_addr;
	socklen_t outbound_addr_len;
	int sock;
	bool result = false;

	if (middlebox->cfg->transparent) {
		/*
		 * If we are a transparent middlebox, then normally the next
		 * hop would be determined by the destination IP of the
		 * inbound connection.  In this demo, transparency at the IP
		 * layer is emulated, not actual, so the destination IP of
		 * the inbound connection does not indicate the next hop.
		 * The next hop is instead determined by the address of the
		 * next middlebox in the configuration file (if present, now
		 * in middlebox->next_addr), or if there was not a next
		 * middlebox in the configuration, the address of the server
		 * from the ClientHello.
		 */
		if (middlebox->next_addr == NULL)
			if (!TLMSP_get_server_address_instance(inbound_conn->ssl,
				&splice_state->next_hop_addr_type,
				&splice_state->next_hop_addr,
				&splice_state->next_hop_addr_len))
				return (false);
	} else {
		/*
		 * If we are not a transparent middlebox, then the next hop
		 * will come from the next entry in the middlebox list
		 * present in the ClientHello, or if there is no next entry
		 * in the middlebox list, then from the server address in
		 * the ClientHello.
		 */
		if (!TLMSP_get_next_hop_address_instance(inbound_conn->ssl,
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
			&outbound_addr_len, middlebox->app->errbuf,
			sizeof(middlebox->app->errbuf));
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
		middlebox->loop, (demo_connection_failed_cb_t)connection_died,
		conn_cb, EV_READ))
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
	bool has_config;
	bool has_tag;
	struct ev_loop *loop;
	struct middlebox_state *single_middlebox;

	/*
	 * argv[0] may be modified by basename(), and future calls to
	 * basename() may modify the memory the result pointer refers to.
	 */
	demo_progname = strdup(basename(argv[0]));
	demo_pid = getpid();
	demo_signal_handling_init();

	has_config = false;
	has_tag = false;
	opterr = 0; /* prevent getopt from printing its own error messages */
	for (;;) {
		opt_index = 0;
		opt_code = getopt_long(argc, argv, ":c:e:ht:v", options,
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
		case OPT_CONFIG_TAG:
			demo_tag = optarg;
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

	if (!has_config || !has_tag) {
		demo_print_error("config file and tag must be specified");
		usage(true);
	}
	
	loop = ev_default_loop(EVFLAG_AUTO);

	single_middlebox = new_middlebox(loop, cfg_file);
	if (single_middlebox == NULL)
	{
		demo_print_error("Failed to create new middlebox");
		exit(1);
	}

	demo_signal_monitor_start(EV_A);

	ev_run(EV_A_ 0);

	demo_app_free(single_middlebox->app);
	if ((demo_error_fd != STDERR_FILENO) && (demo_error_fd != STDOUT_FILENO))
		close(demo_error_fd);
	demo_log_msg(0, "Clean shutdown complete.\n");
	free((void *)demo_progname);
	
	return (0);
}
