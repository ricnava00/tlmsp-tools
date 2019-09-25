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


struct demo_splice *
demo_splice_create(struct demo_app *app, demo_splice_free_cb_t free_cb,
    demo_splice_show_info_cb_t show_info_cb, void *app_data, uint64_t id,
    struct tlmsp_cfg_activity **activities_to_client,
    unsigned int num_activities_to_client,
    struct tlmsp_cfg_activity **activities_to_server,
    unsigned int num_activities_to_server)
{
	struct demo_splice *splice;
	struct demo_connection *conn;

	splice = calloc(1, sizeof(*splice));
	if (splice == NULL)
		return (NULL);
	splice->app = app;
	splice->free_cb = free_cb;
	splice->show_info_cb = show_info_cb;
	splice->app_data = app_data;
	splice->id = id;
	
	/*
	 * to-client connection
	 * The activities in the config file that process the data read from
	 * the connection to the client are the to-server activities.
	 */
	conn = demo_connection_create(app, NULL, NULL, NULL, id,
	    activities_to_server, num_activities_to_server);
	if (conn == NULL) {
		free(splice);
		return (NULL);
	}
	splice->to_client = conn;
	conn->splice = splice;
	conn->to_client = true;

	/*
	 * to-server connection
	 * The activities in the config file that process the data read from
	 * the connection to the client are the to-client activities.
	 */
	conn = demo_connection_create(app, NULL, NULL, NULL, id,
	    activities_to_client, num_activities_to_client);
	if (conn == NULL) {
		free(splice->to_client);
		return (NULL);
	}
	splice->to_server = conn;
	conn->splice = splice;
	conn->to_client = false;

	splice->to_client->other_side = splice->to_server;
	splice->to_server->other_side = splice->to_client;

	demo_app_add_splice(app, splice);
	
	return (splice);
}

bool
demo_splice_handshake_complete(struct demo_splice *splice)
{

	if (!demo_connection_handshake_complete(splice->to_client))
		return (false);
	if (!demo_connection_handshake_complete(splice->to_server))
		return (false);

	return(true);
}

bool
demo_splice_init_io_to_client(struct demo_splice *splice, SSL_CTX *ssl_ctx,
    int sock, struct ev_loop *loop, demo_connection_failed_cb_t fail_cb,
    demo_connection_connected_cb_t connected_cb, demo_connection_cb_t cb,
    int initial_events)
{

	if (!demo_connection_init_io(splice->to_client, ssl_ctx, sock, loop,
		fail_cb, connected_cb, cb, initial_events))
		return (false);

	return (true);
}

bool
demo_splice_start_io_to_client(struct demo_splice *splice)
{

	return (demo_connection_start_io(splice->to_client));
}

bool
demo_splice_init_io_to_server(struct demo_splice *splice, SSL_CTX *ssl_ctx,
    int sock, struct ev_loop *loop, demo_connection_failed_cb_t fail_cb,
    demo_connection_connected_cb_t connected_cb, demo_connection_cb_t cb,
    int initial_events)
{

	if (!demo_connection_init_io(splice->to_server, ssl_ctx, sock, loop,
		fail_cb, connected_cb, cb, initial_events))
		return (false);

	return (true);
}

bool
demo_splice_start_io_to_server(struct demo_splice *splice)
{

	return (demo_connection_start_io(splice->to_server));
}

void
demo_splice_pause_io(struct demo_splice *splice)
{

	demo_connection_pause_io(splice->to_client);
	demo_connection_pause_io(splice->to_server);
}

void
demo_splice_stop_io(struct demo_splice *splice)
{

	demo_connection_stop_io(splice->to_client);
	demo_connection_stop_io(splice->to_server);
}

void
demo_splice_resume_io(struct demo_splice *splice)
{

	demo_connection_resume_io(splice->to_client);
	demo_connection_resume_io(splice->to_server);
}

void
demo_splice_free(struct demo_splice *splice)
{

	demo_app_remove_splice(splice->app, splice);

	splice->free_cb(splice->app_data);
	demo_connection_free(splice->to_client);
	demo_connection_free(splice->to_server);
	free(splice);
}

void
demo_splice_show_info(struct demo_splice *splice, bool trailing_separator)
{

	demo_print_error("---------------------------------------------------");
	if (splice->show_info_cb != NULL)
		splice->show_info_cb(splice->app_data);
	demo_connection_show_info(splice->to_client, true);
	demo_connection_show_info(splice->to_server, false);
	if (trailing_separator)
		demo_print_error("---------------------------------------------------");
}
