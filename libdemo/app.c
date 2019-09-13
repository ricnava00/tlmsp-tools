/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#include <stdlib.h>

#include <libtlmsp-cfg.h>

#include "activity.h"
#include "app.h"
#include "connection.h"
#include "print.h"
#include "splice.h"

static struct demo_app *apps;
unsigned int num_apps;

struct demo_app *
demo_app_create(bool uses_splices, demo_app_free_cb_t free_cb,
    demo_app_show_info_cb_t show_info_cb, void *app_data, uint64_t id,
    const char *config_file, bool force_presentation)
{
	struct demo_app *app;
	unsigned int i;
	
	app = calloc(1, sizeof(*app));
	if (app == NULL)
		return (NULL);

	app->id = id;
	app->app_data = app_data;
	app->uses_splices = uses_splices;
	app->force_presentation = force_presentation;
	app->free_cb = free_cb;
	app->show_info_cb = show_info_cb;

	demo_log_msg(1, "Parsing configuration file");
	app->cfg = tlmsp_cfg_parse_file(config_file, app->errbuf,
	    sizeof(app->errbuf));
	if (app->cfg == NULL)
		goto error;

	if (force_presentation) {
		for (i = 0; i < app->cfg->num_activities; i++)
			app->cfg->activities[i].present = true;
	}
	
	demo_log_msg(1, "Loading match rule files");
	if (!tlmsp_cfg_load_match_files(app->cfg, app->errbuf,
		sizeof(app->errbuf)))
		goto error;

	demo_log_msg(1, "Compiling regular expressions");
	if (!demo_activity_compile_regex(app->cfg))
		goto error;

	if (apps != NULL) {
		apps->prev = app;
		app->next = apps;
	}
	apps = app;
	num_apps++;

	return (app);

error:
	if (app->errbuf[0] != '\0')
		demo_print_error("App creation failed: %s", app->errbuf);
	else
		demo_print_error("App creation failed");
	if (app->cfg != NULL)
		tlmsp_cfg_free(app->cfg);
	free(app);
	return (NULL);	
}

void
demo_app_add_connection(struct demo_app *app, struct demo_connection *conn)
{

	if (app->connections != NULL) {
		app->connections->prev = conn;
		conn->next = app->connections;
	}
	app->connections = conn;
	app->num_connections++;
}

void
demo_app_remove_connection(struct demo_app *app, struct demo_connection *conn)
{

	if (conn->prev == NULL) {
		/* first in the list */
		app->connections = conn->next;
	} else
		conn->prev->next = conn->next;
	if (conn->next != NULL)
		conn->next->prev = conn->prev;
	app->num_connections--;
}

void
demo_app_add_splice(struct demo_app *app, struct demo_splice *splice)
{

	if (app->splices != NULL) {
		app->splices->prev = splice;
		splice->next = app->splices;
	}
	app->splices = splice;
	app->num_splices++;
}

void
demo_app_remove_splice(struct demo_app *app, struct demo_splice *splice)
{

	if (splice->prev == NULL) {
		/* first in the list */
		app->splices = splice->next;
	} else
		splice->prev->next = splice->next;
	if (splice->next != NULL)
		splice->next->prev = splice->prev;
	app->num_splices--;
}

void
demo_app_free(struct demo_app *app)
{
	struct demo_connection *conn;
	struct demo_splice *splice;

	demo_log_msg(1, "Shutting down app");

	if (app->uses_splices) {
		splice = app->splices;
		while (splice != NULL) {
			demo_splice_free(splice);
			splice = splice->next;
		}
	} else {
		conn = app->connections;
		while (conn != NULL) {
			demo_connection_free(conn);
			conn = conn->next;
		}
	}

	if (app->prev == NULL) {
		/* first in the list */
		apps = app->next;
	} else
		app->prev->next = app->next;
	if (app->next != NULL)
		app->next->prev = app->prev;

	/* no logging in this routine after this point */
	app->free_cb(app->app_data);
	demo_activity_free_regex(app->cfg);
	tlmsp_cfg_free(app->cfg);
	free(app);
	num_apps--;
}

void
demo_app_show_info(struct demo_app *app, bool trailing_separator)
{
	struct demo_connection *conn;
	struct demo_splice *splice;

	demo_print_error("===================================================");
	app->show_info_cb(app->app_data);
	if (app->uses_splices) {
		demo_print_error("splices: %u", app->num_splices);
		splice = app->splices;
		while (splice != NULL) {
			demo_splice_show_info(splice, false);
			splice = splice->next;
		}
	} else {
		demo_print_error("connections: %u",
		    app->num_connections);
		conn = app->connections;
		while (conn != NULL) {
			demo_connection_show_info(conn, false);
			conn = conn->next;
		}
	}
	if (trailing_separator)
		demo_print_error("===================================================");
}

void
demo_app_show_info_all(void)
{
	struct demo_app *app;
	
	app = apps;
	while (app != NULL) {
		demo_app_show_info(app, (app->next == NULL));
		app = app->next;
	}
}
