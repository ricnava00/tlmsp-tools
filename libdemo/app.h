/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBDEMO_APP_H_
#define _LIBDEMO_APP_H_

#include <stdbool.h>

#include <libdemo/print.h>


struct tlmsp_cfg;
struct demo_connection;
struct demo_splice;

typedef void (*demo_app_free_cb_t)(void *);
typedef void (*demo_app_show_info_cb_t)(void *);

struct demo_app {
	uint64_t id;
	void *app_data;
	const struct tlmsp_cfg *cfg;
	bool uses_splices;
	bool force_presentation;
	unsigned int num_connections;
	struct demo_connection *connections;
	unsigned int num_splices;
	struct demo_splice *splices;
	demo_app_show_info_cb_t show_info_cb;
	demo_app_free_cb_t free_cb;
	char errbuf[DEMO_ERRBUF_SIZE];
	struct demo_app *next;
	struct demo_app *prev;
};


struct demo_app *demo_app_create(bool uses_splices, demo_app_free_cb_t free_cb,
                                 demo_app_show_info_cb_t show_info_cb,
                                 void *app_data, uint64_t id,
                                 const char *config_file,
                                 bool force_presentation);
void demo_app_add_connection(struct demo_app *app, struct demo_connection *conn);
void demo_app_remove_connection(struct demo_app *app, struct demo_connection *conn);
void demo_app_add_splice(struct demo_app *app, struct demo_splice *splice);
void demo_app_remove_splice(struct demo_app *app, struct demo_splice *splice);
void demo_app_free(struct demo_app *app);
void demo_app_show_info(struct demo_app *app, bool trailing_separator);
void demo_app_show_info_all(void);

#endif /* _LIBDEMO_APP_H_ */
