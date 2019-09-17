/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBDEMO_ACTIVITY_H_
#define _LIBDEMO_ACTIVITY_H_

#include <stdbool.h>


struct demo_connection;
struct demo_activity_match_state;
struct tlmsp_cfg;
struct tlmsp_cfg_activity;

bool demo_activity_conn_queue_initial(struct demo_connection *to_conn);
bool demo_activity_conn_set_up_time_triggered(struct demo_connection *from_conn);
bool demo_activity_conn_start_time_triggered(struct demo_connection *from_conn);
void demo_activity_conn_tear_down_time_triggered(struct demo_connection *from_conn);
struct demo_activity_match_state *demo_activity_create_match_state(struct tlmsp_cfg_activity **activities,
                                                                   unsigned int num_activities);
bool demo_activity_process_read_queue(struct demo_connection *conn);
bool demo_activity_compile_regex(const struct tlmsp_cfg *cfg);
void demo_activity_free_regex(const struct tlmsp_cfg *cfg);

#endif /* _LIBDEMO_ACTIVITY_H_ */
