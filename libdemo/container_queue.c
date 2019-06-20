/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#include <stdlib.h>

#include "connection.h"
#include "container_queue.h"
#include "print.h"
#include "splice.h"


static void container_queue_idle_cb(EV_P_ ev_timer *w, int revents);

void
container_queue_init(struct container_queue *q, struct demo_connection *conn,
    unsigned int max_idle, size_t max_depth)
{

	q->conn = conn;
	q->max_idle = max_idle;
	q->max_depth = max_depth;
	q->head = NULL;
	q->tail = NULL;
	q->length = 0;
	q->container_counter = 0;

	/* XXX not yet */
	q->max_idle = 0;
	if (q->max_idle != 0) {
		ev_init(&q->idle_timer, container_queue_idle_cb);
		q->idle_timer.repeat = (double)q->max_idle / 1000.0;
		q->idle_timer.data = q;
	}

}

static void
container_queue_idle_cb(EV_P_ ev_timer *w, int revents)
{
	struct container_queue *q = w->data;
	struct demo_connection *other_side = q->conn->other_side;
	struct demo_splice *splice = q->conn->splice;
	TLMSP_Container *container;

	/* This should only be getting enabled on a middlebox */
	if (splice != NULL) {
		demo_conn_log(2, q->conn, "Read queue idle timer expired, "
		    "forwarding all containers in queue");
		demo_splice_stop_io(splice);
		/*
		 * On a middlebox, we've exceeded our time window for
		 * matching, so forward what has been accumulated.
		 */
		container = container_queue_head(q);
		while (container != NULL) {
			container_queue_remove_head(q);
			container_queue_add(&other_side->write_queue, container);
			container = container_queue_head(q);
		}
		demo_connection_wait_for(other_side,  EV_WRITE);
		demo_splice_resume_io(splice);
	} 
}

bool
container_queue_add(struct container_queue *q, TLMSP_Container *container)
{
	struct ev_loop *loop = q->conn->loop;
	struct container_queue_entry *entry;

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		return (false);

	q->container_counter++;
	entry->next = NULL;
	entry->container = container;
	entry->length = TLMSP_container_length(container);
	entry->container_number = q->container_counter;
	
	if (q->tail != NULL)
		q->tail->next = entry;
	else
		q->head = entry;
	q->tail = entry;
	q->length += entry->length;

	if (q->max_idle != 0) {
		ev_timer_again(EV_A_ &q->idle_timer);
	}
	
	return (true);
}

TLMSP_Container *
container_queue_head(struct container_queue *q)
{

	return (q->head ? q->head->container : NULL);
}

struct container_queue_entry *
container_queue_head_entry(struct container_queue *q)
{

	return (q->head);
}

TLMSP_Container *
container_queue_remove_head(struct container_queue *q)
{
	struct ev_loop *loop = q->conn->loop;
	struct container_queue_entry *entry;
	TLMSP_Container *container = NULL;
	
	entry = q->head;
	if (entry != NULL) {
		q->head = entry->next;
		if (q->head == NULL) {
			q->tail = NULL;

			if (q->max_idle != 0) {
				/*
				 * Queue is empty, no need for an idle timer.
				 */
				ev_timer_stop(EV_A_ &q->idle_timer);
			}
		}
		q->length -= entry->length;
		container = entry->container;
		free(entry);
	}

	return (container);
}

void
container_queue_drain(struct container_queue *q)
{
	struct ev_loop *loop = q->conn->loop;
	TLMSP_Container *container;

	container = container_queue_head(q);
	while (container != NULL) {
		container_queue_remove_head(q);
		TLMSP_container_free(q->conn->ssl, container);
		container = container_queue_head(q);
	}

	if (q->max_idle != 0) {
		/*
		 * Queue is empty, no need for an idle timer.
		 */
		ev_timer_stop(EV_A_ &q->idle_timer);
	}
}
