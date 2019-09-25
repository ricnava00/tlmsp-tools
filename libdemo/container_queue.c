/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#include <stdlib.h>

#include "app.h"
#include "connection.h"
#include "container_queue.h"
#include "print.h"
#include "splice.h"


static void container_queue_idle_cb(EV_P_ ev_timer *w, int revents);

void
container_queue_init(struct container_queue *q, struct demo_connection *conn,
    unsigned int max_idle_ms, size_t max_length_bytes)
{

	q->conn = conn;
	q->max_idle = max_idle_ms;
	q->max_length = max_length_bytes;
	q->head = NULL;
	q->tail = NULL;
	q->length = 0;
	q->container_counter = 0;

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
	struct demo_connection *conn = q->conn;
	struct demo_connection *other_side = conn->other_side;
	struct demo_splice *splice = conn->splice;

	/* idle timers are only used by middleboxes */
	if (splice != NULL) {
		demo_conn_log(2, q->conn, "Read queue idle timer expired, "
		    "forwarding all containers in queue");
		/*
		 * On a middlebox, we've exceeded our time window for
		 * matching, so forward what has been accumulated.
		 */
		container_queue_drain(q, &other_side->write_queue);
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

/*
 * This is for adding a container back to the head after one has been
 * removed.
 */
bool
container_queue_add_head(struct container_queue *q, TLMSP_Container *container)
{
	struct ev_loop *loop = q->conn->loop;
	struct container_queue_entry *entry;

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		return (false);

	entry->next = q->head;
	entry->container = container;
	entry->length = TLMSP_container_length(container);
	if (q->head)
		entry->container_number = q->head->container_number - 1;
	else
		entry->container_number = q->container_counter;
	
	q->head = entry;
	if (q->tail == NULL)
		q->tail = entry;
	q->length += entry->length;

	/*
	 * When adding back to an empty queue that has an idle timer, the
	 * idle timer needs to be restarted as it is stopped when the queue
	 * becomes empty.
	 */
	if ((q->max_idle != 0) && (entry->next == NULL))
		ev_timer_again(EV_A_ &q->idle_timer);

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
container_queue_drain(struct container_queue *q, struct container_queue *to)
{
	struct ev_loop *loop = q->conn->loop;
	struct demo_connection *other_side;
	TLMSP_Container *container;

	if (to != NULL) {
		other_side = to->conn;
		demo_connection_pause_io(other_side);
	}

	container = container_queue_head(q);
	while (container != NULL) {
		container_queue_remove_head(q);
		if (to != NULL)
			container_queue_add(to, container);
		else
			TLMSP_container_free(q->conn->ssl, container);
		container = container_queue_head(q);
	}

	if (to != NULL) {
		demo_connection_wait_for(other_side, EV_WRITE);
		demo_connection_resume_io(other_side);
	} else if (q->max_idle != 0) {
		/*
		 * Queue is empty, no need for an idle timer.
		 */
		ev_timer_stop(EV_A_ &q->idle_timer);
	}
}
