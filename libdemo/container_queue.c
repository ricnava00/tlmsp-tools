/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#include <stdlib.h>

#include "container_queue.h"


void
container_queue_init(struct container_queue *q, SSL *ssl)
{

	q->ssl = ssl;
	q->head = NULL;
	q->tail = NULL;
	q->length = 0;
	q->container_counter = 0;
}

bool
container_queue_add(struct container_queue *q, TLMSP_Container *container)
{
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
	struct container_queue_entry *entry;
	TLMSP_Container *container = NULL;
	
	entry = q->head;
	if (entry != NULL) {
		q->head = entry->next;
		if (q->head == NULL)
			q->tail = NULL;
		q->length -= entry->length;
		container = entry->container;
		free(entry);
	}

	return (container);
}

void
container_queue_drain(struct container_queue *q)
{
	TLMSP_Container *container;

	container = container_queue_head(q);
	while (container != NULL) {
		container_queue_remove_head(q);
		TLMSP_container_free(q->ssl, container);
		container = container_queue_head(q);
	}
}
