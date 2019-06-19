/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBDEMO_CONTAINER_QUEUE_H_
#define _LIBDEMO_CONTAINER_QUEUE_H_

#include <stdbool.h>

#include <openssl/ssl.h>
#include <openssl/tlmsp.h>


struct container_queue_entry {
	struct container_queue_entry *next;
	TLMSP_Container *container;
	size_t length;  /* number of payload bytes */
	uint64_t container_number;  /* starting at 1 */
};

struct container_queue {
	SSL *ssl;
	struct container_queue_entry *head;
	struct container_queue_entry *tail;
	size_t length;  /* total number of payload bytes */
	uint64_t container_counter;
};

struct container_queue_range {
	struct container_queue_entry *first;
	size_t first_offset;
	struct container_queue_entry *last;
	size_t last_remainder;
};

void container_queue_init(struct container_queue *q, SSL *ssl);
bool container_queue_add(struct container_queue *q,
                         TLMSP_Container *container);
TLMSP_Container *container_queue_head(struct container_queue *q);
struct container_queue_entry *container_queue_head_entry(struct container_queue *q);
TLMSP_Container *container_queue_remove_head(struct container_queue *q);
void container_queue_drain(struct container_queue *q);

#endif /* _LIBDEMO_CONTAINER_QUEUE_H_ */
