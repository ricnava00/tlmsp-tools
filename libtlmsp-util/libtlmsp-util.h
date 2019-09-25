/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBTLMSP_UTIL_H_
#define _LIBTLMSP_UTIL_H_


#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>

/*
 * Values per the specification
 */
#define TLMSP_UTIL_ENTITY_ID_CLIENT	0x01
#define TLMSP_UTIL_ENTITY_ID_SERVER	0xfe

#define TLMSP_UTIL_MIDDLEBOX_ENTITY_ID_MIN		0x02
#define TLMSP_UTIL_MIDDLEBOX_ENTITY_ID_MAX		0xfd

#define TLMSP_UTIL_MAX_MIDDLEBOXES	(TLMSP_UTIL_MIDDLEBOX_ENTITY_ID_MAX - \
					 TLMSP_UTIL_MIDDLEBOX_ENTITY_ID_MIN + 1)

/*
 * Values per the specification
 */
#define TLMSP_UTIL_CONTEXT_ID_RESERVED	0
#define TLMSP_UTIL_CONTEXT_ID_MIN	1
#define TLMSP_UTIL_CONTEXT_ID_MAX	255

#define TLMSP_UTIL_CONTEXT_ID_LUT_SIZE	(TLMSP_UTIL_CONTEXT_ID_MAX + 1)

/*
 * Values per the specification
 */
#define TLMSP_UTIL_ADDRESS_URL		0
#define TLMSP_UTIL_ADDRESS_FQDN		1
#define TLMSP_UTIL_ADDRESS_IPV4		2
#define	TLMSP_UTIL_ADDRESS_IPV6		3
#define	TLMSP_UTIL_ADDRESS_MAC		4
#define	TLMSP_UTIL_ADDRESS_UNKNOWN	256


int tlmsp_util_address_type(const char *address);
bool tlmsp_util_address_to_host_and_port(int address_type, const uint8_t *address,
                                         size_t address_len, int port_shift,
                                         char **host, char **port);
struct sockaddr *tlmsp_util_address_to_sockaddr(int address_type,
                                                const uint8_t *address,
                                                size_t address_len,
                                                socklen_t *addr_len,
                                                int port_shift,
                                                char *errbuf, size_t errbuf_len);

bool tlmsp_util_load_file(const char *filename, const uint8_t **buf,
                          size_t *len, char *errbuf, size_t errbuf_len);

#endif /* _LIBTLMSP_UTIL_H_ */
