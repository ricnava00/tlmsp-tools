/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "libtlmsp-util.h"


/*
 * Determine the type of TLMSP address in the given string using simple
 * heuristics, not complete validation
 *
 * url(0)  - contains '://'
 * fqdn(1) - not an ipv4_adr and contains '.'
 * ipv4_adr(2) - can be converted by inet_pton(AF_INET)
 * ipv6_adr(3) - not a url and can be converted by inet_pton(AF_INET6)
 * mac_adr(4) - six pairs of hex digits separated by ':'
 */
int
tlmsp_util_address_type(const char *address)
{
	union {
		struct in_addr sin;
		struct in6_addr sin6;
	} result;
	const char *p;
	unsigned int i;
	
	if (strstr(address, "://") != NULL)
		return (TLMSP_UTIL_ADDRESS_URL);
	else if (inet_pton(AF_INET, address, &result.sin) == 1)
		return (TLMSP_UTIL_ADDRESS_IPV4);
	else if (inet_pton(AF_INET6, address, &result.sin6) == 1)
		return (TLMSP_UTIL_ADDRESS_IPV6);	
	else if (strchr(address, '.') != NULL)
		return (TLMSP_UTIL_ADDRESS_FQDN);
	else {
		for (i = 0; i < 6; i++) {
			p = &address[i * 3];
			if (!isxdigit(p[0]) || !isxdigit(p[1]))
				return (TLMSP_UTIL_ADDRESS_UNKNOWN);
			if (i < 5) {
				if (p[2] != ':')
					return (TLMSP_UTIL_ADDRESS_UNKNOWN);
			} else {
				if (p[2] != '\0')
					return (TLMSP_UTIL_ADDRESS_UNKNOWN);
			}
		}

		return (TLMSP_UTIL_ADDRESS_MAC);
	}
}

bool
tlmsp_util_address_to_host_and_port(int address_type, const uint8_t *address,
    size_t address_len, char **host, char **port)
{
	char *address_str = NULL;
	char *protocol_end, *path_slash, *colon;
	char *host_result = NULL;
	char *port_result = NULL;

	/* reject addresses that contain '\0' */
	if (memchr(address, '\0', address_len) != NULL)
		return (false);

	address_str = malloc(address_len + 1);
	if (address_str == NULL)
		return (false);
	memcpy(address_str, address, address_len);
	address_str[address_len] = '\0';

	if (address_type == TLMSP_UTIL_ADDRESS_UNKNOWN)
	    address_type = tlmsp_util_address_type(address_str);
	switch (address_type) {
	case TLMSP_UTIL_ADDRESS_URL:
		protocol_end = strstr(address_str, "://");
		if (protocol_end == NULL) /* should never happen */
			goto error;
		protocol_end += 3;
		path_slash = strchr(protocol_end, '/');
		if (path_slash != NULL)
			host_result = strndup(protocol_end,
			    path_slash - protocol_end);
		else
			host_result = strdup(protocol_end);
		if (host_result == NULL)
			goto error;
		colon = strrchr(host_result, ':');
		if (colon != NULL) {
			*colon = '\0';
			if (path_slash != NULL)
				port_result = strndup(colon + 1,
				    path_slash - colon - 1);
			else
				port_result = strdup(colon + 1);
			if (port_result == NULL)
				goto error;
		}
		break;
	case TLMSP_UTIL_ADDRESS_FQDN: /* FALLTHROUGH */
	case TLMSP_UTIL_ADDRESS_IPV4: /* FALLTHROUGH */
	case TLMSP_UTIL_ADDRESS_IPV6: /* FALLTHROUGH */
		host_result = strdup(address_str);
		if (host_result == NULL)
			goto error;
		break;
	default:
		return (false);
	}
	free(address_str);

	if (port_result == NULL) {
		port_result = strdup("443");  /* XXX should there really be a default? */
		if (port_result == NULL)
			goto error;
	}

	*host = host_result;
	*port = port_result;
	return (true);

error:
	if (address_str != NULL)
		free(address_str);
	if (host_result != NULL)
		free(host_result);
	if (port_result != NULL)
		free(port_result);
	return (false);
}

struct sockaddr *
tlmsp_util_address_to_sockaddr(int address_type, const uint8_t *address,
    size_t address_len, socklen_t *addr_len, char *errbuf, size_t errbuf_len)
{
	char *host, *port;
	struct addrinfo hints;
	int errcode;
	struct addrinfo *addrs, *addr;
	struct addrinfo *v4, *v6;
	struct sockaddr *result;

	if (!tlmsp_util_address_to_host_and_port(address_type, address,
		address_len, &host,& port))
	{
		if (errbuf != NULL)
			snprintf(errbuf, errbuf_len,
			    "Could not extract host name and port from %s\n",
			    address);
		return (NULL);
	}
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICSERV;
	errcode = getaddrinfo(host, port, &hints, &addrs);
	if (errcode != 0) {
		if (errbuf != NULL)
			snprintf(errbuf, errbuf_len,
			    "getaddrinfo(%s, %s) failed: %s", host, port,
			    gai_strerror(errcode));
		return (NULL);
	}

	v4 = v6 = NULL;
	addr = addrs;
	while (addr != NULL) {
		switch (addr->ai_family) {
		case AF_INET:
			if (v4 == NULL)
				v4 = addr;
		case AF_INET6:
			if (v6 == NULL)
				v6 = addr;
		}
		addr = addr->ai_next;
	}

	result = NULL;
	if ((v4 != NULL) || (v6 != NULL)) {
		/* Prefer v4 */
		addr = (v4 != NULL) ? v4 : v6;
		result = malloc(addr->ai_addrlen);
		if (result != NULL) {
			memcpy(result, addr->ai_addr, addr->ai_addrlen);
			*addr_len = addr->ai_addrlen;
		} else if (errbuf != NULL)
			snprintf(errbuf, errbuf_len,
			    "Failed to allocate sockaddr");
	} else if (errbuf != NULL)
		snprintf(errbuf, errbuf_len,
		    "No IPv4 or IPv6 address found for %s", host);
	freeaddrinfo(addrs);

	return (result);
}
