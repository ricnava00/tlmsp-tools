/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/tlmsp.h>

#include "libtlmsp-cfg.h"
#include "libtlmsp-util.h"


TLMSP_Contexts *
tlmsp_cfg_contexts_to_openssl(const struct tlmsp_cfg *cfg)
{
	TLMSP_Contexts *tlmsp_contexts = NULL;
	struct tlmsp_cfg_context *context;
	unsigned int i;
	tlmsp_context_audit_t audit;

	for (i = 0; i < cfg->num_contexts; i++) {
		context = &cfg->contexts[i];
		if (context->audit)
			audit = TLMSP_CONTEXT_AUDIT_CONFIRMED;
		else
			audit = TLMSP_CONTEXT_AUDIT_UNCONFIRMED;
		if (!TLMSP_context_add(&tlmsp_contexts, context->id,
			context->purpose, audit)) {
			TLMSP_contexts_free(tlmsp_contexts);
			return (NULL);
		}
	}

	return (tlmsp_contexts);
}

bool
tlmsp_cfg_middlebox_contexts_to_openssl(const struct tlmsp_cfg_middlebox *mb, TLMSP_ContextAccess **ca)
{
	struct tlmsp_cfg_middlebox_context *mb_context;
	unsigned int i;
	tlmsp_context_auth_t auth;

	*ca = NULL;
	for (i = 0; i < mb->num_contexts; i++) {
		mb_context = &mb->contexts[i];

		if(mb_context->access == TLMSP_CFG_CTX_ACCESS_NONE)
			continue;

		if (mb_context->access == TLMSP_CFG_CTX_ACCESS_RW) {
			auth = TLMSP_CONTEXT_AUTH_WRITE;
		} else {
			auth = TLMSP_CONTEXT_AUTH_READ;
		}
		if (!TLMSP_context_access_add(ca, mb_context->base->id, auth)) {
			TLMSP_context_access_free(*ca);
			return (false);
		}
	}

	return (true);
}

TLMSP_Middleboxes *
tlmsp_cfg_initial_middlebox_list_to_openssl(const struct tlmsp_cfg*cfg)
{
	TLMSP_Middleboxes *tlmsp_middleboxes = NULL;
	struct tlmsp_cfg_middlebox *cfg_middlebox;
	TLMSP_ContextAccess *contexts_access;
	struct tlmsp_middlebox_configuration tmc;
	int address_type;
	unsigned int i;

	for (i = 0; i < cfg->num_middleboxes; i++) {
		cfg_middlebox = &cfg->middleboxes[i];

		if (cfg_middlebox->discovered)
			continue;

		/*
		 * Build context access list
		 */
		if (!tlmsp_cfg_middlebox_contexts_to_openssl(
			cfg_middlebox, &contexts_access))
			goto error;

		address_type = tlmsp_util_address_type(cfg_middlebox->address);
		if (address_type == TLMSP_UTIL_ADDRESS_UNKNOWN)
			goto error;
		
		tmc.address_type = address_type;
		tmc.address = cfg_middlebox->address;
		tmc.transparent = cfg_middlebox->transparent;
		tmc.contexts = contexts_access;
		tmc.ca_file_or_dir = NULL;
		if (!TLMSP_middlebox_add(&tlmsp_middleboxes, &tmc))
			goto error;
		TLMSP_context_access_free(contexts_access);
		contexts_access = NULL;
	}

	return (tlmsp_middleboxes);
error:
	/* TLSMP free API points are NULL-safe */
	TLMSP_context_access_free(contexts_access);
	TLMSP_middleboxes_free(tlmsp_middleboxes);
	return (NULL);
}

bool
tlmsp_cfg_middlebox_contexts_match_openssl(const struct tlmsp_cfg_middlebox *mb,
    const TLMSP_ContextAccess *ca)
{
	const struct tlmsp_cfg_middlebox_context *cfg_context;
	unsigned int num_contexts;
	unsigned int i;
	tlmsp_context_id_t id;
	tlmsp_context_id_t max_id;
	tlmsp_context_auth_t auth;
	tlmsp_context_auth_t context_auth[TLMSP_UTIL_CONTEXT_ID_LUT_SIZE];
	tlmsp_context_auth_t cfg_context_auth[TLMSP_UTIL_CONTEXT_ID_LUT_SIZE];

	memset(context_auth, 0, sizeof(context_auth));
	memset(cfg_context_auth, 0, sizeof(cfg_context_auth));

	num_contexts = 0;
	max_id = 0;
	if (TLMSP_context_access_first(ca, &id)) {
		do {
			num_contexts++;
			if (id > max_id)
				max_id = id;
			context_auth[id] = TLMSP_context_access_auth(ca, id);
		} while (TLMSP_context_access_next(ca, &id));
	}

	if (num_contexts != mb->num_contexts)
		return (false);
	
	for (i = 0; i < mb->num_contexts; i++) {
		cfg_context = &mb->contexts[i];
		id = cfg_context->base->id;
		if (id > max_id)
			return (false);
		if (cfg_context->access == TLMSP_CFG_CTX_ACCESS_R)
			auth = TLMSP_CONTEXT_AUTH_READ;
		else if (cfg_context->access == TLMSP_CFG_CTX_ACCESS_RW)
			auth = TLMSP_CONTEXT_AUTH_WRITE;
		else
			auth = 0;
		cfg_context_auth[id] = auth;
	}

	for (i = 0; i <= max_id; i++) {
		if (context_auth[i] != cfg_context_auth[i])
			return (false);
	}

	return (true);
}

bool
tlmsp_cfg_validate_middlebox_list_client_openssl(const struct tlmsp_cfg *cfg,
    TLMSP_Middleboxes *middleboxes)
{
	TLMSP_Middlebox *mb;
	const struct tlmsp_cfg_middlebox *cfg_mb;
	const TLMSP_ContextAccess *contexts;
	uint8_t *address;
	size_t address_len;
	char *address_string;
	int address_type;

	/*
	 * For each entry in the middlebox list, look up the middlebox
	 * config if found, validate the access list
	 */
	mb = TLMSP_middleboxes_first(middleboxes);
	while (mb != NULL) {
		if (!TLMSP_get_middlebox_address(mb, &address_type, &address, &address_len))
			return (false);
		address_string = malloc(address_len + 1);
		if (address_string == NULL) {
			OPENSSL_free(address);
			return (false);
		}
		memcpy(address_string, address, address_len);
		OPENSSL_free(address);
		address_string[address_len] = '\0';

		cfg_mb = tlmsp_cfg_get_middlebox_by_address(cfg, address_string);
		if (cfg_mb == NULL) {
			free(address_string);
			return (false);
		}
		free(address_string);

		contexts = TLMSP_middlebox_context_access(mb);
		if (!tlmsp_cfg_middlebox_contexts_match_openssl(cfg_mb,
			contexts)) {
			return (false);
		}

		mb = TLMSP_middleboxes_next(middleboxes, mb);
	}

	return (true);
}

bool
tlmsp_cfg_process_middlebox_list_server_openssl(const struct tlmsp_cfg *cfg,
    TLMSP_Middleboxes *middleboxes)
{
	TLMSP_Middlebox *mb, *prev_mb;
	const struct tlmsp_cfg_middlebox *cfg_mb;
	struct tlmsp_middlebox_configuration tmc;
	unsigned int i;
	int address_type;
	uint8_t *address;
	size_t address_len;
	char *address_string;

	/*
	 * Walk the middlebox list, checking that the contents are as
	 * expected per the config file, inserting non-transparent
	 * middleboxes from the config file that are marked as discovered,
	 * and forbidding middleboxes that are marked as forbidden.  The
	 * current logic assumes that the client is working straight from
	 * the config file and isn't doing any sort of middlebox list
	 * caching from prior connections (i.e. there will not be any
	 * middlebox list contents not described in the config file).
	 */
	prev_mb = NULL;
	mb = TLMSP_middleboxes_first(middleboxes);
	for (i = 0; i < cfg->num_middleboxes; i++) {
		cfg_mb = &cfg->middleboxes[i];

		if (cfg_mb->discovered && !cfg_mb->transparent &&
		    ((mb == NULL) || !TLMSP_middlebox_dynamic(mb))) {
			TLMSP_ContextAccess *contexts = NULL;

			/*
			 * Insert this config file middlebox before the
			 * current discovery list entry.
			 */
			if (!tlmsp_cfg_middlebox_contexts_to_openssl(cfg_mb,
				&contexts))
				return (false);
			address_type = tlmsp_util_address_type(cfg_mb->address);
			if (address_type == TLMSP_UTIL_ADDRESS_UNKNOWN) {
				TLMSP_context_access_free(contexts);
				return (false);
			}
			tmc.address_type = address_type;
			tmc.address = cfg_mb->address;
			tmc.transparent = cfg_mb->transparent;
			tmc.contexts = contexts;
			tmc.ca_file_or_dir = NULL;
			if (!TLMSP_middleboxes_insert_after(middleboxes, prev_mb, &tmc)) {
				return (false);
			}
		} else if (mb != NULL) {
			const TLMSP_ContextAccess *contexts = NULL;

			if (!TLMSP_get_middlebox_address(mb, &address_type, &address, &address_len))
				return (false);

			address_string = malloc(address_len + 1);
			if (address_string == NULL) {
				OPENSSL_free(address);
				return (false);
			}
			memcpy(address_string, address, address_len);

			OPENSSL_free(address);
			address_string[address_len] = '\0';

			/*
			 * Check that the current discovery list entry
			 * matches the current config file entry.
			 * 
			 * XXX Could use memcmp and avoid the extra allocation.
			 */
			if (strcmp(address_string, cfg_mb->address) != 0) {
				free(address_string);
				return (false);
			}
			free(address_string);

			if (cfg_mb->forbidden) {
				if (!TLMSP_middlebox_forbid(mb))
					return (false);
			} else {
				contexts = TLMSP_middlebox_context_access(mb);
				if (!tlmsp_cfg_middlebox_contexts_match_openssl(cfg_mb,
					contexts))
					return (false);
			}
			prev_mb = mb;
			mb = TLMSP_middleboxes_next(middleboxes, mb);
		} else
			return (false);
	}
	if ((mb != NULL) || (i != cfg->num_middleboxes))
		return (false);

	return (true);
}

