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

#include "libtlmsp-cfg.h"
#include "libtlmsp-util.h"
#include "parse.h"
#include "print.h"


static void tlmsp_cfg_free_payload(struct tlmsp_cfg_payload *payload);
static void tlmsp_cfg_free_buf(struct tlmsp_cfg_buf *buf);


const struct tlmsp_cfg *
tlmsp_cfg_parse_file(const char *filename, char *errbuf, size_t buflen)
{

	return (parse_string_or_file(filename, true, errbuf, buflen));
}

const struct tlmsp_cfg *
tlmsp_cfg_parse_string(const char *str, char *errbuf, size_t buflen)
{

	return (parse_string_or_file(str, false, errbuf, buflen));
}

bool
tlmsp_cfg_load_match_files(const struct tlmsp_cfg *cfg, char *errbuf,
    size_t buflen)
{
	unsigned int i;
	struct tlmsp_cfg_activity *activity;
	struct tlmsp_cfg_match *match;
	
	for (i = 0; i < cfg->num_activities; i++) {
		activity = &cfg->activities[i];
		match = &activity->match;

		if (match->pattern.type == TLMSP_CFG_MATCH_PATTERN_FILE) {
			if (!tlmsp_util_load_file(match->pattern.param.s,
				&match->pattern.param.data.p,
				&match->pattern.param.data.len, errbuf, buflen))
				return (false);
		}
	}

	return (true);
}

void
tlmsp_cfg_print(int fd, const struct tlmsp_cfg *cfg)
{
	unsigned int i;

	indent_print(fd, 0, "{\n");
	for (i = 0; i < cfg->num_contexts; i++) {
		print_context(fd, 1, &cfg->contexts[i]);
	}
	for (i = 0; i < cfg->num_activities; i++) {
		print_activity(fd, 1, &cfg->activities[i]);
	}
	print_client(fd, 1, &cfg->client);
	print_server(fd, 1, &cfg->server);
	for (i = 0; i < cfg->num_middleboxes; i++) {
		print_middlebox(fd, 1, &cfg->middleboxes[i]);
	}
	indent_print(fd, 0, "}\n");
}

const struct tlmsp_cfg_middlebox *
tlmsp_cfg_get_next_middlebox(const struct tlmsp_cfg *cfg,
    const struct tlmsp_cfg_middlebox *mb)
{

	if ((mb - cfg->middleboxes) < (cfg->num_middleboxes - 1))
		return (mb + 1);
	else
		return (NULL);
}

const struct tlmsp_cfg_middlebox *
tlmsp_cfg_get_middlebox_by_address(const struct tlmsp_cfg *cfg,
    const char *address)
{
	unsigned int i;

	for (i = 0; i < cfg->num_middleboxes; i++)
		if (strcmp(cfg->middleboxes[i].address, address) == 0)
			return (&cfg->middleboxes[i]);

	return (NULL);
}

const struct tlmsp_cfg_middlebox *
tlmsp_cfg_get_middlebox_by_tag(const struct tlmsp_cfg *cfg, const char *tag)
{
	unsigned int i;

	for (i = 0; i < cfg->num_middleboxes; i++)
		if (strcmp(cfg->middleboxes[i].tag, tag) == 0)
			return (&cfg->middleboxes[i]);

	return (NULL);
}

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

TLMSP_ContextAccess *
tlmsp_cfg_middlebox_contexts_to_openssl(const struct tlmsp_cfg_middlebox *mb)
{
	TLMSP_ContextAccess *tlmsp_contexts_access = NULL;
	struct tlmsp_cfg_middlebox_context *mb_context;
	unsigned int i;
	tlmsp_context_auth_t auth;

	for (i = 0; i < mb->num_contexts; i++) {
		mb_context = &mb->contexts[i];

		if(mb_context->access == TLMSP_CFG_CTX_ACCESS_NONE)
			continue;

		if (mb_context->access == TLMSP_CFG_CTX_ACCESS_RW) {
			auth = TLMSP_CONTEXT_AUTH_WRITE;
		} else {
			auth = TLMSP_CONTEXT_AUTH_READ;
		}
		if (!TLMSP_context_access_add(&tlmsp_contexts_access,
			mb_context->base->id, auth)) {
			TLMSP_context_access_free(tlmsp_contexts_access);
			return (NULL);
		}
	}

	return (tlmsp_contexts_access);
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
	tlmsp_context_auth_t context_auth[TLMSP_CONTEXT_ID_MAX + 1];
	tlmsp_context_auth_t cfg_context_auth[TLMSP_CONTEXT_ID_MAX + 1];

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

void
tlmsp_cfg_free(const struct tlmsp_cfg *cfg)
{
	unsigned int i;
	struct tlmsp_cfg_context *context;
	struct tlmsp_cfg_activity *activity;
	struct tlmsp_cfg_match *match;
	const struct tlmsp_cfg_client *client;
	const struct tlmsp_cfg_server *server;
	struct tlmsp_cfg_middlebox *middlebox;

	/*
	 * contexts
	 */
	for (i = 0; i < cfg->num_contexts; i++) {
		context = &cfg->contexts[i];

		free_string(context->tag);
		free_string(context->comment);
		free_string(context->purpose);
	}
	free(cfg->contexts);

	/*
	 * activities
	 */
	for (i = 0; i < cfg->num_activities; i++) {
		activity = &cfg->activities[i];
			match = &activity->match;

		free_string(activity->tag);
		if (match->contexts != NULL)
			free(match->contexts);
		switch (match->pattern.type) {
		case TLMSP_CFG_MATCH_PATTERN_NONE:
			/* nothing */
			break;
		case TLMSP_CFG_MATCH_PATTERN_DATA:
			tlmsp_cfg_free_buf(&match->pattern.param.data);
			break;
		case TLMSP_CFG_MATCH_PATTERN_FILE:
			if (match->pattern.param.data.p != NULL)
				free((void *)match->pattern.param.data.p);
			free_string(match->pattern.param.s);
			break;
		case TLMSP_CFG_MATCH_PATTERN_REGEX:
			free_string(match->pattern.param.s);
			break;
		}
		tlmsp_cfg_free_payload(&activity->action.after);
		tlmsp_cfg_free_payload(&activity->action.before);
		tlmsp_cfg_free_payload(&activity->action.replace);
		tlmsp_cfg_free_payload(&activity->action.reply);
	}
	free(cfg->activities);

	/*
	 * client - nothing to do
	 */
	client = &cfg->client;
	free_string(client->address);
	
	/*
	 * server - nothing to do
	 */
	server = &cfg->server;
	free_string(server->address);
	free_string(server->cert_file);
	free_string(server->cert_key_file);

	/*
	 * middleboxes
	 */
	for (i = 0; i < cfg->num_middleboxes; i++) {
		middlebox = &cfg->middleboxes[i];

		free_string(middlebox->tag);
		free_string(middlebox->address);
		free_string(middlebox->cert_file);
		free_string(middlebox->cert_key_file);
		if (middlebox->contexts != NULL)
			free(middlebox->contexts);
	}
	free(cfg->middleboxes);
}

static void
tlmsp_cfg_free_payload(struct tlmsp_cfg_payload *payload)
{
	unsigned int i;

	switch (payload->type) {
	case TLMSP_CFG_PAYLOAD_NONE:
		/* nothing */
		break;
	case TLMSP_CFG_PAYLOAD_DATA:
		if (payload->param.data.len > 0)
			free((void *)payload->param.data.p);
		break;
	case TLMSP_CFG_PAYLOAD_FILE:
		free_string(payload->param.file);
		break;
	case TLMSP_CFG_PAYLOAD_HANDLER:
		free_string(payload->param.cmd);
		break;
	case TLMSP_CFG_PAYLOAD_TEMPLATE:
	{
		struct tlmsp_cfg_template_segment *segment;
		unsigned int num_segments;

		num_segments = payload->param.template.num_segments;
		for (i = 0; i < num_segments; i++) {
			segment = &payload->param.template.segments[i];
			tlmsp_cfg_free_buf(&segment->data);
		}
		if (num_segments > 0)
			free(payload->param.template.segments);
		break;
	}
	}
}

static void
tlmsp_cfg_free_buf(struct tlmsp_cfg_buf *buf)
{

	if (buf->p != NULL)
		free((void *)buf->p);
}
