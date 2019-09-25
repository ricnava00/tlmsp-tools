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

const struct tlmsp_cfg_context *
tlmsp_cfg_get_context_by_tag(const struct tlmsp_cfg *cfg, const char *tag)
{
	unsigned int i;

	for (i = 0; i < cfg->num_contexts; i++)
		if (strcmp(cfg->contexts[i].tag, tag) == 0)
			return (&cfg->contexts[i]);

	return (NULL);
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

char *
tlmsp_cfg_get_client_first_hop_address(const struct tlmsp_cfg *cfg,
    bool reconnect, bool emulated_transparency, int *address_type)
{
	const struct tlmsp_cfg_middlebox *mb;
	const char *address = NULL;
	unsigned int i;

	/*
	 * Under emulated transparency, middleboxes that are marked
	 * transparent are always considered as they must always be
	 * connected to at the transport level, even prior to being
	 * 'discovered'.
	 *
	 * When reconnect is true, discovered non-transparent middleboxes
	 * are also considered.
	 */
	for (i = 0; i < cfg->num_middleboxes; i++) {
		mb = &cfg->middleboxes[i];

		/*
		 * If the middlebox is marked discovered, only consider it
		 * if reconnect is true or it is also marked transparent and
		 * emulated_transparency is enabled.
		 */
		if (mb->discovered &&
		    !(reconnect || (mb->transparent && emulated_transparency)))
			continue;

		/*
		 * If the middlebox is marked transparent, only consider it
		 * if emulated_transparency is enabled.
		 */
		if (mb->transparent && !emulated_transparency)
			continue;

		address = mb->address;
		break;
	}
	if (address == NULL)
		address = cfg->server.address;

	*address_type = tlmsp_util_address_type(address);
	return (strdup(address));
}

void
tlmsp_cfg_free(const struct tlmsp_cfg *cfg)
{
	unsigned int i, j;
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
		for (j = 0; j < activity->num_actions; j++)
			tlmsp_cfg_free_payload(&activity->actions[j].send);
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
	free((void *)cfg);
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
