/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBTLMSP_CFG_H_
#define _LIBTLMSP_CFG_H_

#include <stdbool.h>
#include <stdint.h>

#include <openssl/tlmsp.h>


/* Protocol version */
#define TLMSP_CFG_PROTO_VERSION(major, minor)	((major << 8) | (minor))
#define TLMSP_CFG_PROTO_VERSION_MAJOR(ver)	((ver) >> 8)
#define TLMSP_CFG_PROTO_VERSION_MINOR(ver)	((ver) & 0xff)

#define TLMSP_CONTEXT_ID_RESERVED	0
#define TLMSP_CONTEXT_ID_MIN		1
#define TLMSP_CONTEXT_ID_MAX		255

#define TLMSP_MIDDLEBOX_ID_RESERVED	0
#define TLMSP_MIDDLEBOX_ID_CLIENT	1
#define TLMSP_MIDDLEBOX_ID_SERVER	2
#define TLMSP_MIDDLEBOX_ID_MIN		3
#define TLMSP_MIDDLEBOX_ID_MAX		255


struct tlmsp_cfg_buf {
	const uint8_t *p;
	size_t len;
};

/* used when the end of the template is not a match reference */
#define TLMSP_CFG_MATCH_REF_END		UINT_MAX

struct tlmsp_cfg_payload {
	struct tlmsp_cfg_context *context;
	enum {
		TLMSP_CFG_PAYLOAD_NONE,
		TLMSP_CFG_PAYLOAD_DATA,
		TLMSP_CFG_PAYLOAD_FILE,
		TLMSP_CFG_PAYLOAD_HANDLER,
		TLMSP_CFG_PAYLOAD_TEMPLATE,
	} type;
	union {
		const char *cmd;
		const char *file;
		struct tlmsp_cfg_buf data;
		struct tlmsp_cfg_template {
			unsigned int num_segments;
			/*
			 *  A segment is (possibly empty) data followed by
			 *  the contents of the given match reference.
			 */
			struct tlmsp_cfg_template_segment {
				struct tlmsp_cfg_buf data;
				unsigned int match_ref;
			} *segments;
		} template;
	} param;
};

#define TLMSP_CFG_PAYLOAD_ENABLED(p)	((p)->type != TLMSP_CFG_PAYLOAD_NONE)

#define TLMSP_CFG_MATCH_AT_MAX_MS	1209600000UL /* 2 weeks */

#define TLMSP_CFG_MATCH_EVERY_MAX_MS	1209600000UL /* 2 weeks */

#define TLMSP_CFG_MATCH_CONTAINER_MAX	INT64_MAX

struct tlmsp_cfg_activity {
	const char *tag;
	struct tlmsp_cfg_match {
		unsigned int num_contexts;
		struct tlmsp_cfg_context **contexts;
		bool initial;  /* at was specified with 0 value */
		double at;
		double every;
		struct {
			enum {
				TLMSP_CFG_MATCH_CONTAINER_NONE,
				TLMSP_CFG_MATCH_CONTAINER_N,
				TLMSP_CFG_MATCH_CONTAINER_PROBABILITY,
				TLMSP_CFG_MATCH_CONTAINER_ALL,
			} type;
			union {
				uint64_t n;
				double p;
			} param;
		} container;
		struct {
			enum {
				TLMSP_CFG_MATCH_PATTERN_NONE,
				TLMSP_CFG_MATCH_PATTERN_DATA,
				TLMSP_CFG_MATCH_PATTERN_FILE,
				TLMSP_CFG_MATCH_PATTERN_REGEX,
			} type;
			struct {
				const char *s;
				struct tlmsp_cfg_buf data;
				void *regex;
			} param;
		} pattern;
	} match;
	struct tlmsp_cfg_action {
		enum {
			TLMSP_CFG_ACTION_FAULT_NONE,
			TLMSP_CFG_ACTION_FAULT_CORRUPT_DATA,
			TLMSP_CFG_ACTION_FAULT_CORRUPT_HEADER,
			TLMSP_CFG_ACTION_FAULT_CORRUPT_MAC,
			TLMSP_CFG_ACTION_FAULT_DROP,
			TLMSP_CFG_ACTION_FAULT_REORDER,
		} fault;
		struct tlmsp_cfg_payload after;
		struct tlmsp_cfg_payload before;
		struct tlmsp_cfg_payload replace;
		struct tlmsp_cfg_payload reply;
	} action;
};

struct tlmsp_cfg_client {
	unsigned int version_min;
	unsigned int version_max;
	const char *address;
	unsigned int num_activities;
	struct tlmsp_cfg_activity **activities;
	/* XXX middlebox acceptance policy */
};

struct tlmsp_cfg_server {
	unsigned int version_min;
	unsigned int version_max;
	const char *address;
	const char *cert_file;
	const char *cert_key_file;
	unsigned int num_activities;
	struct tlmsp_cfg_activity **activities;
};

struct tlmsp_cfg_context {
	unsigned int id;
	const char *tag;
	const char *comment;
	const char *purpose;
	bool audit;
};

struct tlmsp_cfg_middlebox_context {
	struct tlmsp_cfg_context *base;
	enum {
		TLMSP_CFG_CTX_ACCESS_NONE,
		TLMSP_CFG_CTX_ACCESS_R,
		TLMSP_CFG_CTX_ACCESS_RW
	} access;
};

struct tlmsp_cfg_middlebox {
	const char *tag;
	const char *address;
	const char *cert_file;
	const char *cert_key_file;
	bool transparent;
	bool discovered;
	unsigned int num_contexts;
	struct tlmsp_cfg_middlebox_context *contexts;
	unsigned int num_activities_to_client;
	struct tlmsp_cfg_activity **activities_to_client;
	unsigned int num_activities_to_server;
	struct tlmsp_cfg_activity **activities_to_server;
};

struct tlmsp_cfg {
	struct tlmsp_cfg_client client;
	struct tlmsp_cfg_server server;
	unsigned int num_contexts;
	struct tlmsp_cfg_context *contexts;
	unsigned int num_middleboxes;
	struct tlmsp_cfg_middlebox *middleboxes;
	unsigned int num_activities;
	struct tlmsp_cfg_activity *activities;
};

const struct tlmsp_cfg *tlmsp_cfg_parse_file(const char *filename, char *errbuf, size_t buflen);
const struct tlmsp_cfg *tlmsp_cfg_parse_string(const char *str, char *errbuf, size_t buflen);
bool tlmsp_cfg_load_match_files(const struct tlmsp_cfg *cfg, char *errbuf, size_t buflen);
const struct tlmsp_cfg_middlebox *tlmsp_cfg_get_next_middlebox(const struct tlmsp_cfg *cfg,
                                                               const struct tlmsp_cfg_middlebox *mb);
const struct tlmsp_cfg_middlebox *tlmsp_cfg_get_middlebox_by_address(const struct tlmsp_cfg *cfg,
                                                                     const char *tag);
const struct tlmsp_cfg_middlebox *tlmsp_cfg_get_middlebox_by_tag(const struct tlmsp_cfg *cfg,
                                                                 const char *tag);

TLMSP_Contexts *tlmsp_cfg_contexts_to_openssl(const struct tlmsp_cfg *cfg);
TLMSP_ContextAccess *tlmsp_cfg_middlebox_contexts_to_openssl(const struct tlmsp_cfg_middlebox *mb);
bool tlmsp_cfg_middlebox_contexts_match_openssl(const struct tlmsp_cfg_middlebox *mb, const TLMSP_ContextAccess *ca);

void tlmsp_cfg_print(int fd, const struct tlmsp_cfg *cfg);
void tlmsp_cfg_free(const struct tlmsp_cfg *cfg);

#endif /* _LIBTLMSP_CFG_H_ */
