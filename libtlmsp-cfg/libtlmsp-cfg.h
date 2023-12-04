/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBTLMSP_CFG_H_
#define _LIBTLMSP_CFG_H_

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>


/* Protocol version */
#define TLMSP_CFG_PROTO_VERSION(major, minor)	((major << 8) | (minor))
#define TLMSP_CFG_PROTO_VERSION_MAJOR(ver)	((ver) >> 8)
#define TLMSP_CFG_PROTO_VERSION_MINOR(ver)	((ver) & 0xff)

struct tlmsp_cfg_buf {
	const uint8_t *p;
	size_t len;
};

/* used when the end of the template is not a match reference */
#define TLMSP_CFG_MATCH_REF_END		UINT_MAX

struct tlmsp_cfg_payload {
	bool reply;
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
		bool forward;
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
	unsigned int num_actions;
	struct tlmsp_cfg_action {
		enum {
			TLMSP_CFG_ACTION_FAULT_NONE,
			TLMSP_CFG_ACTION_FAULT_CORRUPT_DATA,
			TLMSP_CFG_ACTION_FAULT_CORRUPT_HEADER,
			TLMSP_CFG_ACTION_FAULT_CORRUPT_MAC,
			TLMSP_CFG_ACTION_FAULT_DROP,
			TLMSP_CFG_ACTION_FAULT_REORDER,
		} fault;
		bool renegotiate;
		bool shutdown;
		struct tlmsp_cfg_payload log;
		struct tlmsp_cfg_payload send;
		struct tlmsp_cfg_alert {
			/* The context pointer will be NULL for context 0 */
			struct tlmsp_cfg_context *context;
			enum {
				TLMSP_CFG_ACTION_ALERT_LEVEL_NONE,
				/* Values per RFC 5246 */
				TLMSP_CFG_ACTION_ALERT_LEVEL_WARNING = 1,
				TLMSP_CFG_ACTION_ALERT_LEVEL_FATAL = 2,
			} level;
			enum {
				/* Values per RFC 5246 and ETSI TS 103 523-2 */
				TLMSP_CFG_ACTION_ALERT_DESC_CLOSE_NOTIFY = 0,
				TLMSP_CFG_ACTION_ALERT_DESC_UNEXPECTED_MSG = 10,
				TLMSP_CFG_ACTION_ALERT_DESC_BAD_RECORD_MAC = 20,
				TLMSP_CFG_ACTION_ALERT_DESC_RECORD_OVERFLOW = 22,
				TLMSP_CFG_ACTION_ALERT_DESC_DECOMPRESSION_FAIL = 30,
				TLMSP_CFG_ACTION_ALERT_DESC_HANDSHAKE_FAIL = 40,
				TLMSP_CFG_ACTION_ALERT_DESC_BAD_CERT = 42,
				TLMSP_CFG_ACTION_ALERT_DESC_UNSUPPORTED_CERT = 43,
				TLMSP_CFG_ACTION_ALERT_DESC_CERT_REVOKED = 44,
				TLMSP_CFG_ACTION_ALERT_DESC_CERT_EXPIRED = 45,
				TLMSP_CFG_ACTION_ALERT_DESC_CERT_UNKNOWN = 46,
				TLMSP_CFG_ACTION_ALERT_DESC_ILLEGAL_PARAM = 47,
				TLMSP_CFG_ACTION_ALERT_DESC_UNKNOWN_CA = 48,
				TLMSP_CFG_ACTION_ALERT_DESC_ACCESS_DENIED = 49,
				TLMSP_CFG_ACTION_ALERT_DESC_DECODE_ERROR = 50,
				TLMSP_CFG_ACTION_ALERT_DESC_DECRYPT_ERROR = 51,
				TLMSP_CFG_ACTION_ALERT_DESC_PROTOCOL_VERSION = 70,
				TLMSP_CFG_ACTION_ALERT_DESC_INSUFF_SECURITY = 71,
				TLMSP_CFG_ACTION_ALERT_DESC_INTERNAL_ERROR = 80,
				TLMSP_CFG_ACTION_ALERT_DESC_USER_CANCELED = 90,
				TLMSP_CFG_ACTION_ALERT_DESC_NO_RENEGOTIATION = 100,
				TLMSP_CFG_ACTION_ALERT_DESC_UNSUPPORTED_EXT = 110,
				TLMSP_CFG_ACTION_ALERT_DESC_MBOX_ROUTE_FAIL = 170,
				TLMSP_CFG_ACTION_ALERT_DESC_MBOX_AUTH_FAIL = 171,
				TLMSP_CFG_ACTION_ALERT_DESC_MBOX_REQUIRED = 172,
				TLMSP_CFG_ACTION_ALERT_DESC_UNKNOWN_CONTEXT = 174,
				TLMSP_CFG_ACTION_ALERT_DESC_UNSUPPORTED_CONTEXT = 175,
				TLMSP_CFG_ACTION_ALERT_DESC_MBOX_KEY_VERIFY_FAIL = 176,
				TLMSP_CFG_ACTION_ALERT_DESC_BAD_READER_MAC = 177,
				TLMSP_CFG_ACTION_ALERT_DESC_BAD_WRITER_MAC = 178,
				TLMSP_CFG_ACTION_ALERT_DESC_MBOX_KEY_CONFIRM_FAULT = 179,
				TLMSP_CFG_ACTION_ALERT_DESC_AUTH_REQUIRED = 180,
			} description;
		} alert;
	} *actions;
	bool present;
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
	enum tlmsp_cfg_context_access {
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
	bool forbidden;
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
const struct tlmsp_cfg_context *tlmsp_cfg_get_context_by_tag(const struct tlmsp_cfg *cfg,
                                                             const char *tag);
const struct tlmsp_cfg_middlebox *tlmsp_cfg_get_next_middlebox(const struct tlmsp_cfg *cfg,
                                                               const struct tlmsp_cfg_middlebox *mb);
const struct tlmsp_cfg_middlebox *tlmsp_cfg_get_middlebox_by_address(const struct tlmsp_cfg *cfg,
                                                                     const char *tag);
const struct tlmsp_cfg_middlebox *tlmsp_cfg_get_middlebox_by_tag(const struct tlmsp_cfg *cfg,
                                                                 const char *tag);

char *tlmsp_cfg_get_client_first_hop_address(const struct tlmsp_cfg *cfg, bool reconnect,
                                             bool emulated_transparency, int *address_type);

void tlmsp_cfg_print(int fd, const struct tlmsp_cfg *cfg);
void tlmsp_cfg_free(const struct tlmsp_cfg *cfg);

#endif /* _LIBTLMSP_CFG_H_ */
