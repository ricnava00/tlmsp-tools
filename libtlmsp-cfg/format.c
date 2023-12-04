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
#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucl.h>

#include "libtlmsp-cfg.h"
#include "libtlmsp-util.h"
#include "format.h"
#include "trace.h"

/*
 * The build environment provides a VERSION macro that we aren't interested
 * in, and we've got our own below.
 */
#undef VERSION

#define ERRBUF(...)							\
	do {								\
		TRACE(__VA_ARGS__);					\
		TRACE_RAW("\n");					\
		if (errbuf != NULL)					\
			snprintf(errbuf, errbuflen, __VA_ARGS__);	\
	} while(0)

/* Create a compound literal for an array of type t */
#define ARRAY_VAL(t, ...)	((const t[]){ __VA_ARGS__ })
#define ARRAY_VAL_PTR(t, ...)	((const t * const)&ARRAY_VAL(t, __VA_ARGS__))
#define ARRAY_VAL_NUM(t, ...)	(sizeof(ARRAY_VAL(t, __VA_ARGS__)) / sizeof(t))

/*
 * Limit descriptors for unlimited value types as well as every
 * constrainable value type and its applicable limit types.  These are named
 * based on the value type names, not the underlying C types used.
 */
#define NO_LIMIT				\
	((struct value_limit){			\
		.type = NONE			\
	})
#define INT_RANGE_LIMIT(l, u)			\
	((struct value_limit){			\
		.type = RANGE,			\
		.range_min.i64 = (l),		\
		.range_max.i64 = (u)		\
	})
#define INT_SET_LIMIT(...)						\
	((struct value_limit){						\
		.type = SET,						\
		.num_set_members = ARRAY_VAL_NUM(int64_t, __VA_ARGS__),	\
		.set_of.i64 = ARRAY_VAL_PTR(int64_t, __VA_ARGS__)	\
	})
#define FLOAT_RANGE_LIMIT(l, u)			\
	((struct value_limit){			\
		.type = RANGE,			\
		.range_min.d = (l),		\
		.range_max.d = (u)		\
	})
#define FLOAT_SET_LIMIT(...)						\
	((struct value_limit){						\
		.type = SET,						\
		.num_set_members = ARRAY_VAL_NUM(double, __VA_ARGS__),	\
		.set_of.d = ARRAY_VAL_PTR(double, __VA_ARGS__)		\
	})
#define STRING_SET_LIMIT(...)						\
	((struct value_limit){						\
		.type = SET,						\
		.num_set_members = ARRAY_VAL_NUM(char *, __VA_ARGS__),	\
		.set_of.s = ARRAY_VAL_PTR(char *, __VA_ARGS__)		\
	})
#define BOOLEAN_RANGE_LIMIT(l)			\
	((struct value_limit){			\
		.type = RANGE,			\
		.range_min.b = (l),		\
		.range_max.b = (l)		\
	})
#define TIME_RANGE_LIMIT(l, u)			\
	((struct value_limit){			\
		.type = RANGE,			\
		.range_min.d = (l),		\
		.range_max.d = (u)		\
	})
#define TIME_SET_LIMIT(...)						\
	((struct value_limit){						\
		.type = SET,						\
		.num_set_members = ARRAY_VAL_NUM(double, __VA_ARGS__),	\
		.set_of.d = ARRAY_VAL_PTR(double, __VA_ARGS__)		\
	})
#define VERSION_RANGE_LIMIT(l, u)		\
	((struct value_limit){			\
		.type = RANGE,			\
		.range_min.i = (l),		\
		.range_max.i = (u)		\
	})
#define VERSION_SET_LIMIT(...)						\
	((struct value_limit){						\
		.type = SET,						\
		.num_set_members = ARRAY_VAL_NUM(int, __VA_ARGS__),	\
		.set_of.i = ARRAY_VAL_PTR(int, __VA_ARGS__)		\
	})
#define ENUM_LIMIT(...)							\
	((struct value_limit){						\
		.type = SET,						\
		.num_set_members = ARRAY_VAL_NUM(struct enum_pair, __VA_ARGS__), \
		.set_of.ep = ARRAY_VAL_PTR(struct enum_pair, __VA_ARGS__) \
	})

/*
 * Build a descriptor for a key whose value may be one or more value types
 */
#define KEY(k, ...)							\
	((struct key)							\
	{								\
		.key = (k),						\
		.num_types =						\
		    ARRAY_VAL_NUM(struct value_type, __VA_ARGS__),	\
		.types =						\
		    ARRAY_VAL_PTR(struct value_type, __VA_ARGS__)	\
	})
/*
 * Build a descriptor for a value that may be an aggregate of keys
 */
#define VALUE_TYPE(t, tg, l, ...)				\
	((struct value_type)					\
	{							\
		.type = (t),					\
		.tag = (tg),					\
		.limit = (l),					\
		.num_subkeys =					\
		    ARRAY_VAL_NUM(struct key, __VA_ARGS__),	\
		.subkeys =					\
		    ARRAY_VAL_PTR(struct key, __VA_ARGS__)	\
	})
#define NO_SUBKEYS { NULL, 0, NULL }

/*
 * Key value type descriptors for every value type, with and without
 * applicable limits
 */
#define TYPE(s)		TYPE_ ## s
#define TAG(tg)		VALUE_TAG_ ## tg

#define OBJECT(tg, ...)			VALUE_TYPE(TYPE(OBJECT), TAG(tg), NO_LIMIT, __VA_ARGS__)
#define OBJECT_ARRAY(tg, ...)		VALUE_TYPE(TYPE(OBJECT_ARRAY), TAG(tg), NO_LIMIT, __VA_ARGS__)
#define INT(tg)				VALUE_TYPE(TYPE(INT), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define INT_RANGE(tg, l, u)		VALUE_TYPE(TYPE(INT), TAG(tg), INT_RANGE_LIMIT(l, u), NO_SUBKEYS)
#define INT_SET(tg, ...)		VALUE_TYPE(TYPE(INT), TAG(tg), INT_SET_LIMIT(__VA_ARGS__), NO_SUBKEYS)
#define INT_ARRAY(tg)			VALUE_TYPE(TYPE(INT_ARRAY), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define INT_ARRAY_RANGE(tg, l, u)	VALUE_TYPE(TYPE(INT_ARRAY), TAG(tg), INT_RANGE_LIMIT(l, u), NO_SUBKEYS)
#define INT_ARRAY_SET(tg, ...)		VALUE_TYPE(TYPE(INT_ARRAY), TAG(tg), INT_SET_LIMIT(__VA_ARGS__), NO_SUBKEYS)
#define FLOAT(tg)			VALUE_TYPE(TYPE(FLOAT), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define FLOAT_RANGE(tg, l, u)		VALUE_TYPE(TYPE(FLOAT), TAG(tg), FLOAT_RANGE_LIMIT(l, u), NO_SUBKEYS)
#define FLOAT_SET(tg, ...)		VALUE_TYPE(TYPE(FLOAT), TAG(tg), FLOAT_SET_LIMIT(__VA_ARGS__), NO_SUBKEYS)
#define FLOAT_ARRAY(tg)			VALUE_TYPE(TYPE(FLOAT_ARRAY), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define FLOAT_ARRAY_RANGE(tg, l, u)	VALUE_TYPE(TYPE(FLOAT_ARRAY), TAG(tg), FLOAT_RANGE_LIMIT(l, u), NO_SUBKEYS)
#define FLOAT_ARRAY_SET(tg, ...)	VALUE_TYPE(TYPE(FLOAT_ARRAY), TAG(tg), FLOAT_SET_LIMIT(__VA_ARGS__), NO_SUBKEYS)
#define STRING(tg)			VALUE_TYPE(TYPE(STRING), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define STRING_SET(tg, ...)		VALUE_TYPE(TYPE(STRING), TAG(tg), STRING_SET_LIMIT(__VA_ARGS__), NO_SUBKEYS)
#define STRING_ARRAY(tg)		VALUE_TYPE(TYPE(STRING_ARRAY), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define STRING_ARRAY_SET(tg, ...)	VALUE_TYPE(TYPE(STRING_ARRAY), TAG(tg), STRING_SET_LIMIT(__VA_ARGS__), NO_SUBKEYS)
#define BOOLEAN(tg)			VALUE_TYPE(TYPE(BOOLEAN), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define BOOLEAN_RANGE(tg, l)		VALUE_TYPE(TYPE(BOOLEAN), TAG(tg), BOOLEAN_RANGE_LIMIT(l), NO_SUBKEYS)
#define BOOLEAN_ARRAY(tg)		VALUE_TYPE(TYPE(BOOLEAN_ARRAY), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define BOOLEAN_ARRAY_RANGE(tg, l)	VALUE_TYPE(TYPE(BOOLEAN_ARRAY), TAG(tg), BOOLEAN_RANGE_LIMIT(l), NO_SUBKEYS)
#define TIME(tg)			VALUE_TYPE(TYPE(TIME), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define TIME_RANGE(tg, l, u)		VALUE_TYPE(TYPE(TIME), TAG(tg), TIME_RANGE_LIMIT(l, u), NO_SUBKEYS)
#define TIME_SET(tg, ...)		VALUE_TYPE(TYPE(TIME), TAG(tg), TIME_SET_LIMIT(__VA_ARGS_), NO_SUBKEYS)
#define TIME_ARRAY(tg)			VALUE_TYPE(TYPE(TIME_ARRAY), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define TIME_ARRAY_RANGE(tg, l, u)	VALUE_TYPE(TYPE(TIME_ARRAY), TAG(tg), TIME_RANGE_LIMIT(l, u), NO_SUBKEYS)
#define TIME_ARRAY_SET(tg, ...)		VALUE_TYPE(TYPE(TIME_ARRAY), TAG(tg), TIME_SET_LIMIT(__VA_ARGS_), NO_SUBKEYS)
#define VERSION(tg)			VALUE_TYPE(TYPE(VERSION), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define VERSION_RANGE(tg, l, u)		VALUE_TYPE(TYPE(VERSION), TAG(tg), VERSION_RANGE_LIMIT(l, u), NO_SUBKEYS)
#define VERSION_SET(tg, ...)		VALUE_TYPE(TYPE(VERSION), TAG(tg), VERSION_SET_LIMIT(__VA_ARGS__), NO_SUBKEYS)
#define VERSION_ARRAY(tg)		VALUE_TYPE(TYPE(VERSION_ARRAY), TAG(tg), NO_LIMIT, NO_SUBKEYS)
#define VERSION_ARRAY_RANGE(tg, l, u)	VALUE_TYPE(TYPE(VERSION_ARRAY), TAG(tg), VERSION_RANGE_LIMIT(l, u), NO_SUBKEYS)
#define VERSION_ARRAY_SET(tg, ...)	VALUE_TYPE(TYPE(VERSION_ARRAY), TAG(tg), VERSION_SET_LIMIT(__VA_ARGS__), NO_SUBKEYS)
#define ENUM(tg, ...)			VALUE_TYPE(TYPE(ENUM), TAG(tg), ENUM_LIMIT(__VA_ARGS__), NO_SUBKEYS)
#define ENUM_ARRAY(tg, ...)		VALUE_TYPE(TYPE(ENUM_ARRAY), TAG(tg), ENUM_LIMIT(__VA_ARGS__), NO_SUBKEYS)


static bool fmt_ucl_type_is_primitive(const ucl_object_t *obj);
static bool fmt_value_type_is_primitive(const struct value_type *value_fmt);
static const char *fmt_make_string(const char *format, ...);
static bool fmt_extract_string_value(const ucl_object_t *obj, const char **str);
static bool fmt_ucl_object_to_version(const ucl_object_t *obj, int *v);
static const struct value_type *fmt_find_value_type_by_tag(const struct value_type *cfg,
                                                           enum value_tag tag);


/*
 * Definition of the config file as a hierarchy of keys, their values, and
 * their value limits.  Value descriptors include a tag the parser can use
 * to invoke handlers when those values are encountered.
 */
const struct value_type cfg_format =
  OBJECT(NO_TAG,
         KEY("context",
              OBJECT_ARRAY(CONTEXT,
                           KEY("id", INT_RANGE(CONTEXT_ID,
                                               TLMSP_UTIL_CONTEXT_ID_MIN,
                                               TLMSP_UTIL_CONTEXT_ID_MAX)),
                           KEY("tag", STRING(CONTEXT_TAG)),
                           KEY("comment", STRING(CONTEXT_COMMENT)),
                           KEY("purpose", STRING(CONTEXT_PURPOSE)),
                           KEY("audit", BOOLEAN(CONTEXT_AUDIT)))),
         KEY("activity",
              OBJECT_ARRAY(ACTIVITY,
                           KEY("tag", STRING(ACTIVITY_TAG)),
                           KEY("match",
                                OBJECT(ACTIVITY_MATCH,
                                       KEY("which",
                                            INT_ARRAY_RANGE(ACTIVITY_MATCH_WHICH_IDS,
                                                            TLMSP_UTIL_CONTEXT_ID_MIN,
                                                            TLMSP_UTIL_CONTEXT_ID_MAX),
                                            STRING_ARRAY(ACTIVITY_MATCH_WHICH_TAGS)),
                                       KEY("at", INT_RANGE(ACTIVITY_MATCH_AT,
                                                           0,
                                                           TLMSP_CFG_MATCH_AT_MAX_MS)),
                                       KEY("every", INT_RANGE(ACTIVITY_MATCH_EVERY,
                                                              1,
                                                              TLMSP_CFG_MATCH_EVERY_MAX_MS)),
                                       KEY("container",
                                            FLOAT_RANGE(ACTIVITY_MATCH_CONTAINER_PROBABILITY,
                                                        0.0,
                                                        1.0),
                                            INT_RANGE(ACTIVITY_MATCH_CONTAINER_N,
                                                      1,
                                                      TLMSP_CFG_MATCH_CONTAINER_MAX),
					   STRING_SET(ACTIVITY_MATCH_CONTAINER_ALL, "*", "all")),
                                       KEY("data", STRING(ACTIVITY_MATCH_DATA)),
                                       KEY("file", STRING(ACTIVITY_MATCH_FILE)),
                                       KEY("regex", STRING(ACTIVITY_MATCH_REGEX)),
                                       KEY("forward", BOOLEAN(ACTIVITY_MATCH_FORWARD)))),
                           KEY("action",
                                OBJECT_ARRAY(ACTIVITY_ACTION,
#ifdef notyet
                                       KEY("fault",
                                            ENUM(ACTIVITY_ACTION_FAULT,
                                                 { "corrupt-data",   TLMSP_CFG_ACTION_FAULT_CORRUPT_DATA },
                                                 { "corrupt-header", TLMSP_CFG_ACTION_FAULT_CORRUPT_HEADER },
                                                 { "corrupt-mac",    TLMSP_CFG_ACTION_FAULT_CORRUPT_MAC },
                                                 { "drop",           TLMSP_CFG_ACTION_FAULT_DROP },
                                                 { "reorder",        TLMSP_CFG_ACTION_FAULT_REORDER } )),
#endif
                                       KEY("log",
                                            OBJECT_ARRAY(ACTIVITY_ACTION_LOG,
#ifdef notyet
                                                   KEY("file", STRING(ACTIVITY_ACTION_LOG_FILE)),
#endif
                                                   KEY("handler", STRING(ACTIVITY_ACTION_LOG_HANDLER)))),
                                       KEY("send",
                                            OBJECT_ARRAY(ACTIVITY_ACTION_SEND,
                                                   KEY("context",
                                                        INT_RANGE(ACTIVITY_ACTION_SEND_CONTEXT_ID,
                                                                  TLMSP_UTIL_CONTEXT_ID_MIN,
                                                                  TLMSP_UTIL_CONTEXT_ID_MAX),
                                                        STRING(ACTIVITY_ACTION_SEND_CONTEXT_TAG)),
                                                   KEY("data", STRING(ACTIVITY_ACTION_SEND_DATA)),
                                                   KEY("file", STRING(ACTIVITY_ACTION_SEND_FILE)),
                                                   KEY("handler", STRING(ACTIVITY_ACTION_SEND_HANDLER)),
                                                   KEY("template", STRING(ACTIVITY_ACTION_SEND_TEMPLATE)))),
                                       KEY("reply",
                                            OBJECT_ARRAY(ACTIVITY_ACTION_REPLY,
                                                   KEY("context",
                                                        INT_RANGE(ACTIVITY_ACTION_REPLY_CONTEXT_ID,
                                                                  TLMSP_UTIL_CONTEXT_ID_MIN,
                                                                  TLMSP_UTIL_CONTEXT_ID_MAX),
                                                        STRING(ACTIVITY_ACTION_REPLY_CONTEXT_TAG)),
                                                   KEY("data", STRING(ACTIVITY_ACTION_REPLY_DATA)),
                                                   KEY("file", STRING(ACTIVITY_ACTION_REPLY_FILE)),
                                                   KEY("handler", STRING(ACTIVITY_ACTION_REPLY_HANDLER)),
                                                   KEY("template", STRING(ACTIVITY_ACTION_REPLY_TEMPLATE)))),
                                       KEY("alert",
                                            OBJECT_ARRAY(ACTIVITY_ACTION_ALERT,
                                                   KEY("context",
                                                        INT_RANGE(ACTIVITY_ACTION_ALERT_CONTEXT_ID,
                                                                  0,
                                                                  TLMSP_UTIL_CONTEXT_ID_MAX),
                                                        STRING(ACTIVITY_ACTION_ALERT_CONTEXT_TAG)),
                                                   KEY("level",
                                                        ENUM(ACTIVITY_ACTION_ALERT_LEVEL,
                                                             { "warning", TLMSP_CFG_ACTION_ALERT_LEVEL_WARNING },
                                                             { "fatal",   TLMSP_CFG_ACTION_ALERT_LEVEL_FATAL } )),
                                                   KEY("description",
                                                        ENUM(ACTIVITY_ACTION_ALERT_DESC_ENUM,
                                                             { "close_notify",                     TLMSP_CFG_ACTION_ALERT_DESC_CLOSE_NOTIFY },
                                                             { "unexpected_message",               TLMSP_CFG_ACTION_ALERT_DESC_UNEXPECTED_MSG },
                                                             { "bad_record_mac",                   TLMSP_CFG_ACTION_ALERT_DESC_BAD_RECORD_MAC },
                                                             { "record_overflow",                  TLMSP_CFG_ACTION_ALERT_DESC_RECORD_OVERFLOW },
                                                             { "decompression_failure",            TLMSP_CFG_ACTION_ALERT_DESC_DECOMPRESSION_FAIL },
                                                             { "handshake_failure",                TLMSP_CFG_ACTION_ALERT_DESC_HANDSHAKE_FAIL },
                                                             { "bad_certificate",                  TLMSP_CFG_ACTION_ALERT_DESC_BAD_CERT },
                                                             { "unsupported_certificate",          TLMSP_CFG_ACTION_ALERT_DESC_UNSUPPORTED_CERT },
                                                             { "certificate_revoked",              TLMSP_CFG_ACTION_ALERT_DESC_CERT_REVOKED },
                                                             { "certificate_expired",              TLMSP_CFG_ACTION_ALERT_DESC_CERT_EXPIRED },
                                                             { "certificate_unknown",              TLMSP_CFG_ACTION_ALERT_DESC_CERT_UNKNOWN },
                                                             { "illegal_parameter",                TLMSP_CFG_ACTION_ALERT_DESC_ILLEGAL_PARAM },
                                                             { "unknown_ca",                       TLMSP_CFG_ACTION_ALERT_DESC_UNKNOWN_CA },
                                                             { "access_denied",                    TLMSP_CFG_ACTION_ALERT_DESC_ACCESS_DENIED },
                                                             { "decode_error",                     TLMSP_CFG_ACTION_ALERT_DESC_DECODE_ERROR },
                                                             { "decrypt_error",                    TLMSP_CFG_ACTION_ALERT_DESC_DECRYPT_ERROR },
                                                             { "protocol_version",                 TLMSP_CFG_ACTION_ALERT_DESC_PROTOCOL_VERSION },
                                                             { "insufficient_security",            TLMSP_CFG_ACTION_ALERT_DESC_INSUFF_SECURITY },
                                                             { "internal_error",                   TLMSP_CFG_ACTION_ALERT_DESC_INTERNAL_ERROR },
                                                             { "user_canceled",                    TLMSP_CFG_ACTION_ALERT_DESC_USER_CANCELED },
                                                             { "no_renegotiation",                 TLMSP_CFG_ACTION_ALERT_DESC_NO_RENEGOTIATION },
                                                             { "unsupported_extension",            TLMSP_CFG_ACTION_ALERT_DESC_UNSUPPORTED_EXT },
                                                             { "middlebox_route_failure",          TLMSP_CFG_ACTION_ALERT_DESC_MBOX_ROUTE_FAIL },
                                                             { "middlebox_auth_failure",           TLMSP_CFG_ACTION_ALERT_DESC_MBOX_AUTH_FAIL },
                                                             { "middlebox_required",               TLMSP_CFG_ACTION_ALERT_DESC_MBOX_REQUIRED },
                                                             { "unknown_context",                  TLMSP_CFG_ACTION_ALERT_DESC_UNKNOWN_CONTEXT },
                                                             { "unsupported_context",              TLMSP_CFG_ACTION_ALERT_DESC_UNSUPPORTED_CONTEXT },
                                                             { "middlebox_key_verify_failure",     TLMSP_CFG_ACTION_ALERT_DESC_MBOX_KEY_VERIFY_FAIL },
                                                             { "bad_reader_mac",                   TLMSP_CFG_ACTION_ALERT_DESC_BAD_READER_MAC },
                                                             { "bad_writer_mac",                   TLMSP_CFG_ACTION_ALERT_DESC_BAD_WRITER_MAC },
                                                             { "middlebox_key_confirmation_fault", TLMSP_CFG_ACTION_ALERT_DESC_MBOX_KEY_CONFIRM_FAULT },
                                                             { "authentication_required",          TLMSP_CFG_ACTION_ALERT_DESC_AUTH_REQUIRED } ),
							INT_RANGE(ACTIVITY_ACTION_ALERT_DESC_INT, 0, 255)))),
                                       KEY("shutdown", BOOLEAN(ACTIVITY_ACTION_SHUTDOWN)),
                                       KEY("renegotiate", BOOLEAN(ACTIVITY_ACTION_RENEGOTIATE)))),
                           KEY("present", BOOLEAN(ACTIVITY_PRESENT)))),
         KEY("client",
              OBJECT(CLIENT,
                     KEY("version",
                          VERSION_SET(CLIENT_VERSION_SINGLE, PROTOCOL_VERSIONS),
                          OBJECT(CLIENT_VERSION_RANGE,
                                 KEY("min",
                                      VERSION_SET(CLIENT_VERSION_MIN,
                                                  PROTOCOL_VERSIONS)),
                                 KEY("max",
                                      VERSION_SET(CLIENT_VERSION_MAX,
                                                  PROTOCOL_VERSIONS)))),
                     KEY("address", STRING(CLIENT_ADDRESS)),
                     KEY("function", STRING_ARRAY(CLIENT_FUNCTION)))),
         KEY("server",
              OBJECT(SERVER,
                     KEY("version",
                          VERSION_SET(SERVER_VERSION_SINGLE, PROTOCOL_VERSIONS),
                          OBJECT(SERVER_VERSION_RANGE,
                                 KEY("min",
                                      VERSION_SET(SERVER_VERSION_MIN,
                                                  PROTOCOL_VERSIONS)),
                                 KEY("max",
                                      VERSION_SET(SERVER_VERSION_MAX,
                                                  PROTOCOL_VERSIONS)))),
                     KEY("address", STRING(SERVER_ADDRESS)),
                     KEY("cert-file", STRING(SERVER_CERT_FILE)),
                     KEY("cert-key-file", STRING(SERVER_CERT_KEY_FILE)),
                     KEY("function", STRING_ARRAY(SERVER_FUNCTION)))),
         KEY("middlebox",
              OBJECT_ARRAY(MIDDLEBOX,
                           KEY("tag", STRING(MIDDLEBOX_TAG)),
                           KEY("address", STRING(MIDDLEBOX_ADDRESS)),
                           KEY("cert-file", STRING(MIDDLEBOX_CERT_FILE)),
                           KEY("cert-key-file", STRING(MIDDLEBOX_CERT_KEY_FILE)),
                           KEY("transparent", BOOLEAN(MIDDLEBOX_TRANSPARENT)),
                           KEY("discovered", BOOLEAN(MIDDLEBOX_DISCOVERED)),
                           KEY("forbidden", BOOLEAN(MIDDLEBOX_FORBIDDEN)),
                           KEY("context",
                                OBJECT_ARRAY(MIDDLEBOX_CONTEXT,
                                             KEY("which",
                                                  INT_ARRAY_RANGE(MIDDLEBOX_CONTEXT_WHICH_IDS,
                                                                  TLMSP_UTIL_CONTEXT_ID_MIN,
                                                                  TLMSP_UTIL_CONTEXT_ID_MAX),
                                                  STRING_ARRAY(MIDDLEBOX_CONTEXT_WHICH_TAGS)),
                                             KEY("access",
                                                  ENUM(MIDDLEBOX_CONTEXT_ACCESS,
                                                       { "none",  TLMSP_CFG_CTX_ACCESS_NONE },
                                                       { "r",     TLMSP_CFG_CTX_ACCESS_R },
                                                       { "rw",    TLMSP_CFG_CTX_ACCESS_RW } )))),
                           KEY("function-to-client", STRING_ARRAY(MIDDLEBOX_FUNCTION_TO_CLIENT)),
                           KEY("function-to-server", STRING_ARRAY(MIDDLEBOX_FUNCTION_TO_SERVER)))));


const struct key *
fmt_obj_find_key(const struct value_type *obj, const char *key, char *errbuf,
    size_t errbuflen)
{
	unsigned int i;

	for (i = 0; i < obj->num_subkeys; i++)
		if (strcmp(obj->subkeys[i].key, key) == 0)
			return (&obj->subkeys[i]);

	ERRBUF("unknown key '%s'", key);

	return (NULL);
}

const struct value_type *
fmt_find_value_type_by_ucl_type(const struct key *key, ucl_type_t ucl_type,
    bool container_is_array, char *errbuf, size_t errbuflen)
{
	unsigned int i;
	unsigned int pass;
	ucl_type_t orig_ucl_type = ucl_type;

	/* Arrays of arrays aren't supported */
	if (ucl_type == UCL_ARRAY && container_is_array) {
		ERRBUF("arrays of arrays are not supported");
		return (NULL);
	}

	pass = 0;
again:
	pass++;
	for (i = 0; i < key->num_types; i++) {
		/* 
		 * Keys in array containers can only match array value
		 * types.
		 */
		if (container_is_array && !IS_ARRAY(key->types[i].type))
			continue;

		/* 
		 * A UCL_ARRAY is OK is there is at least one array value type.
		 */
		if (((ucl_type == UCL_ARRAY) && IS_ARRAY(key->types[i].type)) ||
		    UCL_TYPE(key->types[i].type) == ucl_type) {
			TRACE("matched %s value for %s key '%s' to type %s\n",
			    fmt_ucl_type_name(orig_ucl_type),
			    container_is_array ? "array" : "scalar",
			    key->key,
			    fmt_type_name(key->types[i].type));
			return (&key->types[i]);
		}
	}

	/*
	 * On the second pass:
	 *
	 *  - We allow a parsed UCL_INT to match a value type looking for a
	 *    UCL_FLOAT.
	 *
	 * On the third pass:
	 *
	 *  - We allow a UCL_INT, UCL_FLOAT, and UCL_BOOLEAN to match a
         *    value type looking for a UCL_STRING.  Note that with this
         *    approach, UCL_FLOAT and UCL_BOOLEAN are going to in general
         *    experience some conversion artifacts as we can't access the
         *    original strings that were parsed (e.g., how many decimal
         *    places for the string representation of a float, and what
         *    representation of a bool to use?)
	 */
	if ((pass == 1)  && (ucl_type == UCL_INT)) {
		ucl_type = UCL_FLOAT;
		goto again;
	}

	if (pass == 2) {
		switch (ucl_type) {
		case UCL_INT:
		case UCL_FLOAT:
		case UCL_BOOLEAN:
			ucl_type = UCL_STRING;
			goto again;
			break;
		default:
			break;
		}
	}

	ERRBUF("no match found for %s value for %s key '%s'",
	    fmt_ucl_type_name(orig_ucl_type),
	    container_is_array ? "array" : "scalar",
	    key->key);
	
	return (NULL);
}

bool
fmt_get_value(const struct value_type *value_fmt, const ucl_object_t *obj, struct value *v)
{
	struct value value;
	const struct value_limit *limit;
	ucl_type_t ucl_type;
	unsigned int scalar_fmt_type;
	unsigned int i;
	
	/*
	 * Both the ucl object and the corresponding value type format
	 * should be for primitive types.
	 */
	ucl_type = ucl_object_type(obj);
	scalar_fmt_type = SCALAR_TYPE(value_fmt->type);
	if (!fmt_ucl_type_is_primitive(obj) ||
	    !fmt_value_type_is_primitive(value_fmt)) {
		TRACE("attempt to extract value for non-primitive type (%s -> %s)\n",
		    fmt_ucl_type_name(ucl_type),
		    fmt_type_name(scalar_fmt_type));
		return (false);  /* Should never happen */
	}

	/*
	 * Extract the expected value type from the ucl object.  A given
	 * value type may have multiple ucl types that can match to it
	 * according to the logic in fmt_find_value_type_by_ucl_type().
	 */
	value.sid = scalar_fmt_type;
	switch (scalar_fmt_type) {
	case TYPE_INT:
		value.type_int = ucl_object_toint(obj);
		break;
	case TYPE_FLOAT:
		/*
		 * May have matched a UCL_FLOAT or UCL_INT in
		 * fmt_find_value_type_by_ucl_type().
		 */
		switch (ucl_type) {
		case UCL_INT:
			value.type_float = ucl_object_toint(obj);
			break;
		case UCL_FLOAT:
			value.type_float = ucl_object_todouble(obj);
			break;
		default:
			TRACE("unexpected type %s for conversion to %s\n",
			    fmt_ucl_type_name(ucl_type),
			    fmt_type_name(scalar_fmt_type));
			return (false);  /* should not happen */
		}
		break;
	case TYPE_STRING:
		if (!fmt_extract_string_value(obj, &value.type_string))
			return (false);
		break;
	case TYPE_BOOLEAN:
		value.type_boolean = ucl_object_toboolean(obj);
		break;
	case TYPE_TIME:
		value.type_time = ucl_object_todouble(obj);
		break;
	case TYPE_VERSION:
		if (!fmt_ucl_object_to_version(obj, &value.type_version)) {
			TRACE("failed to extract value of TYPE_VERSION - bad format\n");
			return (false);
		}
		break;
	case TYPE_ENUM:
		/*
		 * The string value is established here.  It will be
		 * converted to the enum index value in the limit check
		 * below.
		 */
		if (!fmt_extract_string_value(obj, &value.type_enum.s))
			return (false);
		break;
	default:
		TRACE("attempt to extract value for unsupported type %s\n",
		    fmt_type_name(scalar_fmt_type));
		return (false);  /* should never see this */
	}

	/*
	 * Check the extracted value against the limits
	 */
	limit = &value_fmt->limit;
	switch (limit->type) {
	case NONE:
		break;
	case RANGE:
		switch (C_TYPE(value_fmt->type)) {
		case C_INT:
			if ((value.v.i < limit->range_min.i) ||
			    (value.v.i > limit->range_max.i)) {
				TRACE("extracted value %d, of %s is outside of range [%d, %d]\n",
				    value.v.i,
				    fmt_type_name(scalar_fmt_type),
				    limit->range_min.i, limit->range_max.i);
				return (false);
			}
			break;
		case C_INT64:
			if ((value.v.i64 < limit->range_min.i64) ||
			    (value.v.i64 > limit->range_max.i64)) {
				TRACE("extracted value %" PRId64 " of %s is "
				    "outside of range [%" PRId64 ", %" PRId64 "]\n",
				    value.v.i64,
				    fmt_type_name(scalar_fmt_type),
				    limit->range_min.i64,
				    limit->range_max.i64);
				return (false);
			}
			break;
		case C_DOUBLE:
			if ((value.v.d < limit->range_min.d) ||
			    (value.v.d > limit->range_max.d)) {
				TRACE("extracted value %f of %s is outside of range [%f, %f]\n",
				    value.v.d,
				    fmt_type_name(scalar_fmt_type),
				    limit->range_min.d, limit->range_max.d);
				return (false);
			}
			break;
		case C_BOOL:
			if ((value.v.b != limit->range_min.b) &&
			    (value.v.b != limit->range_max.b)) {
				TRACE("extracted value %s of %s is outside of range [%s, %s]\n",
				    value.v.b ? "true" : "false",
				    fmt_type_name(scalar_fmt_type),
				    limit->range_min.b ? "true" : "false",
				    limit->range_max.b ? "true" : "false");
				return (false);
			}
			break;
		default:
			TRACE("range limit not supported for %s\n",
			    fmt_type_name(scalar_fmt_type));
			return (false);
			break;
		}
		break;
	case SET:
		switch (C_TYPE(value_fmt->type)) {
		case C_INT:
			for (i = 0; i < limit->num_set_members; i++) {
				if (value.v.i == limit->set_of.i[i])
					break;
			}
			if (i == limit->num_set_members) {
				TRACE("extracted value %d of %s is outside of limit set\n",
				    value.v.i,
				    fmt_type_name(scalar_fmt_type));
				return (false);
			}
			break;
		case C_INT64:
			for (i = 0; i < limit->num_set_members; i++) {
				if (value.v.i64 == limit->set_of.i64[i])
					break;
			}
			if (i == limit->num_set_members) {
				TRACE("extracted value %" PRId64 " of %s is "
				    "outside of limit set\n",
				    value.v.i64,
				    fmt_type_name(scalar_fmt_type));
				return (false);
			}
			break;
		case C_DOUBLE:
			for (i = 0; i < limit->num_set_members; i++) {
				if (value.v.d == limit->set_of.d[i])
					break;
			}
			if (i == limit->num_set_members) {
				TRACE("extracted value %f of %s is outside of limit set\n",
				    value.v.d,
				    fmt_type_name(scalar_fmt_type));
				return (false);
			}
			break;
		case C_STRING:
			for (i = 0; i < limit->num_set_members; i++) {
				if (strcmp(value.v.s, limit->set_of.s[i]) == 0)
					break;
			}
			if (i == limit->num_set_members) {
				TRACE("extracted value %s of %s is outside of limit set\n",
				    value.v.s,
				    fmt_type_name(scalar_fmt_type));
				return (false);
			}
			break;
		case C_ENUM_PAIR:
			for (i = 0; i < limit->num_set_members; i++) {
				if (strcmp(value.v.ep.s, limit->set_of.ep[i].s) == 0)
					break;
			}
			if (i == limit->num_set_members) {
				TRACE("extracted value %s of %s is outside of limit set\n",
				    value.v.ep.s,
				    fmt_type_name(scalar_fmt_type));
				return (false);
			}
			value.v.ep.e = limit->set_of.ep[i].e;
			break;
		default:
			TRACE("set limit not supported for %s\n",
			    fmt_type_name(scalar_fmt_type));
			return (false);
			break;
		}
		break;
	}

	TRACE("extracted value ");
	switch (C_TYPE(value_fmt->type)) {
	case C_INT: TRACE_RAW("%d ", value.v.i); break;
	case C_INT64: TRACE_RAW("%" PRId64 " ", value.v.i64); break;
	case C_DOUBLE: TRACE_RAW("%f ", value.v.d); break;
	case C_STRING: TRACE_RAW("%s ", value.v.s); break;
	case C_BOOL: TRACE_RAW("%s ", value.v.b ? "true" : "false"); break;
	case C_ENUM_PAIR: TRACE_RAW("%s (%u) ", value.v.ep.s, value.v.ep.e); break;
	default: TRACE_RAW("<unknown type> ");
	}
	TRACE_RAW("for type %s\n",fmt_type_name(scalar_fmt_type));

	*v = value;
	
	return (true);
}

static bool
fmt_ucl_type_is_primitive(const ucl_object_t *obj)
{
	switch (ucl_object_type(obj)) {
	case UCL_INT:
	case UCL_FLOAT:
	case UCL_STRING:
	case UCL_BOOLEAN:
	case UCL_TIME:
		return (true);
	default:
		return (false);
	}
}

static bool
fmt_value_type_is_primitive(const struct value_type *value_fmt)
{
	return (C_TYPE(value_fmt->type) != C_COMPOSITE);
}

static const char *
fmt_make_string(const char *format, ...)
{
	va_list ap;
	int size;
	char * buf;
	
	va_start(ap, format);
	size = vsnprintf(NULL, 0, format, ap);
	buf = malloc(size + 1);
	if (buf != NULL)
		vsnprintf(buf, size + 1, format, ap);
	va_end(ap);

	return (buf);
}

static bool
fmt_extract_string_value(const ucl_object_t *obj, const char **result)
{
	ucl_type_t ucl_type;
	const char *str;

	ucl_type = ucl_object_type(obj);

	/*
	 * May have matched a UCL_INT, UCL_FLOAT, or UCL_BOOLEAN in
	 * fmt_find_value_type_by_ucl_type().
	 */
	switch (ucl_type) {
	case UCL_INT:
		str = fmt_make_string("%" PRId64, ucl_object_toint(obj));
		break;
	case UCL_FLOAT: {
		double tmp;

		tmp = ucl_object_todouble(obj);
		if (isnan(tmp)) /* text was "nan" without quotes */
			str = strdup("nan");
		else if (isinf(tmp)) /* text was "inf" without quotes */
			str = strdup("inf");
		else
			str = fmt_make_string("%.3f", tmp);
		break;
	}
	case UCL_STRING:
		str = ucl_object_tostring(obj);
		if (str != NULL)
			str = strdup(str);
		break;
	case UCL_BOOLEAN:
		if (ucl_object_toboolean(obj))
			str = strdup("true");
		else
			str = strdup("false");
		break;
	default:
		TRACE("unexpected type %s for conversion to TYPE_STRING\n",
		    fmt_ucl_type_name(ucl_type));
		return (false);  /* should not happen */
	}
	if (str == NULL) {
		TRACE("failed to extract value of TYPE_STRING - memory allocation failed\n");
		return (false);
	}
	/*
	 * The parser does not provide any NULL string pointers in
	 * the completed configuration structure, so during
	 * initialization of each element, unset strings are set to
	 * point to an empty string.  The parser treats all empty
	 * strings as statically allocated in order to avoid
	 * gratuitous strdup(""), so don't return a dynamically
	 * allocated empty string in the value.
	 */
	if (str[0] == '\0') {
		free((void *)str);
		str = "";
	}

	*result = str;
	
	return (true);
}

static bool
fmt_ucl_object_to_version(const ucl_object_t *obj, int *v)
{
	const char *str;
	const char *dot;
	const char *p;

	str = ucl_object_tostring(obj);
	if (str == NULL)
		return (false);

	/* Valid version strings are 'vMajor.Minor', e.g. v1.0 */
	if (str[0] != 'v')
		return (false);

	dot = strchr(str, '.');
	if (dot == NULL)
		return (false);

	/* only base 10 digits allowed between 'v' and '.' */
	for (p = str + 1; *p != '.'; p++)
		if (!isdigit(*p))
			return (false);

	/* must be at least one digit between 'v' and '.' */
	if (str + 1 == dot)
		return (false);

	/* first digit of major can't be zero */
	if (str[1] == '0')
		return (false);
	
	/* only base 10 digits allowed between '.' and end */
	for (p = dot + 1; *p != '\0'; p++)
		if (!isdigit(*p))
			return (false);

	/* must be at least one digit between '.' and end */
	if (dot[1] == '\0')
		return (false);

	*v = TLMSP_CFG_PROTO_VERSION(strtoul(&str[1], NULL, 10),
	    strtoul(&dot[1], NULL, 10));
	
	return (true);
}

static const struct value_type *
fmt_find_value_type_by_tag(const struct value_type *cfg, enum value_tag tag)
{
	unsigned int i, j;
	const struct key *subkey;
	const struct value_type *result;
	
	if (cfg->tag == tag)
		return (cfg);

	for (i = 0; i < cfg->num_subkeys; i++) {
		subkey = &cfg->subkeys[i];
		for (j = 0; j < subkey->num_types; j++) {
			result = fmt_find_value_type_by_tag(&subkey->types[j],
			    tag);
			if (result != NULL)
				return (result);
		}
	}

	return (NULL);
}

unsigned int
fmt_find_value_type_limit_set_by_tag(const struct value_type *cfg,
    enum value_tag tag, unsigned int scalar_type, const union limit_set **result)
{
	const struct value_type *v;

	v = fmt_find_value_type_by_tag(cfg, tag);
	if ((v == NULL) || (SCALAR_TYPE(v->type) != scalar_type) ||
	    (v->limit.type != SET))
		return (0);

	*result = &v->limit.set_of;
	return (v->limit.num_set_members);
}

const char *
fmt_type_name(unsigned int type)
{
#define TOSTR(x) #x
#define HANDLE(x) case x: return (TOSTR(x))

	switch (type) {
		HANDLE(TYPE_OBJECT);
		HANDLE(TYPE_OBJECT_ARRAY);
		HANDLE(TYPE_INT);
		HANDLE(TYPE_INT_ARRAY);
		HANDLE(TYPE_FLOAT);
		HANDLE(TYPE_FLOAT_ARRAY);
		HANDLE(TYPE_STRING);
		HANDLE(TYPE_STRING_ARRAY);
		HANDLE(TYPE_BOOLEAN);
		HANDLE(TYPE_BOOLEAN_ARRAY);
		HANDLE(TYPE_TIME);
		HANDLE(TYPE_TIME_ARRAY);
		HANDLE(TYPE_VERSION);
		HANDLE(TYPE_VERSION_ARRAY);
		HANDLE(TYPE_ENUM);
		HANDLE(TYPE_ENUM_ARRAY);
	default:
		return ("<unknown type>");
	}

#undef HANDLE
#undef TOSTR
}

const char *
fmt_ucl_type_name(ucl_type_t type)
{
#define TOSTR(x) #x
#define HANDLE(x) case x: return (TOSTR(x))

	switch (type) {
		HANDLE(UCL_OBJECT);
		HANDLE(UCL_ARRAY);
		HANDLE(UCL_INT);
		HANDLE(UCL_FLOAT);
		HANDLE(UCL_STRING);
		HANDLE(UCL_BOOLEAN);
		HANDLE(UCL_TIME);
		HANDLE(UCL_USERDATA);
		HANDLE(UCL_NULL);
	}

#undef HANDLE	
#undef TOSTR
}

#ifdef TRACE_ENABLED
const char *
fmt_value_tag_name(enum value_tag tag)
{
#define TOSTR(x) #x
#define HANDLE(x) case x: return (TOSTR(x))

	switch (tag) {
		HANDLE(VALUE_TAG_NO_TAG);
		HANDLE(VALUE_TAG_TOP_OBJECT);
		HANDLE(VALUE_TAG_ACTIVITY);
		HANDLE(VALUE_TAG_ACTIVITY_TAG);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_WHICH_IDS);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_WHICH_TAGS);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_AT);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_EVERY);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_CONTAINER_PROBABILITY);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_CONTAINER_N);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_CONTAINER_ALL);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_DATA);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_FILE);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_REGEX);
		HANDLE(VALUE_TAG_ACTIVITY_MATCH_FORWARD);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_FAULT);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_RENEGOTIATE);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_SHUTDOWN);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_LOG);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_LOG_FILE);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_LOG_HANDLER);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_SEND);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_ID);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_TAG);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_SEND_DATA);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_SEND_FILE);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_SEND_HANDLER);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_SEND_TEMPLATE);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_REPLY);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_REPLY_CONTEXT_ID);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_REPLY_CONTEXT_TAG);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_REPLY_DATA);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_REPLY_FILE);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_REPLY_HANDLER);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_REPLY_TEMPLATE);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_ALERT);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_ALERT_CONTEXT_ID);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_ALERT_CONTEXT_TAG);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_ALERT_LEVEL);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_ALERT_DESC_ENUM);
		HANDLE(VALUE_TAG_ACTIVITY_ACTION_ALERT_DESC_INT);
		HANDLE(VALUE_TAG_ACTIVITY_PRESENT);
		HANDLE(VALUE_TAG_CLIENT);
		HANDLE(VALUE_TAG_CLIENT_VERSION_SINGLE);
		HANDLE(VALUE_TAG_CLIENT_VERSION_RANGE);
		HANDLE(VALUE_TAG_CLIENT_VERSION_MIN);
		HANDLE(VALUE_TAG_CLIENT_VERSION_MAX);
		HANDLE(VALUE_TAG_CLIENT_ADDRESS);
		HANDLE(VALUE_TAG_CLIENT_FUNCTION);
		HANDLE(VALUE_TAG_SERVER);
		HANDLE(VALUE_TAG_SERVER_VERSION_SINGLE);
		HANDLE(VALUE_TAG_SERVER_VERSION_RANGE);
		HANDLE(VALUE_TAG_SERVER_VERSION_MIN);
		HANDLE(VALUE_TAG_SERVER_VERSION_MAX);
		HANDLE(VALUE_TAG_SERVER_ADDRESS);
		HANDLE(VALUE_TAG_SERVER_CERT_FILE);
		HANDLE(VALUE_TAG_SERVER_CERT_KEY_FILE);
		HANDLE(VALUE_TAG_SERVER_FUNCTION);
		HANDLE(VALUE_TAG_CONTEXT);
		HANDLE(VALUE_TAG_CONTEXT_ID);	
		HANDLE(VALUE_TAG_CONTEXT_TAG);
		HANDLE(VALUE_TAG_CONTEXT_COMMENT);
		HANDLE(VALUE_TAG_CONTEXT_PURPOSE);
		HANDLE(VALUE_TAG_CONTEXT_AUDIT);
		HANDLE(VALUE_TAG_MIDDLEBOX);
		HANDLE(VALUE_TAG_MIDDLEBOX_TAG);
		HANDLE(VALUE_TAG_MIDDLEBOX_ADDRESS);
		HANDLE(VALUE_TAG_MIDDLEBOX_CERT_FILE);
		HANDLE(VALUE_TAG_MIDDLEBOX_CERT_KEY_FILE);
		HANDLE(VALUE_TAG_MIDDLEBOX_TRANSPARENT);
		HANDLE(VALUE_TAG_MIDDLEBOX_DISCOVERED);
		HANDLE(VALUE_TAG_MIDDLEBOX_FORBIDDEN);
		HANDLE(VALUE_TAG_MIDDLEBOX_CONTEXT);
		HANDLE(VALUE_TAG_MIDDLEBOX_CONTEXT_WHICH_IDS);
		HANDLE(VALUE_TAG_MIDDLEBOX_CONTEXT_WHICH_TAGS);
		HANDLE(VALUE_TAG_MIDDLEBOX_CONTEXT_ACCESS);
		HANDLE(VALUE_TAG_MIDDLEBOX_FUNCTION_TO_CLIENT);
		HANDLE(VALUE_TAG_MIDDLEBOX_FUNCTION_TO_SERVER);
	case NUM_VALUE_TAGS:
		return ("<internal error>");
		break;
	}

#undef HANDLE
#undef TOSTR
}
#endif /* TRACE_ENABLED */
