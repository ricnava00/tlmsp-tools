/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _FORMAT_H_
#define _FORMAT_H_

#include <ucl.h>

#include "libtlmsp-cfg.h"


#define PROTOCOL_VERSION_1_0	TLMSP_CFG_PROTO_VERSION(1, 0)

#define PROTOCOL_VERSION_MIN	PROTOCOL_VERSION_1_0
#define PROTOCOL_VERSION_MAX	PROTOCOL_VERSION_1_0
/* Comma separated list of TLMSP protocol versions (no parens) */
#define PROTOCOL_VERSIONS	PROTOCOL_VERSION_1_0 /*, PROTOCOL_VERSION_1_1 */	

/*
 * Key values can be constrained by limits
 */
struct value_limit {
	enum {
		NONE,
		RANGE,
		SET
	} type;
	union {
		bool b;
		int i;
		int64_t i64;
		double d;
	} range_min;
	union {
		bool b;
		int i;
		int64_t i64;
		double d;
	} range_max;
	unsigned int num_set_members;
	union limit_set {
		/*
		 * For bool, use a RANGE limit to restrict to a single
		 * value.
		 */
		const int *i;
		const int64_t *i64;
		const double *d;
		const char * const *s;
		const struct enum_pair {
			const char *s;
			unsigned int e;
		} *ep;
	} set_of;
};

struct value_type;

/* Describe a key that that may have more than one value type */
struct key {
	const char *key;
	unsigned int num_types;
	const struct value_type *types;
};

/* Tag values associated with specific key values in the format */
enum value_tag {
	VALUE_TAG_NO_TAG,
	VALUE_TAG_TOP_OBJECT,
	VALUE_TAG_ACTIVITY,
	VALUE_TAG_ACTIVITY_TAG,
	VALUE_TAG_ACTIVITY_MATCH,
	VALUE_TAG_ACTIVITY_MATCH_WHICH_IDS,
	VALUE_TAG_ACTIVITY_MATCH_WHICH_TAGS,
	VALUE_TAG_ACTIVITY_MATCH_AT,
	VALUE_TAG_ACTIVITY_MATCH_EVERY,
	VALUE_TAG_ACTIVITY_MATCH_CONTAINER_PROBABILITY,
	VALUE_TAG_ACTIVITY_MATCH_CONTAINER_N,
	VALUE_TAG_ACTIVITY_MATCH_CONTAINER_ALL,
	VALUE_TAG_ACTIVITY_MATCH_DATA,
	VALUE_TAG_ACTIVITY_MATCH_FILE,
	VALUE_TAG_ACTIVITY_MATCH_REGEX,
	VALUE_TAG_ACTIVITY_MATCH_FORWARD,
	VALUE_TAG_ACTIVITY_ACTION,
	VALUE_TAG_ACTIVITY_ACTION_FAULT,
	VALUE_TAG_ACTIVITY_ACTION_RENEGOTIATE,
	VALUE_TAG_ACTIVITY_ACTION_SHUTDOWN,
	VALUE_TAG_ACTIVITY_ACTION_LOG,
	VALUE_TAG_ACTIVITY_ACTION_LOG_FILE,
	VALUE_TAG_ACTIVITY_ACTION_LOG_HANDLER,
	VALUE_TAG_ACTIVITY_ACTION_SEND,
	VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_ID,
	VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_TAG,
	VALUE_TAG_ACTIVITY_ACTION_SEND_DATA,
	VALUE_TAG_ACTIVITY_ACTION_SEND_FILE,
	VALUE_TAG_ACTIVITY_ACTION_SEND_HANDLER,
	VALUE_TAG_ACTIVITY_ACTION_SEND_TEMPLATE,
	VALUE_TAG_ACTIVITY_ACTION_REPLY,
	VALUE_TAG_ACTIVITY_ACTION_REPLY_CONTEXT_ID,
	VALUE_TAG_ACTIVITY_ACTION_REPLY_CONTEXT_TAG,
	VALUE_TAG_ACTIVITY_ACTION_REPLY_DATA,
	VALUE_TAG_ACTIVITY_ACTION_REPLY_FILE,
	VALUE_TAG_ACTIVITY_ACTION_REPLY_HANDLER,
	VALUE_TAG_ACTIVITY_ACTION_REPLY_TEMPLATE,
	VALUE_TAG_ACTIVITY_ACTION_ALERT,
	VALUE_TAG_ACTIVITY_ACTION_ALERT_CONTEXT_ID,
	VALUE_TAG_ACTIVITY_ACTION_ALERT_CONTEXT_TAG,
	VALUE_TAG_ACTIVITY_ACTION_ALERT_LEVEL,
	VALUE_TAG_ACTIVITY_ACTION_ALERT_DESC_ENUM,
	VALUE_TAG_ACTIVITY_ACTION_ALERT_DESC_INT,
	VALUE_TAG_ACTIVITY_PRESENT,
	VALUE_TAG_CLIENT,
	VALUE_TAG_CLIENT_VERSION_SINGLE,
	VALUE_TAG_CLIENT_VERSION_RANGE,
	VALUE_TAG_CLIENT_VERSION_MIN,
	VALUE_TAG_CLIENT_VERSION_MAX,
	VALUE_TAG_CLIENT_ADDRESS,
	VALUE_TAG_CLIENT_FUNCTION,
	VALUE_TAG_SERVER,
	VALUE_TAG_SERVER_VERSION_SINGLE,
	VALUE_TAG_SERVER_VERSION_RANGE,
	VALUE_TAG_SERVER_VERSION_MIN,
	VALUE_TAG_SERVER_VERSION_MAX,
	VALUE_TAG_SERVER_ADDRESS,
	VALUE_TAG_SERVER_CERT_FILE,
	VALUE_TAG_SERVER_CERT_KEY_FILE,
	VALUE_TAG_SERVER_FUNCTION,
	VALUE_TAG_CONTEXT,
	VALUE_TAG_CONTEXT_ID,	
	VALUE_TAG_CONTEXT_TAG,
	VALUE_TAG_CONTEXT_COMMENT,
	VALUE_TAG_CONTEXT_PURPOSE,
	VALUE_TAG_CONTEXT_AUDIT,
	VALUE_TAG_MIDDLEBOX,
	VALUE_TAG_MIDDLEBOX_TAG,
	VALUE_TAG_MIDDLEBOX_ADDRESS,
	VALUE_TAG_MIDDLEBOX_CERT_FILE,
	VALUE_TAG_MIDDLEBOX_CERT_KEY_FILE,
	VALUE_TAG_MIDDLEBOX_TRANSPARENT,
	VALUE_TAG_MIDDLEBOX_DISCOVERED,
	VALUE_TAG_MIDDLEBOX_FORBIDDEN,
	VALUE_TAG_MIDDLEBOX_CONTEXT,
	VALUE_TAG_MIDDLEBOX_CONTEXT_WHICH_IDS,
	VALUE_TAG_MIDDLEBOX_CONTEXT_WHICH_TAGS,
	VALUE_TAG_MIDDLEBOX_CONTEXT_ACCESS,
	VALUE_TAG_MIDDLEBOX_FUNCTION_TO_CLIENT,
	VALUE_TAG_MIDDLEBOX_FUNCTION_TO_SERVER,
	NUM_VALUE_TAGS /* always last */
};

/* Describe a value type that may be an aggregate of keys */
struct value_type {
	unsigned int type;
	enum value_tag tag;
	struct value_limit limit;
	unsigned int num_subkeys;
	const struct key *subkeys;
};

struct value {
	unsigned int sid;	/* scalar type ID */
	union {
		bool b;
		int i;
		int64_t i64;
		double d;
		const char *s;
		struct enum_pair ep;
	} v;
#define type_int	v.i64
#define type_float	v.d
#define type_string	v.s
#define type_boolean	v.b
#define type_time	v.d
#define type_version	v.i
#define type_enum	v.ep
};

/*
 * Key value type IDs
 *
 * +-+--------+--------+--------+
 * |A|   UID  |  CID   |   UCL  |
 * +-+--------+--------+--------+
 *
 *   A = array bit
 * UID = unique ID (8 bits)
 * CID = corresponding C type ID (8 bits)
 * UCL = corresponding UCL type ID (8 bits)
 *
 */
#define _ARRAY_BIT			0x1000000
#define _ARRAY_OF(t)			(_ARRAY_BIT | (t))
#define _MAKE_TYPE(uid, cid, ucl)	(((uid) << 16) | ((cid) << 8) | (ucl))

#define IS_ARRAY(t)	((t) & _ARRAY_BIT)
#define SCALAR_TYPE(t)	((t) & ~_ARRAY_BIT)
#define C_TYPE(t)	(((t) >> 8) & 0xff)
#define UCL_TYPE(t)	((t) & 0xff)

#define C_COMPOSITE	0	
#define C_INT		1
#define C_INT64		2
#define C_DOUBLE	3
#define C_STRING	4
#define C_BOOL		5
#define C_ENUM_PAIR	6

#define TYPE_OBJECT		_MAKE_TYPE(0, C_COMPOSITE, UCL_OBJECT)
#define TYPE_OBJECT_ARRAY	_ARRAY_OF(TYPE_OBJECT)
#define TYPE_INT		_MAKE_TYPE(1, C_INT64, UCL_INT)
#define TYPE_INT_ARRAY		_ARRAY_OF(TYPE_INT)
#define TYPE_FLOAT		_MAKE_TYPE(2, C_DOUBLE, UCL_FLOAT)
#define TYPE_FLOAT_ARRAY	_ARRAY_OF(TYPE_FLOAT)
#define TYPE_STRING		_MAKE_TYPE(3, C_STRING, UCL_STRING)
#define TYPE_STRING_ARRAY	_ARRAY_OF(TYPE_STRING)
#define TYPE_BOOLEAN		_MAKE_TYPE(4, C_BOOL, UCL_BOOLEAN)
#define TYPE_BOOLEAN_ARRAY	_ARRAY_OF(TYPE_BOOLEAN)
#define TYPE_TIME		_MAKE_TYPE(5, C_DOUBLE, UCL_TIME)
#define TYPE_TIME_ARRAY		_ARRAY_OF(TYPE_TIME)
#define TYPE_VERSION		_MAKE_TYPE(6, C_INT, UCL_STRING)
#define TYPE_VERSION_ARRAY	_ARRAY_OF(TYPE_VERSION)
#define TYPE_ENUM		_MAKE_TYPE(7, C_ENUM_PAIR, UCL_STRING)
#define TYPE_ENUM_ARRAY		_ARRAY_OF(TYPE_ENUM)

/*
 * Configuration file format definition
 */
extern const struct value_type cfg_format;

const struct key *fmt_obj_find_key(const struct value_type *obj,
                                   const char *key, char *errbuf, size_t errbuflen);
const struct value_type *fmt_find_value_type_by_ucl_type(const struct key *key,
                                                         ucl_type_t ucl_type,
                                                         bool container_is_array,
                                                         char *errbuf,
                                                         size_t errbuflen);
bool fmt_get_value(const struct value_type *value_fmt, const ucl_object_t *obj,
                   struct value *v);
unsigned int fmt_find_value_type_limit_set_by_tag(const struct value_type *cfg,
                                                  enum value_tag tag,
                                                  unsigned int scalar_type,
                                                  const union limit_set **result);
const char *fmt_type_name(unsigned int type);
const char *fmt_ucl_type_name(ucl_type_t type);
#ifdef TRACE_ENABLED
const char *fmt_value_tag_name(enum value_tag tag);
#endif

#endif /* _FORMAT_H_ */
