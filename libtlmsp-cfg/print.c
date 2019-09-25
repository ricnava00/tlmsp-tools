/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#ifdef __FreeBSD__
#define _WITH_DPRINTF
#endif

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#include "format.h"
#include "libtlmsp-cfg.h"
#include "print.h"


#define INDENT_INCR	2

static void print_activity_match(int fd, unsigned int indent,
                                     const struct tlmsp_cfg_match *cfg);
static void print_activity_action(int fd, unsigned int indent,
                                      const struct tlmsp_cfg_action *cfg);
static void print_payload(int fd, unsigned int indent,
                          const struct tlmsp_cfg_payload *cfg);
static void print_alert(int fd, unsigned int indent,
                        const struct tlmsp_cfg_alert *cfg);
static void print_middlebox_context(int fd, unsigned int indent,
                                    const struct tlmsp_cfg_middlebox_context *cfg);
static void print_boolean(int fd, bool value);
static void print_boolean_key(int fd, unsigned int indent, const char *key,
                              bool value);
static void print_double(int fd, double value, unsigned int precision);
static void print_double_key(int fd, unsigned int indent, const char *key,
                             double value, unsigned int precision);
static void print_enum(int fd, enum value_tag tag, int64_t value);
static void print_enum_key(int fd, unsigned int indent, const char *key,
                           enum value_tag tag, int64_t value);
static void print_int_key(int fd, unsigned int indent, const char *key,
                          int64_t value);
static void print_context_ptr_array(int fd, struct tlmsp_cfg_context **a,
                                    unsigned int size);
static void print_context_ptr_array_key(int fd, unsigned int indent,
                                        const char *key,
                                        struct tlmsp_cfg_context **a,
                                        unsigned int size);
static void print_string_key(int fd, unsigned int indent, const char *key,
                             const char *value);
static void print_version(int fd, unsigned int version);
static void print_version_key(int fd, unsigned int indent, const char *key,
                              unsigned int value);
static void print_buf(int fd, const struct tlmsp_cfg_buf *buf);
static void print_buf_key(int fd, unsigned int indent, const char *key,
                          const struct tlmsp_cfg_buf *buf);
static void print_template(int fd, const struct tlmsp_cfg_template *template);
static void print_template_key(int fd, unsigned int indent, const char *key,
                               const struct tlmsp_cfg_template *template);


void
print_activity(int fd, unsigned int indent, const struct tlmsp_cfg_activity *cfg)
{
	unsigned int i;

	indent_print(fd, indent,                   "activity {\n");
	print_string_key(fd, indent + 1,             "tag", cfg->tag);
	print_boolean_key(fd, indent + 1,            "present", cfg->present);
	print_activity_match(fd, indent + 1, &cfg->match);
	for (i = 0; i < cfg->num_actions; i++)
		print_activity_action(fd, indent + 1, &cfg->actions[i]);
	indent_print(fd, indent,                   "}\n");
}

static void
print_activity_match(int fd, unsigned int indent, const struct tlmsp_cfg_match *cfg)
{
	indent_print(fd, indent,                    "match {\n");
	print_context_ptr_array_key(fd, indent + 1,   "which", cfg->contexts, cfg->num_contexts);
	if (cfg->initial)
		print_int_key(fd, indent + 1,         "at", 0);
	else if (cfg->at != 0.0)
		print_int_key(fd, indent + 1,         "at", cfg->at * 1000);
	if (cfg->every > 0.0)
		print_int_key(fd, indent + 1,         "every", cfg->every * 1000);
	switch (cfg->container.type) {
	case TLMSP_CFG_MATCH_CONTAINER_NONE:
		/* nothing */
		break;
	case TLMSP_CFG_MATCH_CONTAINER_N:
		print_int_key(fd, indent + 1,         "container", cfg->container.param.n);
		break;
	case TLMSP_CFG_MATCH_CONTAINER_PROBABILITY:
		print_double_key(fd, indent + 1,      "container", cfg->container.param.p, 4);
		break;
	case TLMSP_CFG_MATCH_CONTAINER_ALL:
		print_string_key(fd, indent + 1,      "container", "*");
		break;
	}
	switch (cfg->pattern.type) {
	case TLMSP_CFG_MATCH_PATTERN_NONE:
		/* nothing */
		break;
	case TLMSP_CFG_MATCH_PATTERN_DATA:
		print_buf_key(fd, indent + 1,         "data", &cfg->pattern.param.data);
		break;
	case TLMSP_CFG_MATCH_PATTERN_FILE:
		print_string_key(fd, indent + 1,      "file", cfg->pattern.param.s);
		break;
	case TLMSP_CFG_MATCH_PATTERN_REGEX:
		print_string_key(fd, indent + 1,      "regex", cfg->pattern.param.s);
		break;
	}
	indent_print(fd, indent,                    "}\n");
}

static void
print_activity_action(int fd, unsigned int indent, const struct tlmsp_cfg_action *cfg)
{

	indent_print(fd, indent,              "action {\n");
#ifdef notyet
	if (cfg->fault != TLMSP_CFG_ACTION_FAULT_NONE)
		print_enum_key(fd, indent + 1,  "fault",
		    VALUE_TAG_ACTIVITY_ACTION_FAULT, cfg->fault);
#endif
	print_payload(fd, indent + 1, &cfg->send);
	print_alert(fd, indent + 1, &cfg->alert);
	indent_print(fd, indent,              "}\n");
}

static void
print_payload(int fd, unsigned int indent, const struct tlmsp_cfg_payload *cfg)
{

	if (cfg->type == TLMSP_CFG_PAYLOAD_NONE)
		return;

	indent_print(fd, indent,                  "%s {\n",
	    cfg->reply ? "reply" : "send");
	print_int_key(fd, indent + 1,               "context", cfg->context->id);
	switch (cfg->type) {
	case TLMSP_CFG_PAYLOAD_NONE:
		/* nothing */
		break;
	case TLMSP_CFG_PAYLOAD_DATA:
		print_buf_key(fd, indent + 1,    "data", &cfg->param.data);
		break;
	case TLMSP_CFG_PAYLOAD_FILE:
		print_string_key(fd, indent + 1,    "file", cfg->param.file);
		break;
	case TLMSP_CFG_PAYLOAD_HANDLER:
		print_string_key(fd, indent + 1,    "handler", cfg->param.cmd);
		break;
	case TLMSP_CFG_PAYLOAD_TEMPLATE:
		print_template_key(fd, indent + 1,  "template", &cfg->param.template);
		break;
	}
	indent_print(fd, indent,        "}\n");
}

static void
print_alert(int fd, unsigned int indent, const struct tlmsp_cfg_alert *cfg)
{

	if (cfg->level == TLMSP_CFG_ACTION_ALERT_LEVEL_NONE)
		return;

	indent_print(fd, indent,                  "alert {\n");
	print_int_key(fd, indent + 1,               "context", cfg->context->id);
	print_enum_key(fd, indent + 1,              "level",
	    VALUE_TAG_ACTIVITY_ACTION_ALERT_LEVEL, cfg->level);
	print_enum_key(fd, indent + 1,              "description",
	    VALUE_TAG_ACTIVITY_ACTION_ALERT_DESC_ENUM, cfg->description);
	indent_print(fd, indent,        "}\n");
}

void
print_context(int fd, unsigned int indent, const struct tlmsp_cfg_context *cfg)
{

	indent_print(fd, indent,          "context {\n");
	print_int_key(fd, indent + 1,       "id", cfg->id);
	print_string_key(fd, indent + 1,    "tag", cfg->tag);
	print_string_key(fd, indent + 1,    "comment", cfg->comment);
	print_string_key(fd, indent + 1,    "purpose", cfg->purpose);
	print_boolean_key(fd, indent + 1,   "audit", cfg->audit);
	indent_print(fd, indent,          "}\n");	
}

void
print_client(int fd, unsigned int indent, const struct tlmsp_cfg_client *cfg)
{

	indent_print(fd, indent,       "client {\n");
	indent_print(fd, indent + 1,     "version {\n");
	print_version_key(fd, indent + 2,  "min", cfg->version_min);
	print_version_key(fd, indent + 2,  "max", cfg->version_max);
	indent_print(fd, indent + 1,     "}\n");
	print_string_key(fd, indent + 1, "address", cfg->address);
	indent_print(fd, indent,       "}\n");
}

void
print_server(int fd, unsigned int indent, const struct tlmsp_cfg_server *cfg)
{

	indent_print(fd, indent,       "server {\n");
	indent_print(fd, indent + 1,     "version {\n");
	print_version_key(fd, indent + 2,  "min", cfg->version_min);
	print_version_key(fd, indent + 2,  "max", cfg->version_max);
	indent_print(fd, indent + 1,     "}\n");
	print_string_key(fd, indent + 1, "address", cfg->address);
	indent_print(fd, indent,       "}\n");
}

void
print_middlebox(int fd, unsigned int indent,
    const struct tlmsp_cfg_middlebox *cfg)
{
	unsigned int i;

	indent_print(fd, indent,        "middlebox {\n");
	print_string_key(fd, indent + 1,  "tag", cfg->tag);
	print_string_key(fd, indent + 1,  "address", cfg->address);
	print_boolean_key(fd, indent + 1, "transparent", cfg->transparent);
	print_boolean_key(fd, indent + 1, "discovered", cfg->discovered);
	print_boolean_key(fd, indent + 1, "forbidden", cfg->forbidden);
	for (i = 0; i < cfg->num_contexts; i++)
		print_middlebox_context(fd, indent + 1, &cfg->contexts[i]);
	indent_print(fd, indent,        "}\n");	
}

static void
print_middlebox_context(int fd, unsigned int indent,
    const struct tlmsp_cfg_middlebox_context *cfg)
{

	indent_print(fd, indent,     "context {\n");
	print_int_key(fd, indent + 1,  "id", cfg->base->id);
	print_enum_key(fd, indent + 1, "access",
	    VALUE_TAG_MIDDLEBOX_CONTEXT_ACCESS, cfg->access);
	indent_print(fd, indent,     "}\n");	
}

int
indent_print(int fd, unsigned int indent, const char *format, ...)
{
	va_list ap;
	int result;
	
	va_start(ap, format);
	dprintf(fd, "%*s", indent * INDENT_INCR, "");
	result = vdprintf(fd, format, ap);
	va_end(ap);

	return (result);
}

static void
print_boolean(int fd, bool value)
{

	dprintf(fd, "%s", value ? "yes" : "no");
}

static void
print_boolean_key(int fd, unsigned int indent, const char *key, bool value)
{

	indent_print(fd, indent, "%s = ", key);
	print_boolean(fd, value);
	dprintf(fd, "\n");
}

static void
print_double(int fd, double value, unsigned int precision)
{

	dprintf(fd, "%.*f", precision, value);
}

static void
print_double_key(int fd, unsigned int indent, const char *key, double value,
	unsigned int precision)
{

	indent_print(fd, indent, "%s = ", key);
	print_double(fd, value, precision);
	dprintf(fd, "\n");
}

static void
print_context_ptr_array(int fd, struct tlmsp_cfg_context **a, unsigned int size)
{
       unsigned int i;

       if (size == 0)
               return;

       if (size == 1)
               dprintf(fd, "%u", a[0]->id);
       else {
               dprintf(fd, "[ ");
               for (i = 0; i < size; i++)
                       dprintf(fd, "%s%u", (i > 0) ? ", " : "", a[i]->id);
               dprintf(fd, " ]");
       }
}

static void
print_context_ptr_array_key(int fd, unsigned int indent, const char *key,
    struct tlmsp_cfg_context **a, unsigned int size)
{
       if (size == 0)
               return;

       indent_print(fd, indent, "%s = ", key);
       print_context_ptr_array(fd, a, size);
       dprintf(fd, "\n");
}

static void
print_enum(int fd, enum value_tag tag, int64_t value)
{
	unsigned int set_size;
	unsigned int i;
	const union limit_set *result;
	
	set_size =
	    fmt_find_value_type_limit_set_by_tag(&cfg_format, tag, TYPE_ENUM,
		&result);

	if (set_size != 0)
		for (i = 0; i < set_size; i++)
			if (result->ep[i].e == value) {
				dprintf(fd, "%s", result->ep[i].s);
				return;
			}

	dprintf(fd, "<unknown> (%" PRId64 ")", value);
}

static void
print_enum_key(int fd, unsigned int indent, const char *key, enum value_tag tag,
    int64_t value)
{

	indent_print(fd, indent, "%s = ", key);
	print_enum(fd, tag, value);
	dprintf(fd, "\n");
}

static void
print_int_key(int fd, unsigned int indent, const char *key, int64_t value)
{

	indent_print(fd, indent, "%s = %" PRId64 "\n", key, value);
}

static void
print_string_key(int fd, unsigned int indent, const char *key, const char *value)
{

	if (value[0] != '\0')
		indent_print(fd, indent, "%s = %s\n", key, value);
}

static void
print_version(int fd, unsigned int version)
{

	dprintf(fd, "v%u.%u", TLMSP_CFG_PROTO_VERSION_MAJOR(version),
	    TLMSP_CFG_PROTO_VERSION_MINOR(version));
}

static void
print_version_key(int fd, unsigned int indent, const char *key,
    unsigned int value)
{

	indent_print(fd, indent, "%s = ", key);
	print_version(fd, value);
	dprintf(fd, "\n");
}

static void
print_buf(int fd, const struct tlmsp_cfg_buf *buf)
{
	size_t i;

	for (i = 0; i < buf->len; i++)
		if (buf->p[i] == '%')
			dprintf(fd, "%%25");
		else if (isprint(buf->p[i]))
			dprintf(fd, "%c", buf->p[i]);
		else
			dprintf(fd, "%%%02x", buf->p[i]);
}

static void
print_buf_key(int fd, unsigned int indent, const char *key,
    const struct tlmsp_cfg_buf *buf)
{

	indent_print(fd, indent, "%s = ", key);
	print_buf(fd, buf);
	dprintf(fd, "\n");
}

static void
print_template(int fd, const struct tlmsp_cfg_template *template)
{
	size_t i;

	for (i = 0; i < template->num_segments; i++) {
		print_buf(fd, &template->segments[i].data);
		if (template->segments[i].match_ref != TLMSP_CFG_MATCH_REF_END)
			dprintf(fd, "${%u}", template->segments[i].match_ref);
	}
}

static void
print_template_key(int fd, unsigned int indent, const char *key,
    const struct tlmsp_cfg_template *template)
{

	indent_print(fd, indent, "%s = ", key);
	print_template(fd, template);
	dprintf(fd, "\n");
}

