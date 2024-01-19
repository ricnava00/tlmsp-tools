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
#include <string.h>
#include <ucl.h>

#include "format.h"
#include "libtlmsp-cfg.h"
#include "libtlmsp-util.h"
#include "parse.h"
#include "trace.h"


#define AUTO_ARRAY_GROWTH_SIZE	16

#define MS_TO_S(ms)	((double)(ms) / 1000.0)

/* Assumes a struct iteration_state * named 'state' is in scope */
#define ERRBUF(...)							\
	do {								\
		TRACE(__VA_ARGS__);					\
		TRACE_RAW("\n");					\
		if (state->errbuf != NULL)				\
			snprintf(state->errbuf, state->errbuflen, __VA_ARGS__); \
	} while(0)


struct auto_array_state {
	void **array_ptr;
	unsigned int current_size;	/* elements */
	unsigned int next_index;
	unsigned int growth_size;	/* elements */
	size_t element_size;		/* bytes */
};
#define auto_array_cur(s)	((s)->next_index - 1)
#define auto_array_cur_p(s, t)	((t *)(*(s)->array_ptr) + auto_array_cur(s))
#define auto_array_elements(s)	((s)->next_index)

/* direct-indexed by context ID */
typedef bool context_id_array_t[TLMSP_UTIL_CONTEXT_ID_LUT_SIZE]; 	
/* direct-indexed by context ID */
typedef struct tlmsp_cfg_context *context_ptr_array_t[TLMSP_UTIL_CONTEXT_ID_LUT_SIZE];
/* direct-indexed by context ID */
typedef enum tlmsp_cfg_context_access context_access_array_t[TLMSP_UTIL_CONTEXT_ID_LUT_SIZE]; 	

/* for building a list of context pointers in a config object */
struct context_list {
	struct iteration_state *state;
	/* for managing the context pointer array in the config object */
	struct auto_array_state ptr_array;
	/* for managing the count of contexst pointers in the config object */
	unsigned int *count;
	/* for tracking which context IDs have already been added */ 
	context_id_array_t ids;
};

/* for building a list of activity pointers in a config object */
struct activity_list {
	struct iteration_state *state;
	/* for managing the context pointer array in the config object */
	struct auto_array_state ptr_array;
	/* for managing the count of contexst pointers in the config object */
	unsigned int *count;
};

/* for tracking generic per-object state */
struct object {
	bool has_tag[NUM_VALUE_TAGS];
};

struct iteration_state {
	const struct value_type *fmt;
	struct tlmsp_cfg *cfg;
	struct tlmsp_cfg_context *cur_context;
	struct tlmsp_cfg_activity *cur_activity;
	struct tlmsp_cfg_action *cur_action;
	struct tlmsp_cfg_middlebox *cur_middlebox;
	struct tlmsp_cfg_middlebox_context *cur_middlebox_context;
	struct tlmsp_cfg_middlebox_context *first_middlebox_context;
#define OBJECT_STACK_MAX_DEPTH	8
	struct object object_stack[OBJECT_STACK_MAX_DEPTH];
	int object_stack_level;
	struct object *cur_obj;
	struct auto_array_state context_array;
	struct auto_array_state activity_array;
	struct auto_array_state activity_action_array;
	struct activity_list activity_list_to_client;
	struct activity_list activity_list_to_server;
	struct context_list match_context_list;
	struct auto_array_state middlebox_array;
	struct auto_array_state middlebox_context_array;
	context_id_array_t middlebox_context_ids;
	context_id_array_t middlebox_context_replicate_ids;
	context_id_array_t context_id_in_use;
	bool context_ptrs_initialized;
	context_ptr_array_t context_ptrs;
	char *errbuf;
	size_t errbuflen;
	char tmpbuf[512];
};

/* assumes struct iteration_state *state is in scope */
#define HAS_VALUE_TAG_FULL(tag)	(state->cur_obj->has_tag[tag])
#define HAS_VALUE_TAG(t)	HAS_VALUE_TAG_FULL(VALUE_TAG_ ## t)
#define PARENT_HAS_VALUE_TAG(t) \
	((state->cur_obj->object_stack_level > 0) && (state->cur_obj - 1)->has_tag[VALUE_TAG_ ## t])

enum value_event {
	VALUE_EVENT_START,
	VALUE_EVENT_FINISH
};

static bool push_object(struct iteration_state *state);
static void pop_object(struct iteration_state *state);
static bool process_container(struct iteration_state *state,
                              const struct value_type *container_value_fmt,
                              const ucl_object_t *container_obj);
static bool process_value(struct iteration_state *state,
                          const struct value_type *value_fmt,
                          const ucl_object_t *value_obj);
static bool handle_value_tag_start(struct iteration_state *state,
                                   enum value_tag tag, struct value *v);
static bool handle_value_tag_start_do(struct iteration_state *state,
                                      enum value_tag tag, struct value *v);
static bool handle_value_tag_finish(struct iteration_state *state,
                                    enum value_tag tag, struct value *v);
static void auto_array_state_init(struct auto_array_state *s, void **a,
                                  size_t element_size);
static bool auto_array_one_more(struct auto_array_state *s);
static bool check_one_tag(struct iteration_state *state, enum value_tag tag,
                          const char *thing, const char *per);
static void initialize_cfg_client(struct tlmsp_cfg_client *cfg);
static void initialize_cfg_server(struct tlmsp_cfg_server *cfg);
static void initialize_cfg_context(struct tlmsp_cfg_context *cfg);
static unsigned int assign_context_id(struct iteration_state *state);
static void initialize_context_ptr_lut(struct iteration_state *state,
                                        struct tlmsp_cfg *cfg);
static void initialize_context_list(struct iteration_state *state,
                                    struct context_list *cl,
                                    struct tlmsp_cfg_context ***contexts,
                                    unsigned int *count);
static bool add_id_to_context_list(struct context_list *cl, unsigned int id);
static bool add_tag_to_context_list(struct context_list *cl, const char *tag);
static struct tlmsp_cfg_context *get_context_by_tag(struct tlmsp_cfg *cfg,
                                                    const char *tag, bool multi_ok);
static void initialize_cfg_activity(struct tlmsp_cfg_activity *cfg);
static void initialize_activity_list(struct iteration_state *state,
                                    struct activity_list *cl,
                                    struct tlmsp_cfg_activity ***activities,
                                    unsigned int *count);
static bool add_tag_to_activity_list(struct activity_list *cl, const char *tag);
static struct tlmsp_cfg_activity *get_activity_by_tag(struct tlmsp_cfg *cfg,
                                                      const char *tag);
static void initialize_cfg_payload(struct tlmsp_cfg_payload *cfg);
static bool check_log_payload(struct iteration_state *state,
                              struct tlmsp_cfg_payload *payload, const char *name);
static bool check_cfg_payload(struct iteration_state *state,
                              struct tlmsp_cfg_payload *payload, const char *name);
static bool set_cfg_payload_context_by_id(struct iteration_state *state,
                                          struct tlmsp_cfg_payload *cfg,  unsigned int id,
                                          const char *name);
static bool set_cfg_payload_context_by_tag(struct iteration_state *state,
                                           struct tlmsp_cfg_payload *cfg, const char *tag,
                                           const char *name);
static bool set_cfg_payload_data(struct iteration_state *state,
                                 struct tlmsp_cfg_payload *cfg,
                                 const char *data_string);
static bool set_cfg_payload_file(struct iteration_state *state,
                                 struct tlmsp_cfg_payload *cfg,
                                 const char *filename);
static bool set_cfg_payload_handler(struct iteration_state *state,
                                    struct tlmsp_cfg_payload *cfg,
                                    const char *cmd);
static bool set_cfg_payload_template(struct iteration_state *state,
                                     struct tlmsp_cfg_payload *cfg,
                                     const char *template);
static bool find_first_match_reference(const uint8_t *buf, size_t len,
                                       size_t *ref_start, size_t *ref_end,
                                       unsigned int *ref_value);
static bool set_cfg_buf_from_encoded_string(struct iteration_state *state,
                                            struct tlmsp_cfg_buf *buf,
                                            const char *data_string);
static bool percent_encoded_string_to_buf(const char *str, uint8_t **buf,
                                          size_t *len);
static void initialize_cfg_middlebox(struct tlmsp_cfg_middlebox *cfg);
static bool add_middlebox_context(struct iteration_state *state);
static void initialize_cfg_middlebox_context(struct tlmsp_cfg_middlebox_context *cfg);
static bool check_cfg_middlebox_activity(struct iteration_state *state,
                                         struct tlmsp_cfg_middlebox *cfg,
                                         struct tlmsp_cfg_activity *activity);
static void copy_cfg_middlebox_context(struct tlmsp_cfg_middlebox_context *dest,
                                       struct tlmsp_cfg_middlebox_context *src);
static bool add_context_ptr_to_array(struct auto_array_state *s,
                                     struct tlmsp_cfg_context *cfg);
static bool add_activity_ptr_to_array(struct auto_array_state *s,
                                      struct tlmsp_cfg_activity *cfg);

#ifdef TRACE_ENABLED
static const char *value_event_name(enum value_event event);
#endif


struct tlmsp_cfg *
parse_string_or_file(const char *strarg, bool isfile, char *errbuf, size_t errbuflen)
{
	int parser_flags;
	struct ucl_parser *parser;
	ucl_object_t *obj;
	struct iteration_state *state;
	struct tlmsp_cfg *cfg;
	bool parse_success;

	if (errbuf != NULL)
		snprintf(errbuf, errbuflen, "no further detail");

	TRACE("starting config parse\n");

	state = NULL;
	parser = NULL;
	cfg = NULL;
	obj = NULL;

	state = calloc(1, sizeof(*state));
	if (state == NULL) {
		TRACE("failed to allocate iteration state\n");
		if (errbuf != NULL)
			snprintf(errbuf, errbuflen, "failed to allocate iteration state");
		goto out;
	}
	state->errbuf = errbuf;
	state->errbuflen = errbuflen;
	
	/*
	 * Configure the parser to convert all keys to lowercase and to
	 * convert multiple instances of the same key into an explicit
	 * array.
	 */
	parser_flags =
	    UCL_PARSER_KEY_LOWERCASE |
	    UCL_PARSER_NO_IMPLICIT_ARRAYS;
	parser = ucl_parser_new(parser_flags);
	if (parser == NULL) {
		ERRBUF("parser creation failed");
		goto out;
	}

	if (isfile)
		parse_success = ucl_parser_add_file(parser, strarg);
	else
		parse_success = ucl_parser_add_string(parser, strarg, 0);

	if (!parse_success) {
		ERRBUF("ucl parse error: %s", ucl_parser_get_error(parser));
		goto out;
	}

	obj = ucl_parser_get_object(parser);
	if (obj == NULL) {
		ERRBUF("no top object");
		goto out;
	}

	state->fmt = &cfg_format;
	state->cfg = calloc(1, sizeof(struct tlmsp_cfg));
	if (state->cfg == NULL) {
		ERRBUF("failed to allocate base config");
		goto out;
	}

	state->object_stack_level = -1;

	if (handle_value_tag_start(state, VALUE_TAG_TOP_OBJECT, NULL) &&
	    push_object(state) &&
	    process_container(state, &cfg_format, obj) &&
	    handle_value_tag_finish(state, VALUE_TAG_TOP_OBJECT, NULL))
		cfg = state->cfg;
	else
		tlmsp_cfg_free(state->cfg);
	
 out:
	if (obj != NULL)
		ucl_object_unref(obj);
	if (parser != NULL)
		ucl_parser_free(parser);
	if (state != NULL)
		free(state);
	TRACE("config load %s\n", (cfg == NULL) ? "failed" : "succeeded\n");

	return (cfg);
}

void
free_string(const char *str)
{
	if (str[0] != '\0')
		free((void *)str);
}

static bool
push_object(struct iteration_state *state)
{

	if (state->object_stack_level == (OBJECT_STACK_MAX_DEPTH - 1)) {
		ERRBUF("object stack is full");
		return (false);
	}

	state->object_stack_level++;
	state->cur_obj = &state->object_stack[state->object_stack_level];
	memset(state->cur_obj->has_tag, 0, sizeof(state->cur_obj->has_tag));

	return (true);
}

static void
pop_object(struct iteration_state *state)
{

	state->object_stack_level--;
	state->cur_obj = &state->object_stack[state->object_stack_level];
}

static bool
process_container(struct iteration_state *state,
    const struct value_type *container_value_fmt, const ucl_object_t *container_obj)
{
	ucl_object_iter_t it;
	bool container_is_array;
	bool result;
	const ucl_object_t *cur;
	const struct key *key_fmt;
	const struct value_type *cur_fmt;
	
	it = ucl_object_iterate_new(container_obj);
	container_is_array = (ucl_object_type(container_obj) == UCL_ARRAY);
	result = false;

	/*
	 * If the container object is an array, the container value format
	 * will be that of the container of the array, and we use the key of
	 * the container object to retrieve the key format.  The key format
	 * will of course be the same for all iterated objects.
	 */
	if (container_is_array) {
		key_fmt = fmt_obj_find_key(container_value_fmt,
		    ucl_object_key(container_obj), state->errbuf, state->errbuflen);
		if (key_fmt == NULL)
			goto out;
	}
	
	while ((cur = ucl_object_iterate_safe(it, false)) != NULL) {
		if (!container_is_array) {
			/*
			 * If the container is not an array, check to see if the
			 * container format contains a key with this name.
			 */
			key_fmt = fmt_obj_find_key(container_value_fmt,
			    ucl_object_key(cur), state->errbuf, state->errbuflen);
			if (key_fmt == NULL)
				goto out;
		}

		/*
		 * Check if the key format has a value type corresponding to
		 * the current ucl object's type.
		 *
		 * Note that if the current ucl object is an array, this
		 * amounts to a check that the key format has at least one
		 * array value type.  If there are multiple array value
		 * types, it does not matter which one is returned as it
		 * will not be used below - the array will be processed in
		 * the context of the current container format.
		 */
		cur_fmt = fmt_find_value_type_by_ucl_type(key_fmt,
		    ucl_object_type(cur), container_is_array, state->errbuf,
		    state->errbuflen);
		if (cur_fmt == NULL)
			goto out;

		switch (ucl_object_type(cur)) {
		case UCL_OBJECT:
			if (!handle_value_tag_start(state, cur_fmt->tag, NULL))
				goto out;
			if (!push_object(state))
				goto out;
			if (!process_container(state, cur_fmt, cur))
				goto out;
			if (!handle_value_tag_finish(state, cur_fmt->tag, NULL))
				goto out;
			pop_object(state);
			break;
		case UCL_ARRAY:
			/*
			 * Arrays are processed in the context of their
			 * container's format.  For each array element, the
			 * key will be looked up again and the element type
			 * will have to match an array type in the key's
			 * format.  This is not as efficient as it could be,
			 * but it reduces code.
			 *
			 * Note that if a key format contains multiple array
			 * value types, an array consisting of a mixture of
			 * the corresponding scalar types will not be
			 * rejected by this processing.  It is up to the
			 * value handlers to perform such checking.
			 */
			if (!process_container(state, container_value_fmt, cur))
				goto out;
			break;
		default:
			if (!handle_value_tag_start(state, cur_fmt->tag, NULL))
				goto out;
			if (!process_value(state, cur_fmt, cur))
				goto out;
			break;
		}
	}

	result = true;

out:
	ucl_object_iterate_free(it);

	return (result);
}

static bool
process_value(struct iteration_state *state,
    const struct value_type *value_fmt, const ucl_object_t *value_obj)
{
	struct value v;

	if (!fmt_get_value(value_fmt, value_obj, &v))
		return (false);

	if (!handle_value_tag_finish(state, value_fmt->tag, &v))
		return (false);

	return (true);
}

static bool
handle_value_tag_start(struct iteration_state *state, enum value_tag tag,
    struct value *value)
{
	bool result;

	result = handle_value_tag_start_do(state, tag, value);
	if (tag != VALUE_TAG_TOP_OBJECT)
		state->cur_obj->has_tag[tag] = true;

	return (result);	
}

static bool
handle_value_tag_start_do(struct iteration_state *state, enum value_tag tag,
    struct value *value)
{
	struct tlmsp_cfg *cfg;
	
	TRACE("%s: %s\n", fmt_value_tag_name(tag), value_event_name(VALUE_EVENT_START));
	
	cfg = state->cfg;
	switch (tag) {
	case VALUE_TAG_NO_TAG:
		/* nothing to do */
		break;
	case VALUE_TAG_TOP_OBJECT:
		initialize_cfg_client(&cfg->client);
		initialize_cfg_server(&cfg->server);
		auto_array_state_init(&state->context_array,
		    (void **)&cfg->contexts, sizeof(*cfg->contexts));
		auto_array_state_init(&state->activity_array,
		    (void **)&cfg->activities, sizeof(*cfg->activities));
		auto_array_state_init(&state->middlebox_array,
		    (void **)&cfg->middleboxes, sizeof(*cfg->middleboxes));
		break;
        case VALUE_TAG_ACTIVITY:
		if (cfg->num_contexts == 0) {
			ERRBUF("at least one context must be configured before any 'activity'");
			return (false);
		}
		/*
		 * Make sure the array of context pointers is initialized.
		 * No more contexts can be created after an activity is
		 * created, so the context autoarray is stable and it is
		 * safe to take references into it.  This action is
		 * idempotent.
		 */
		initialize_context_ptr_lut(state, cfg);
		if (!auto_array_one_more(&state->activity_array)) {
			ERRBUF("failed to allocate more space in activity array");
			return (false);
		}
		state->cur_activity = &cfg->activities[cfg->num_activities];
		cfg->num_activities++;
		initialize_cfg_activity(state->cur_activity);
		auto_array_state_init(&state->activity_action_array,
		    (void **)&state->cur_activity->actions,
		    sizeof(*state->cur_activity->actions));
		break;
        case VALUE_TAG_ACTIVITY_TAG:
		/* nothing to do */
		break;
        case VALUE_TAG_ACTIVITY_MATCH:
		if (!check_one_tag(state, tag, "match", "activity"))
			return (false);
		initialize_context_list(state, &state->match_context_list,
		    &state->cur_activity->match.contexts,
		    &state->cur_activity->match.num_contexts);
		break;
	case VALUE_TAG_ACTIVITY_MATCH_WHICH_IDS:
	case VALUE_TAG_ACTIVITY_MATCH_WHICH_TAGS:
		/* nothing to do */
		break;
        case VALUE_TAG_ACTIVITY_MATCH_AT:
		if (!check_one_tag(state, tag, "at", "match"))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_MATCH_EVERY:
		if (!check_one_tag(state, tag, "every", "match"))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_MATCH_CONTAINER_PROBABILITY:
        case VALUE_TAG_ACTIVITY_MATCH_CONTAINER_N:
	case VALUE_TAG_ACTIVITY_MATCH_CONTAINER_ALL:
		/* nothing to do */
		break;
        case VALUE_TAG_ACTIVITY_MATCH_DATA:
        case VALUE_TAG_ACTIVITY_MATCH_FILE:
        case VALUE_TAG_ACTIVITY_MATCH_REGEX:
        case VALUE_TAG_ACTIVITY_MATCH_FORWARD:
		/* nothing to do */
		break;
        case VALUE_TAG_ACTIVITY_ACTION:
		if (!HAS_VALUE_TAG(ACTIVITY_MATCH)) {
			ERRBUF("'match' must appear before 'action'");
			return (false);
		}
		break;
        case VALUE_TAG_ACTIVITY_ACTION_FAULT:
	case VALUE_TAG_ACTIVITY_ACTION_RENEGOTIATE:
        case VALUE_TAG_ACTIVITY_ACTION_LOG:
        case VALUE_TAG_ACTIVITY_ACTION_SEND:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY:
	case VALUE_TAG_ACTIVITY_ACTION_ALERT:
	case VALUE_TAG_ACTIVITY_ACTION_SHUTDOWN:
		if ((tag == VALUE_TAG_ACTIVITY_ACTION_FAULT) &&
		    !check_one_tag(state, tag, "fault", "action"))
			return (false);
		if ((tag == VALUE_TAG_ACTIVITY_ACTION_RENEGOTIATE) &&
		    !check_one_tag(state, tag, "renegotiate", "action"))
			return (false);
		if (!auto_array_one_more(&state->activity_action_array)) {
			ERRBUF("failed to allocate more space in activity action array");
			return (false);
		}
		state->cur_action =
		    &state->cur_activity->actions[state->cur_activity->num_actions];
		state->cur_activity->num_actions++;
		initialize_cfg_payload(&state->cur_action->send);
		if (tag == VALUE_TAG_ACTIVITY_ACTION_REPLY)
			state->cur_action->send.reply = true;
		break;
        case VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_ID:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_CONTEXT_ID:
	case VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_TAG:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_CONTEXT_TAG:
		/* nothing to do */
		break;
	case VALUE_TAG_ACTIVITY_ACTION_SEND_DATA:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_DATA:
        case VALUE_TAG_ACTIVITY_ACTION_LOG_FILE:
        case VALUE_TAG_ACTIVITY_ACTION_SEND_FILE:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_FILE:
	case VALUE_TAG_ACTIVITY_ACTION_LOG_HANDLER:
	case VALUE_TAG_ACTIVITY_ACTION_SEND_HANDLER:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_HANDLER:
        case VALUE_TAG_ACTIVITY_ACTION_SEND_TEMPLATE:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_TEMPLATE:
		if (state->cur_action->send.type != TLMSP_CFG_PAYLOAD_NONE) {
			ERRBUF("only one data source per payload specification is supported");
			return (false);
		}
		break;
        case VALUE_TAG_ACTIVITY_ACTION_ALERT_CONTEXT_ID:
	case VALUE_TAG_ACTIVITY_ACTION_ALERT_CONTEXT_TAG:
	case VALUE_TAG_ACTIVITY_ACTION_ALERT_LEVEL:
	case VALUE_TAG_ACTIVITY_ACTION_ALERT_DESC_ENUM:
	case VALUE_TAG_ACTIVITY_ACTION_ALERT_DESC_INT:
		/* nothing to do */
		break;
	case VALUE_TAG_ACTIVITY_PRESENT:
		/* nothing to do */
		break;
	case VALUE_TAG_CLIENT:
		if (!check_one_tag(state, tag, "client", "top-object"))
			return (false);
		initialize_activity_list(state, &state->activity_list_to_server,
		    &cfg->client.activities, &cfg->client.num_activities);
		break;
	case VALUE_TAG_CLIENT_VERSION_SINGLE:
	case VALUE_TAG_CLIENT_VERSION_RANGE:
	case VALUE_TAG_CLIENT_VERSION_MIN:
	case VALUE_TAG_CLIENT_VERSION_MAX:
	case VALUE_TAG_CLIENT_ADDRESS:
	case VALUE_TAG_CLIENT_FUNCTION:
		/* nothing to do */
		break;
	case VALUE_TAG_SERVER:
		if (!check_one_tag(state, tag, "server", "top-object"))
			return (false);
		initialize_activity_list(state, &state->activity_list_to_client,
		    &cfg->server.activities, &cfg->server.num_activities);
		break;
	case VALUE_TAG_SERVER_VERSION_SINGLE:
	case VALUE_TAG_SERVER_VERSION_RANGE:
	case VALUE_TAG_SERVER_VERSION_MIN:
	case VALUE_TAG_SERVER_VERSION_MAX:
	case VALUE_TAG_SERVER_ADDRESS:
	case VALUE_TAG_SERVER_FUNCTION:
		/* nothing to do */
		break;
	case VALUE_TAG_SERVER_CERT_FILE:
	case VALUE_TAG_SERVER_CERT_KEY_FILE:
		/* nothing to do */
		break;
	case VALUE_TAG_CONTEXT:
		if (cfg->num_activities > 0) {
			ERRBUF("all contexts must be defined before activities");
			return (false);
		}
		if (cfg->num_middleboxes > 0) {
			ERRBUF("all contexts must be defined before middleboxes");
			return (false);
		}
		if (!auto_array_one_more(&state->context_array)) {
			ERRBUF("failed to allocate more space in context array");
			return (false);
		}
		state->cur_context = &cfg->contexts[cfg->num_contexts];
		cfg->num_contexts++;
		initialize_cfg_context(state->cur_context);
		break;
	case VALUE_TAG_CONTEXT_ID:
	case VALUE_TAG_CONTEXT_TAG:
	case VALUE_TAG_CONTEXT_COMMENT:
	case VALUE_TAG_CONTEXT_PURPOSE:
	case VALUE_TAG_CONTEXT_AUDIT:
		/* nothing to do */
		break;
	case VALUE_TAG_MIDDLEBOX:
		if (cfg->num_contexts == 0) {
			ERRBUF("at least one context must be configured");
			return (false);
		}
		/*
		 * Make sure the array of context pointers is initialized.
		 * No more contexts can be created after a middlebox is
		 * created, so the context autoarray is stable and it is
		 * safe to take references into it.  This action is
		 * idempotent.
		 */
		initialize_context_ptr_lut(state, cfg);
		if (!auto_array_one_more(&state->middlebox_array)) {
			ERRBUF("failed to allocate more space in middlebox array");
			return (false);
		}
		state->cur_middlebox = &cfg->middleboxes[cfg->num_middleboxes];
		cfg->num_middleboxes++;
		initialize_cfg_middlebox(state->cur_middlebox);

		memset(state->middlebox_context_ids, 0,
		    sizeof(state->middlebox_context_ids));
		auto_array_state_init(&state->middlebox_context_array,
		    (void **)&state->cur_middlebox->contexts,
		    sizeof(*state->cur_middlebox->contexts));
		initialize_activity_list(state, &state->activity_list_to_client,
		    &state->cur_middlebox->activities_to_client,
		    &state->cur_middlebox->num_activities_to_client);
		initialize_activity_list(state, &state->activity_list_to_server,
		    &state->cur_middlebox->activities_to_server,
		    &state->cur_middlebox->num_activities_to_server);
		break;
	case VALUE_TAG_MIDDLEBOX_TAG:
	case VALUE_TAG_MIDDLEBOX_ADDRESS:
	case VALUE_TAG_MIDDLEBOX_CERT_FILE:
	case VALUE_TAG_MIDDLEBOX_CERT_KEY_FILE:
	case VALUE_TAG_MIDDLEBOX_TRANSPARENT:
	case VALUE_TAG_MIDDLEBOX_DISCOVERED:
	case VALUE_TAG_MIDDLEBOX_FORBIDDEN:
		/* nothing to do */
		break;
	case VALUE_TAG_MIDDLEBOX_CONTEXT:
		if (!add_middlebox_context(state))
			return (false);
		initialize_cfg_middlebox_context(state->cur_middlebox_context);

		state->first_middlebox_context = NULL;
		memset(state->middlebox_context_replicate_ids, 0,
		    sizeof(state->middlebox_context_replicate_ids));
		break;
	case VALUE_TAG_MIDDLEBOX_CONTEXT_WHICH_IDS:
	case VALUE_TAG_MIDDLEBOX_CONTEXT_WHICH_TAGS:
	case VALUE_TAG_MIDDLEBOX_CONTEXT_ACCESS:
		/* nothing to do */
		break;
	case VALUE_TAG_MIDDLEBOX_FUNCTION_TO_CLIENT:
		break;
	case VALUE_TAG_MIDDLEBOX_FUNCTION_TO_SERVER:
		break;
	case NUM_VALUE_TAGS:
		/* should never happen */
		ERRBUF("internal error");
		return (false);
		break;
	}

	return (true);
}

static bool
handle_value_tag_finish(struct iteration_state *state, enum value_tag tag,
    struct value *value)
{
	struct tlmsp_cfg *cfg;
	struct tlmsp_cfg_context *context;
	const char *tag_str;
	unsigned int i;
	unsigned int context_id;
	
	TRACE("%s: %s\n", fmt_value_tag_name(tag), value_event_name(VALUE_EVENT_FINISH));

	cfg = state->cfg;
	switch (tag) {
	case VALUE_TAG_NO_TAG:
		/* nothing to do */
		break;
	case VALUE_TAG_TOP_OBJECT:
		if (cfg->num_contexts == 0) {
			ERRBUF("at least one context must be defined");
			return (false);
		}
		break;
        case VALUE_TAG_ACTIVITY:
		if (!HAS_VALUE_TAG(ACTIVITY_TAG)) {
			ERRBUF("'tag' key is missing from 'activity'");
			return (false);
		}
		if (!HAS_VALUE_TAG(ACTIVITY_MATCH)) {
			ERRBUF("'match' key is missing from 'activity'");
			return (false);
		}
		if (!HAS_VALUE_TAG(ACTIVITY_ACTION)) {
			ERRBUF("'action' key is missing from 'activity'");
			return (false);
		}
		break;
        case VALUE_TAG_ACTIVITY_TAG:
		for (i = 0; i < cfg->num_activities; i++)
			if (strcmp(cfg->activities[i].tag,
				value->type_string) == 0) {
				ERRBUF("duplicate activity tag '%s'",
				    value->type_string);
				return (false);
			}
		state->cur_activity->tag = value->type_string;
		break;
        case VALUE_TAG_ACTIVITY_MATCH: {
		bool has_time_match = false;
		bool has_container_match = false;
		bool has_pattern_match = false;

		if (HAS_VALUE_TAG(ACTIVITY_MATCH_AT) ||
		    HAS_VALUE_TAG(ACTIVITY_MATCH_EVERY))
			has_time_match = true;
		if (HAS_VALUE_TAG(ACTIVITY_MATCH_CONTAINER_N) ||
		    HAS_VALUE_TAG(ACTIVITY_MATCH_CONTAINER_PROBABILITY) ||
		    HAS_VALUE_TAG(ACTIVITY_MATCH_CONTAINER_ALL))
			has_container_match = true;
		if (HAS_VALUE_TAG(ACTIVITY_MATCH_DATA) ||
		    HAS_VALUE_TAG(ACTIVITY_MATCH_FILE) ||
		    HAS_VALUE_TAG(ACTIVITY_MATCH_REGEX))
			has_pattern_match = true;

		if ((has_time_match + has_container_match +
			has_pattern_match) == 0) {
			ERRBUF("match needs a time, container, or pattern specification");
			return (false);
		}
		if ((has_time_match + has_container_match +
			has_pattern_match) > 1) {
			ERRBUF("match can only have a time, container, or pattern specification");
			return (false);
		}
		if (has_time_match &&
		    (HAS_VALUE_TAG(ACTIVITY_MATCH_WHICH_IDS) ||
			HAS_VALUE_TAG(ACTIVITY_MATCH_WHICH_TAGS))) {
			ERRBUF("'which' key does not apply to time matches");
			return (false);
		}
		if (has_time_match &&
		    (HAS_VALUE_TAG(ACTIVITY_MATCH_FORWARD))) {
			ERRBUF("'forward' key does not apply to time matches");
			return (false);
		}
		if ((has_container_match || has_pattern_match) &&
		    !HAS_VALUE_TAG(ACTIVITY_MATCH_WHICH_IDS) &&
		    !HAS_VALUE_TAG(ACTIVITY_MATCH_WHICH_TAGS)) {
			ERRBUF("container and pattern match require 'which' key");
			return (false);
		}
		break;
	}
	case VALUE_TAG_ACTIVITY_MATCH_WHICH_IDS:
		if (!add_id_to_context_list(&state->match_context_list,
			value->type_int))
			return (false);
		break;
	case VALUE_TAG_ACTIVITY_MATCH_WHICH_TAGS:
		if (!add_tag_to_context_list(&state->match_context_list,
			value->type_string))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_MATCH_FORWARD:
                state->cur_activity->match.forward = value->type_boolean;
                break;
        case VALUE_TAG_ACTIVITY_MATCH_AT:
		if (value->type_int == 0)
			state->cur_activity->match.initial = true;
		state->cur_activity->match.at = MS_TO_S(value->type_int);
		break;
        case VALUE_TAG_ACTIVITY_MATCH_EVERY:
		state->cur_activity->match.every = MS_TO_S(value->type_int);
		break;
        case VALUE_TAG_ACTIVITY_MATCH_CONTAINER_PROBABILITY:
		state->cur_activity->match.container.type =
		    TLMSP_CFG_MATCH_CONTAINER_PROBABILITY;
		state->cur_activity->match.container.param.p =
		    value->type_float;
		break;
        case VALUE_TAG_ACTIVITY_MATCH_CONTAINER_N:
		state->cur_activity->match.container.type =
		    TLMSP_CFG_MATCH_CONTAINER_N;
		state->cur_activity->match.container.param.n =
		    value->type_int;
		break;
        case VALUE_TAG_ACTIVITY_MATCH_CONTAINER_ALL:
		state->cur_activity->match.container.type =
		    TLMSP_CFG_MATCH_CONTAINER_ALL;
		break;
        case VALUE_TAG_ACTIVITY_MATCH_DATA:
		state->cur_activity->match.pattern.type =
		    TLMSP_CFG_MATCH_PATTERN_DATA;
		if (!set_cfg_buf_from_encoded_string(state,
			&state->cur_activity->match.pattern.param.data,
			value->type_string))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_MATCH_FILE:
		state->cur_activity->match.pattern.type =
		    TLMSP_CFG_MATCH_PATTERN_FILE;
		state->cur_activity->match.pattern.param.s =
		    value->type_string;
		break;
        case VALUE_TAG_ACTIVITY_MATCH_REGEX:
		state->cur_activity->match.pattern.type =
		    TLMSP_CFG_MATCH_PATTERN_REGEX;
		state->cur_activity->match.pattern.param.s =
		    value->type_string;
		break;
        case VALUE_TAG_ACTIVITY_ACTION:
		/* nothing to do */
		break;
        case VALUE_TAG_ACTIVITY_ACTION_FAULT:
		state->cur_action->fault = value->type_enum.e;
		break;
        case VALUE_TAG_ACTIVITY_ACTION_RENEGOTIATE:
		state->cur_action->renegotiate = value->type_boolean;
		break;
	case VALUE_TAG_ACTIVITY_ACTION_SHUTDOWN:
		state->cur_action->shutdown = value->type_boolean;
		break;
        case VALUE_TAG_ACTIVITY_ACTION_LOG:
		if (!check_log_payload(state,
			&state->cur_action->log,
			"log"))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_ACTION_SEND:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY:
		if (!check_cfg_payload(state,
			&state->cur_action->send,
			(tag == VALUE_TAG_ACTIVITY_ACTION_SEND) ?
			"send" : "reply"))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_ID:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_CONTEXT_ID:
		if (!set_cfg_payload_context_by_id(state,
			&state->cur_action->send, value->type_int,
			(tag == VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_ID) ?
			"send" : "reply"))
			return (false);
		break;
	case VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_TAG:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_CONTEXT_TAG:
		if (!set_cfg_payload_context_by_tag(state,
			&state->cur_action->send, value->type_string,
			(tag == VALUE_TAG_ACTIVITY_ACTION_SEND_CONTEXT_TAG) ?
			"send" : "reply"))
			return (false);
		break;
	case VALUE_TAG_ACTIVITY_ACTION_SEND_DATA:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_DATA:
		if (!set_cfg_payload_data(state,
			&state->cur_action->send, value->type_string))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_ACTION_LOG_FILE:
		//Implement
		break;
        case VALUE_TAG_ACTIVITY_ACTION_SEND_FILE:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_FILE:
		if (!set_cfg_payload_file(state,
			&state->cur_action->send, value->type_string))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_ACTION_LOG_HANDLER:
		if (!set_cfg_payload_handler(state,
			&state->cur_action->log, value->type_string))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_ACTION_SEND_HANDLER:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_HANDLER:
		if (!set_cfg_payload_handler(state,
			&state->cur_action->send, value->type_string))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_ACTION_SEND_TEMPLATE:
	case VALUE_TAG_ACTIVITY_ACTION_REPLY_TEMPLATE:
		if (!set_cfg_payload_template(state,
			&state->cur_action->send, value->type_string))
			return (false);
		break;
        case VALUE_TAG_ACTIVITY_ACTION_ALERT:
		if (!(HAS_VALUE_TAG(ACTIVITY_ACTION_ALERT_CONTEXT_ID) ||
			HAS_VALUE_TAG(ACTIVITY_ACTION_ALERT_CONTEXT_TAG))) {
			ERRBUF("alert requires 'context' key");
			return (false);
		}
		if (!HAS_VALUE_TAG(ACTIVITY_ACTION_ALERT_LEVEL)) {
			ERRBUF("alert requires 'level' key");
			return (false);
		}
		if (!(HAS_VALUE_TAG(ACTIVITY_ACTION_ALERT_DESC_ENUM) ||
			HAS_VALUE_TAG(ACTIVITY_ACTION_ALERT_DESC_INT))) {
			ERRBUF("alert requires 'description' key");
			return (false);
		}
		break;
        case VALUE_TAG_ACTIVITY_ACTION_ALERT_CONTEXT_ID:
		context_id = value->type_int;
		if (context_id != 0) {
			if (!state->context_id_in_use[context_id]) {
				ERRBUF("context ID %u does not exist",
				    context_id);
				return (false);
			}
			state->cur_action->alert.context =
			    state->context_ptrs[context_id];
		} else
			state->cur_action->alert.context = NULL;
		break;
	case VALUE_TAG_ACTIVITY_ACTION_ALERT_CONTEXT_TAG:
		tag_str = value->type_string;
		context = get_context_by_tag(state->cfg, tag_str, false);
		if (context == NULL) {
			if (get_context_by_tag(state->cfg, tag_str, true)) {
				ERRBUF("cannot use context tag %s in 'alert' "
				    "- it represents multiple context IDs",
				    tag_str);
				return (false);
			} else {
				ERRBUF("unknown context tag '%s' in 'alert'",
				    tag_str);
				return (false);
			}
		}
		state->cur_action->alert.context = context;
		break;
	case VALUE_TAG_ACTIVITY_ACTION_ALERT_LEVEL:
		state->cur_action->alert.level = value->type_enum.e;
		break;
	case VALUE_TAG_ACTIVITY_ACTION_ALERT_DESC_ENUM:
		state->cur_action->alert.description = value->type_enum.e;
		break;
	case VALUE_TAG_ACTIVITY_ACTION_ALERT_DESC_INT:
		state->cur_action->alert.description = value->type_int;
		break;
        case VALUE_TAG_ACTIVITY_PRESENT:
		state->cur_activity->present = value->type_boolean;
		break;
	case VALUE_TAG_CLIENT:
		if (!HAS_VALUE_TAG(CLIENT_ADDRESS)) {
			ERRBUF("client 'address' key is missing");
			return (false);
		}
		break;
	case VALUE_TAG_CLIENT_VERSION_SINGLE:
		cfg->client.version_min = value->type_version;
		cfg->client.version_max = value->type_version;
		break;
	case VALUE_TAG_CLIENT_VERSION_RANGE:
		/* Check if the range isn't inside-out */
		if (cfg->client.version_min > cfg->client.version_max) {
			ERRBUF("client version range min (%d )exceeds "
			    "max (%d)",
			    cfg->client.version_min,
			    cfg->client.version_max);
			return (false);
		}
		break;
	case VALUE_TAG_CLIENT_VERSION_MIN:
		cfg->client.version_min = value->type_version;
		break;
	case VALUE_TAG_CLIENT_VERSION_MAX:
		cfg->client.version_max = value->type_version;
		break;
	case VALUE_TAG_CLIENT_ADDRESS:
		cfg->client.address = value->type_string;
		break;
	case VALUE_TAG_CLIENT_FUNCTION:
		if (!add_tag_to_activity_list(&state->activity_list_to_server,
			value->type_string))
			return (false);
		break;
	case VALUE_TAG_SERVER:
		if (!HAS_VALUE_TAG(SERVER_ADDRESS)) {
			ERRBUF("server 'address' key is missing");
			return (false);
		}
		break;
	case VALUE_TAG_SERVER_VERSION_SINGLE:
		cfg->server.version_min = value->type_version;
		cfg->server.version_max = value->type_version;
		break;
	case VALUE_TAG_SERVER_VERSION_RANGE:
		/* Check if the range isn't inside-out */
		if (cfg->server.version_min > cfg->server.version_max) {
			ERRBUF("server version range min (%d )exceeds "
			    "max (%d)",
			    cfg->server.version_min,
			    cfg->server.version_max);
			return (false);
		}
		break;
	case VALUE_TAG_SERVER_VERSION_MIN:
		cfg->server.version_min = value->type_version;
		break;
	case VALUE_TAG_SERVER_VERSION_MAX:
		cfg->server.version_max = value->type_version;
		break;
	case VALUE_TAG_SERVER_ADDRESS:
		cfg->server.address = value->type_string;
		break;
	case VALUE_TAG_SERVER_CERT_FILE:
		cfg->server.cert_file = value->type_string;
		break;
	case VALUE_TAG_SERVER_CERT_KEY_FILE:
		cfg->server.cert_key_file = value->type_string;
		break;
	case VALUE_TAG_SERVER_FUNCTION:
		if (!add_tag_to_activity_list(&state->activity_list_to_client,
			value->type_string))
			return (false);
		break;
	case VALUE_TAG_CONTEXT:
		if (state->cur_context->id == TLMSP_UTIL_CONTEXT_ID_RESERVED) {
			state->cur_context->id = assign_context_id(state);
			if (state->cur_context->id == TLMSP_UTIL_CONTEXT_ID_RESERVED) {
				ERRBUF("unable to assign context ID");
				return (false);
			}
		} else if (state->context_id_in_use[state->cur_context->id]) {
			ERRBUF("context ID %u is already in use",
			    state->cur_context->id);
			return (false);
		} else
			state->context_id_in_use[state->cur_context->id] = true;
		break;
	case VALUE_TAG_CONTEXT_ID:
		state->cur_context->id = value->type_int;
		break;
	case VALUE_TAG_CONTEXT_TAG:
		state->cur_context->tag = value->type_string;
		break;
	case VALUE_TAG_CONTEXT_COMMENT:
		state->cur_context->comment = value->type_string;
		break;
	case VALUE_TAG_CONTEXT_PURPOSE:
		state->cur_context->purpose = value->type_string;
		break;
	case VALUE_TAG_CONTEXT_AUDIT:
		state->cur_context->audit = value->type_boolean;
		break;
	case VALUE_TAG_MIDDLEBOX:
		if (!HAS_VALUE_TAG(MIDDLEBOX_TAG)) {
			ERRBUF("'tag' key missing from middlebox declaration");
			return (false);
		}
		if (!HAS_VALUE_TAG(MIDDLEBOX_ADDRESS)) {
			ERRBUF("'address' key missing from middlebox declaration");
			return (false);
		}
		if (!HAS_VALUE_TAG(MIDDLEBOX_CERT_FILE)) {
			snprintf(state->tmpbuf, sizeof(state->tmpbuf), "%s-cert.pem",
			    state->cur_middlebox->tag);
			state->cur_middlebox->cert_file = strdup(state->tmpbuf);
		}
		if (!HAS_VALUE_TAG(MIDDLEBOX_CERT_KEY_FILE)) {
			snprintf(state->tmpbuf, sizeof(state->tmpbuf), "%s-key.pem",
			    state->cur_middlebox->tag);
			state->cur_middlebox->cert_key_file = strdup(state->tmpbuf);
		}
		/*
		 * It is not valid to have a server insert a new middlebox
		 * into the list that is also marked forbidden.
		 */
		if (state->cur_middlebox->discovered &&
		    !state->cur_middlebox->transparent &&
		    state->cur_middlebox->forbidden) {
			ERRBUF("a non-transparent, discovered middlebox cannot be "
			    "marked forbidden");
			return (false);			
		}
		state->cur_middlebox = NULL;
		break;
	case VALUE_TAG_MIDDLEBOX_TAG:
		for (i = 0; i < cfg->num_middleboxes; i++)
			if (strcmp(cfg->middleboxes[i].tag,
				value->type_string) == 0) {
				ERRBUF("duplicate middlebox tag '%s'",
				    value->type_string);
				return (false);
			}
		state->cur_middlebox->tag = value->type_string;
		break;
	case VALUE_TAG_MIDDLEBOX_ADDRESS:
		state->cur_middlebox->address = value->type_string;
		break;
	case VALUE_TAG_MIDDLEBOX_CERT_FILE:
		state->cur_middlebox->cert_file = value->type_string;
		break;
	case VALUE_TAG_MIDDLEBOX_CERT_KEY_FILE:
		state->cur_middlebox->cert_key_file = value->type_string;
		break;
	case VALUE_TAG_MIDDLEBOX_TRANSPARENT:
		state->cur_middlebox->transparent = value->type_boolean;
		break;
	case VALUE_TAG_MIDDLEBOX_DISCOVERED:
		state->cur_middlebox->discovered = value->type_boolean;
		break;
	case VALUE_TAG_MIDDLEBOX_FORBIDDEN:
		state->cur_middlebox->forbidden = value->type_boolean;
		break;
	case VALUE_TAG_MIDDLEBOX_CONTEXT:
		if (!HAS_VALUE_TAG(MIDDLEBOX_CONTEXT_WHICH_IDS) &&
		    !HAS_VALUE_TAG(MIDDLEBOX_CONTEXT_WHICH_TAGS)) {
			ERRBUF("'which' key missing from middlebox context");
			return (false);
		}
		/*
		 * Replicate by ID
		 */
		for (i = TLMSP_UTIL_CONTEXT_ID_MIN; i <= TLMSP_UTIL_CONTEXT_ID_MAX; i++) {
			if (!state->middlebox_context_replicate_ids[i])
				continue;
			if (!add_middlebox_context(state))
				return (false);
			copy_cfg_middlebox_context(state->cur_middlebox_context,
			    state->first_middlebox_context);
			state->cur_middlebox_context->base =
			    state->context_ptrs[i];
		}
		break;
	case VALUE_TAG_MIDDLEBOX_CONTEXT_WHICH_IDS:
		context_id = value->type_int;
		if (!state->context_id_in_use[context_id]) {
			ERRBUF("context ID %u does not exist",
			    context_id);
			return (false);
		}
		if (state->middlebox_context_ids[context_id]) {
			ERRBUF("context ID %u is already configured for this middlebox",
			    context_id);
			return (false);
		}
		state->middlebox_context_ids[context_id] = true;

		/*
		 * If this is the first ID in this middlebox
		 * context, then we use it to configure the current
		 * context object.  Otherwise, we add it to the list
		 * of copies to make once the current context object
		 * is completely parsed.
		 */
		if (state->first_middlebox_context == NULL) {
			state->first_middlebox_context = state->cur_middlebox_context;
			state->cur_middlebox_context->base =
			    state->context_ptrs[context_id];
		} else
			state->middlebox_context_replicate_ids[context_id] = true;
		break;
	case VALUE_TAG_MIDDLEBOX_CONTEXT_WHICH_TAGS:
	{
		bool tag_found;

		/*
		 * If this is the first tag in this middlebox context, then
		 * we use the first ID associated with the tag to configure
		 * the current context object, and add all of the other IDs
		 * to the list of copies to make once the current middlebox
		 * context object is completely parsed.  Otherwise, we add
		 * all of the IDs associated with the tag to the copy list.
		 */
		for (i = 0; i < cfg->num_contexts; i++) {
			context = &cfg->contexts[i];
			if ((strcmp(context->tag, value->type_string) != 0) &&
			    (strcmp("*", value->type_string) != 0))
				continue;

			context_id = context->id;
			if (state->middlebox_context_ids[context_id]) {
				ERRBUF("context ID %u is already configured "
				    "for this middlebox", context_id);
				return (false);
			}
				
			tag_found = true;
			state->middlebox_context_ids[context_id] = true;
			if (state->first_middlebox_context == NULL) {
				state->first_middlebox_context =
				    state->cur_middlebox_context;
				state->cur_middlebox_context->base =
				    state->context_ptrs[context_id];
			} else
				state->middlebox_context_replicate_ids[context_id] = true;
		}

		if (!tag_found) {
			ERRBUF("context with tag '%s' not found",
			    value->type_string);
			return(false);
		}

		break;
	}
	case VALUE_TAG_MIDDLEBOX_CONTEXT_ACCESS:
		state->cur_middlebox_context->access = value->type_enum.e;
		break;
	case VALUE_TAG_MIDDLEBOX_FUNCTION_TO_CLIENT:
	{
		struct tlmsp_cfg_middlebox *mb;

		mb = state->cur_middlebox;
		if (!add_tag_to_activity_list(&state->activity_list_to_client,
			value->type_string))
			return (false);
		if (!check_cfg_middlebox_activity(state, mb,
			mb->activities_to_client[mb->num_activities_to_client - 1]))
			return (false);
		break;
	}
	case VALUE_TAG_MIDDLEBOX_FUNCTION_TO_SERVER:
	{
		struct tlmsp_cfg_middlebox *mb;

		mb = state->cur_middlebox;
		if (!add_tag_to_activity_list(&state->activity_list_to_server,
			value->type_string))
			return (false);
		if (!check_cfg_middlebox_activity(state, mb,
			mb->activities_to_server[mb->num_activities_to_server - 1]))
			return (false);
		break;
	}
	case NUM_VALUE_TAGS:
		/* should never happen */
		ERRBUF("internal error");
		return (false);
		break;
	}

	return (true);
}

static void
auto_array_state_init(struct auto_array_state *s, void **a, size_t element_size)
{

	s->array_ptr = a;
	s->current_size = 0;
	s->next_index = 0;
	s->growth_size = AUTO_ARRAY_GROWTH_SIZE;
	s->element_size = element_size;
}

static bool
auto_array_one_more(struct auto_array_state *s)
{
	size_t current_bytes;
	size_t growth_bytes;
	void *new_mem;
	
	if (s->next_index == s->current_size) {
		current_bytes = s->current_size * s->element_size;
		growth_bytes = s->growth_size * s->element_size;
		new_mem = realloc(*(s->array_ptr), current_bytes + growth_bytes);
		if (new_mem == NULL)
			return (false);
		*(s->array_ptr) = new_mem;
		memset((uint8_t *)new_mem + current_bytes, 0, growth_bytes);
		s->current_size += s->growth_size;
	}

	s->next_index++;

	return (true);
}

static bool
check_one_tag(struct iteration_state *state, enum value_tag tag,
    const char *thing, const char *per)
{

	if (HAS_VALUE_TAG_FULL(tag)) {
		ERRBUF("only one '%s' per '%s' is supported", thing, per);
		return (false);
	}

	return (true);
}

static void
initialize_cfg_client(struct tlmsp_cfg_client *cfg)
{

	cfg->version_min = PROTOCOL_VERSION_MIN;
	cfg->version_max = PROTOCOL_VERSION_MAX;
	cfg->address = "";
}

static void
initialize_cfg_server(struct tlmsp_cfg_server *cfg)
{

	cfg->version_min = PROTOCOL_VERSION_MIN;
	cfg->version_max = PROTOCOL_VERSION_MAX;
	cfg->address = "";
	cfg->cert_file = strdup("server-cert.pem");
	cfg->cert_key_file = strdup("server-key.pem");
}

static void
initialize_cfg_context(struct tlmsp_cfg_context *cfg)
{

	cfg->id = TLMSP_UTIL_CONTEXT_ID_RESERVED;
	cfg->tag = "";
	cfg->comment = "";
	cfg->purpose = "";
	cfg->audit = false;
}

static unsigned int
assign_context_id(struct iteration_state *state)
{
	unsigned int i;

	if (state->cfg->num_contexts ==
	    (TLMSP_UTIL_CONTEXT_ID_MAX - TLMSP_UTIL_CONTEXT_ID_MIN + 1))
		return (false);
	
	for (i = TLMSP_UTIL_CONTEXT_ID_MIN; i <= TLMSP_UTIL_CONTEXT_ID_MAX; i++)
		if (!state->context_id_in_use[i]) {
			state->context_id_in_use[i] = true;
			return (i);
		}

	return (TLMSP_UTIL_CONTEXT_ID_RESERVED);
}

static void
initialize_context_ptr_lut(struct iteration_state *state, struct tlmsp_cfg *cfg)
{
	struct tlmsp_cfg_context *context;
	unsigned int i;

	if (!state->context_ptrs_initialized) {
		for (i = 0; i <= cfg->num_contexts; i++) {
			context = &cfg->contexts[i];
			state->context_ptrs[context->id] = context;
		}
		state->context_ptrs_initialized = true;
	}
}

static void
initialize_context_list(struct iteration_state *state, struct context_list *cl,
    struct tlmsp_cfg_context ***contexts, unsigned int *count)
{

	cl->state = state;
	memset(cl->ids, 0, sizeof(cl->ids));
	auto_array_state_init(&cl->ptr_array, (void **)contexts, sizeof(*contexts));
	cl->count = count;
}

static bool
add_id_to_context_list(struct context_list *cl, unsigned int id)
{
	struct iteration_state *state = cl->state;
	
	if (!state->context_id_in_use[id]) {
		ERRBUF("context ID %u does not exist", id);
		return (false);
	}

	/*
	 * Duplicate IDs are OK, but we only want to add
	 * them to the configuration once.
	 */
	if (!cl->ids[id]) {
		if (!add_context_ptr_to_array(&cl->ptr_array, state->context_ptrs[id])) {
			ERRBUF("failed to allocate more space in context ptr array");
			return (false);
		}
		*(cl->count) = *(cl->count) + 1;
		cl->ids[id] = true;
	}

	return (true);
}

static bool
add_tag_to_context_list(struct context_list *cl, const char *tag)
{
	struct iteration_state *state = cl->state;
	struct tlmsp_cfg *cfg = state->cfg;
	struct tlmsp_cfg_context *context;
	unsigned int i;
	bool tag_found;

	tag_found = false;
	for (i = 0; i < cfg->num_contexts; i++) {
		context = &cfg->contexts[i];
		if ((strcmp(context->tag, tag) != 0) &&
		    (strcmp("*", tag) != 0))
			continue;

		tag_found = true;
		add_id_to_context_list(cl, context->id);
	}

	if (!tag_found) {
		ERRBUF("context with tag '%s' not found", tag);
		return(false);
	}

	return (true);
}

static struct tlmsp_cfg_context *
get_context_by_tag(struct tlmsp_cfg *cfg, const char *tag, bool multi_ok)
{
	struct tlmsp_cfg_context *context;
	struct tlmsp_cfg_context *first_found;
	unsigned int i;

	first_found = NULL;
	for (i = 0; i < cfg->num_contexts; i++) {
		context = &cfg->contexts[i];
		if ((strcmp(context->tag, tag) == 0)) {
			if (multi_ok)
				return (context);
			else if (first_found != NULL)
				return (NULL);
			first_found = context;
		}
	}

	return (first_found);
}

static void
initialize_cfg_activity(struct tlmsp_cfg_activity *cfg)
{

	cfg->tag = "";
	/*
	 * struct has already been zeroed
	 *
	 * cfg->match.num_contexts = 0;
	 * cfg->match.contexts = NULL;
	 * cfg->match.initial = false;
	 * cfg->match.at = 0.0;
	 * cfg->match.every = 0.0;
	 * cfg->match.container.type = TLMSP_CFG_MATCH_CONTAINER_NONE;
	 * cfg->match.container.param = 0;
	 * cfg->match.pattern.type = TLMSP_CFG_MATCH_PATTERN_NONE;
	 * cfg->match.pattern.param = { zeros }
	 * cfg->num_actions = 0
	 * cfg->actions = NULL
	 * cfg->present = false
	 */
}

static void
initialize_activity_list(struct iteration_state *state, struct activity_list *cl,
    struct tlmsp_cfg_activity ***activities, unsigned int *count)
{

	cl->state = state;
	auto_array_state_init(&cl->ptr_array, (void **)activities, sizeof(*activities));
	cl->count = count;
}

static bool
add_tag_to_activity_list(struct activity_list *cl, const char *tag)
{
	struct iteration_state *state = cl->state;
	struct tlmsp_cfg *cfg = state->cfg;
	struct tlmsp_cfg_activity *activity;

	activity = get_activity_by_tag(cfg, tag);
	if (activity) {
		if (!add_activity_ptr_to_array(&cl->ptr_array, activity)) {
			ERRBUF("failed to allocate more space in activity pointer array");
			return (false);
		}
		*(cl->count) = *(cl->count) + 1;
		return (true);
	}

	ERRBUF("activity with tag '%s' not found", tag);
	return(false);
}

static struct tlmsp_cfg_activity *
get_activity_by_tag(struct tlmsp_cfg *cfg, const char *tag)
{
	struct tlmsp_cfg_activity *activity;
	unsigned int i;

	for (i = 0; i < cfg->num_activities; i++) {
		activity = &cfg->activities[i];
		if ((strcmp(activity->tag, tag) == 0))
			return (activity);
	}

	return (NULL);
}

static void
initialize_cfg_payload(struct tlmsp_cfg_payload *cfg)
{

	/*
	 * struct has already been zeroed
	 *
	 * cfg->reply = false;
	 * cfg->context = NULL;
	 * cfg->type = TLMSP_CFG_PAYLOAD_NONE;
	 * cfg->param = { zeros }
	 */
}

static bool
check_log_payload(struct iteration_state *state,
    struct tlmsp_cfg_payload *payload, const char *name)
{

	if (payload->type == TLMSP_CFG_PAYLOAD_NONE) {
		ERRBUF("payload specification is missing from '%s' action",
		    name);
		return (false);
	}	

	return (true);
}

static bool
check_cfg_payload(struct iteration_state *state,
    struct tlmsp_cfg_payload *payload, const char *name)
{

	if (payload->context == NULL) {
		ERRBUF("'context' key is missing from '%s' action",
		    name);
		return (false);
	}
	if (payload->type == TLMSP_CFG_PAYLOAD_NONE) {
		ERRBUF("payload specification is missing from '%s' action",
		    name);
		return (false);
	}

	return (true);
}

static bool
set_cfg_payload_context_by_id(struct iteration_state *state,
    struct tlmsp_cfg_payload *cfg, unsigned int id, const char *name)
{

		if (!state->context_id_in_use[id]) {
			ERRBUF("context ID %u does not exist", id);
			return (false);
		}
		cfg->context = state->context_ptrs[id];

		return (true);
}

static bool
set_cfg_payload_context_by_tag(struct iteration_state *state,
    struct tlmsp_cfg_payload *cfg, const char *tag, const char *name)
{
	struct tlmsp_cfg_context *context;

	context = get_context_by_tag(state->cfg, tag, false);
	if (context == NULL) {
		if (get_context_by_tag(state->cfg, tag, true))
			ERRBUF("cannot use context tag %s in '%s' "
			    "- it represents multiple context IDs", name, tag);
		else
			ERRBUF("unknown context tag '%s' in '%s'", tag, name);
		return (false);
	}
	cfg->context = context;

	return (true);
}

static bool
set_cfg_payload_data(struct iteration_state *state,
    struct tlmsp_cfg_payload *cfg, const char *data_string)
{

	cfg->type = TLMSP_CFG_PAYLOAD_DATA;
	if (!set_cfg_buf_from_encoded_string(state, &cfg->param.data, data_string))
		return (false);

	return (true);
}

static bool
set_cfg_payload_file(struct iteration_state *state,
    struct tlmsp_cfg_payload *cfg, const char *filename)
{

	cfg->type = TLMSP_CFG_PAYLOAD_FILE;
	cfg->param.file = filename;

	return (true);
}

static bool
set_cfg_payload_handler(struct iteration_state *state,
    struct tlmsp_cfg_payload *cfg, const char *cmd)
{

	cfg->type = TLMSP_CFG_PAYLOAD_HANDLER;
	cfg->param.cmd = cmd;

	return (true);
}

static bool
set_cfg_payload_template(struct iteration_state *state,
    struct tlmsp_cfg_payload *cfg, const char *template)
{
	struct tlmsp_cfg_template_segment *segment;
	uint8_t *decoded;
	size_t decoded_len;
	unsigned int num_segments;
	size_t search_index;
	size_t search_len;
	size_t ref_start, ref_end;
	unsigned int i;
	unsigned int ref_value;

	/*
	 * Templates can contain references to match results of the form
	 * ${n}, where 'n' is the index of the match result.  Here, we
	 * decompose the template into a series of segments each of which
	 * begins with a (possibly empty) series of data bytes and ends with
	 * a match reference (or the end of the template).
	 *
	 * The decoding is done in a relaxed way such that malformed
	 * match references will appear literally in the result.
	 *
	 * An empty template will decompose into zero segments, not one
	 * segment containing an empty string and no match reference.
	 */
	if (!percent_encoded_string_to_buf(template, &decoded, &decoded_len)) {
		ERRBUF("failed to allocate memory for payload template");
		return (false);
	}
	cfg->type = TLMSP_CFG_PAYLOAD_TEMPLATE;
	/*
	 * First we need to determine the number of segments
	 */
	num_segments = 0;
	if (decoded_len > 0) {
		search_index = 0;
		search_len = decoded_len;
		while (find_first_match_reference(&decoded[search_index],
			search_len, NULL, &ref_end, NULL)) {

			search_index += ref_end + 1;
			search_len = decoded_len - search_index;
			num_segments++;
		}
		if (search_index != decoded_len) {
			/* template does not end with a reference */
			num_segments++;
		}

		cfg->param.template.segments =
		    calloc(num_segments, sizeof(*cfg->param.template.segments));
		if (cfg->param.template.segments == NULL) {
			ERRBUF("failed to allocate memory for payload template "
			    "segments");
			return (false);
		}
		cfg->param.template.num_segments = num_segments;

		search_index = 0;
		search_len = decoded_len;
		for (i = 0; i < num_segments; i++) {
			segment = &cfg->param.template.segments[i];
			if (find_first_match_reference(&decoded[search_index],
				search_len, &ref_start, &ref_end, &ref_value)) {
				segment->data.len = ref_start;
				segment->match_ref = ref_value;
			} else {
				/* last segment, does not end with match reference */
				segment->data.len = decoded_len - search_index;
				segment->match_ref = TLMSP_CFG_MATCH_REF_END;
			}
			if (segment->data.len > 0) {
				segment->data.p = malloc(segment->data.len);
				if (segment->data.p == NULL) {
					ERRBUF("failed to allocate memory for "
					    "payload template segment");
					return (false);
				}
				memcpy((void *)segment->data.p,
				    &decoded[search_index], segment->data.len);
			}
			search_index += ref_end + 1;
			search_len = decoded_len - search_index;
		}
	}
	cfg->param.template.num_segments = num_segments;
	
	return (true);
}

static bool
find_first_match_reference(const uint8_t *buf, size_t len, size_t *ref_start,
    size_t *ref_end, unsigned int *ref_value)
{
	unsigned int i, j;
	bool ref_end_found;

	for (i = 0; i < len; i++) {
		if ((buf[i] == '$') &&       /* ref begins with $ */
		    (len  >= 4) &&           /* must be at least 4 chars */
		    (buf[i + 1] == '{')) {   /* ref begins with ${ */
			ref_end_found = false;
			for (j = i + 2; j < len; j++) {
				if (buf[j] == '}') {
					ref_end_found = true;
					break;
				}
				if (!isdigit(buf[j]))
					break;
			}
			if (ref_end_found &&
			    ((j - i) > 2)) {  /* contains more than one digit */
				if (ref_start != NULL)
					*ref_start = i;
				if (ref_end != NULL)
					*ref_end = j;
				if (ref_value != NULL) {
					/*
					 * It's OK to use sscanf() here even
					 * though the buffer is not a
					 * NUL-terminated string, as we have
					 * already established that starting
					 * at the given point, it contains
					 * only digits followed by a
					 * non-digit.
					 */
					sscanf((char *)&buf[i+2], "%u", ref_value);
				}
				return (true);
			}
		}
	}

	return (false);
}

static bool
set_cfg_buf_from_encoded_string(struct iteration_state *state,
    struct tlmsp_cfg_buf *buf, const char *data_string)
{
	uint8_t *decoded;
	size_t decoded_len;

	if (!percent_encoded_string_to_buf(data_string, &decoded, &decoded_len)) {
		ERRBUF("failed to allocate memory for buf data");
		return (false);
	}
	buf->p = decoded;
	buf->len = decoded_len;

	return (true);
}

static bool
percent_encoded_string_to_buf(const char *str, uint8_t **buf, size_t *len)
{
	uint8_t *output;
	size_t input_len, output_len;
	unsigned int i;
	unsigned int byte_value;
	
	/*
	 * The only reserved character is '%', and technically that means
	 * you always have to say '%25' in the string if you want a '%' to
	 * come through.  However, we are a bit relaxed about the decoding
	 * such that a '%' in the string that is now followed by two hex
	 * digits will be passed through.
	 */
	/* 
	 * Instead of making a first decode pass to determine the exact
	 * result size, we allocate a result buffer that could contain the
	 * entire input string length as the decoded result is strictly less
	 * than or equal to that in size.
	 */
	input_len = strlen(str);
	if (input_len > 0) {
		output = malloc(input_len);
		if (output == NULL)
			return (false);
	}
	output_len = 0;
	for (i = 0; i < input_len; i++) {
		if ((str[i] == '%') &&
		    ((input_len - i) >= 3) &&
		    isxdigit(str[i + 1]) &&
		    isxdigit(str[i + 2])) {
			sscanf(&str[i + 1], "%2x", &byte_value);
			output[output_len++] = byte_value;
			i += 2;
		} else
			output[output_len++] = str[i];
	}

	*buf = output;
	*len = output_len;
	return (true);
}

static void
initialize_cfg_middlebox(struct tlmsp_cfg_middlebox *cfg)
{

	cfg->tag = "";
	cfg->address = "";
	cfg->cert_file = "";
	cfg->cert_key_file = "";
	/*
	 * struct has already been zeroed
	 *
	 * cfg->transparent = false;
	 * cfg->discovered = false;
	 * cfg->forbidden = false;
	 * cfg->num_contexts = 0;
	 * cfg->contexts = NULL;
	 * cfg->num_faults = 0;
	 * cfg->faults = NULL;
	 */
}

static bool
check_cfg_middlebox_activity(struct iteration_state *state,
    struct tlmsp_cfg_middlebox *cfg, struct tlmsp_cfg_activity *activity)
{
	struct tlmsp_cfg_context *context;
	const char *keyword;
	context_access_array_t context_access;
	unsigned int i;

	/*
	 * Middleboxes can't initiate a renegotiate
	 */
	for (i = 0; i < activity->num_actions; i++) {
		if (activity->actions[i].renegotiate) {
			ERRBUF("middlebox %s activity %s contains a renegotiate "
			    "action", cfg->tag, activity->tag);
			return (false);
		}
	}	

	/*
	 * Check whether middlebox has context access necessary for the
	 * match and each action
	 */
	memset(context_access, 0, sizeof(context_access));
	for (i = 0; i < cfg->num_contexts; i++)
		context_access[cfg->contexts[i].base->id] = cfg->contexts[i].access;

	/*
	 * Check that middlebox has read access to all match contexts
	 */
	for (i = 0; i < activity->match.num_contexts; i++) {
		context = activity->match.contexts[i];
		if (!activity->match.forward && context_access[context->id] != TLMSP_CFG_CTX_ACCESS_RW) {
			if (context->tag[0] != '\0')
				ERRBUF("middlebox %s activity %s (without forward) requires write "
				    "access to context %s", cfg->tag, activity->tag, context->tag);
			else
				ERRBUF("middlebox %s activity %s (without forward) requires write "
				    "access to context %u", cfg->tag, activity->tag, context->id);
			return (false);
		}
		if (activity->match.forward && context_access[context->id] == TLMSP_CFG_CTX_ACCESS_NONE) {
			if (context->tag[0] != '\0')
				ERRBUF("middlebox %s activity %s (with forward) requires at least read "
				       "access to context %s", cfg->tag, activity->tag, context->tag);
			else
				ERRBUF("middlebox %s activity %s (with forward) requires at least read "
				       "access to context %u", cfg->tag, activity->tag, context->id);
			return (false);
		}
/*
		if (activity->match.forward && context_access[context->id] != TLMSP_CFG_CTX_ACCESS_R) {
			if (context->tag[0] != '\0')
				ERRBUF("middlebox %s activity %s (with forward) requires EXACTLY read "
				       "access to context %s", cfg->tag, activity->tag, context->tag);
			else
				ERRBUF("middlebox %s activity %s (with forward) requires EXACTLY read "
				       "access to context %u", cfg->tag, activity->tag, context->id);
			return (false);
		}
*/
	}

	/*
	 * Check that middlebox has write access to all action contexts
	 */
	for (i = 0; i < activity->num_actions; i++) {
		context = activity->actions[i].send.context;
		keyword = activity->actions[i].send.reply ? "send" : "reply";
		if ((context != NULL) &&
		    (context_access[context->id] != TLMSP_CFG_CTX_ACCESS_RW)) {
			if (context->tag[0] != '\0')
				ERRBUF("middlebox %s activity %s %s requires write "
				    "access to context %s", cfg->tag, activity->tag,
				    keyword, context->tag);
			else
				ERRBUF("middlebox %s activity %s %s requires write "
				    "access to context %u", cfg->tag, activity->tag,
				    keyword, context->id);
			return (false);
		}
	}

	return (true);
}

static bool
add_middlebox_context(struct iteration_state *state)
{
	if (!auto_array_one_more(&state->middlebox_context_array)) {
		ERRBUF("failed to allocate more space in middlebox context array");
		return (false);
	}
	state->cur_middlebox_context =
	    &state->cur_middlebox->contexts[state->cur_middlebox->num_contexts];
	state->cur_middlebox->num_contexts++;

	return (true);
}

static void
initialize_cfg_middlebox_context(struct tlmsp_cfg_middlebox_context *cfg)
{

	/* cfg->base = NULL; struct has already been zeroed */
	cfg->access = TLMSP_CFG_CTX_ACCESS_R;
}

static void
copy_cfg_middlebox_context(struct tlmsp_cfg_middlebox_context *dest,
    struct tlmsp_cfg_middlebox_context *src)
{

	dest->base = src->base;
	dest->access = src->access;
}

static bool
add_context_ptr_to_array(struct auto_array_state *s, struct tlmsp_cfg_context *cfg)
{
	if (!auto_array_one_more(s))
		return (false);
	*auto_array_cur_p(s, struct tlmsp_cfg_context *) = cfg;
	
	return (true);
}

static bool
add_activity_ptr_to_array(struct auto_array_state *s, struct tlmsp_cfg_activity *cfg)
{
	if (!auto_array_one_more(s))
		return (false);
	*auto_array_cur_p(s, struct tlmsp_cfg_activity *) = cfg;
	
	return (true);
}

#ifdef TRACE_ENABLED
static const char *
value_event_name(enum value_event event)
{
#define TOSTR(x) #x

	switch (event) {
	case VALUE_EVENT_START: return (TOSTR(VALUE_EVENT_START));
	case VALUE_EVENT_FINISH: return (TOSTR(VALUE_EVENT_FINISH));
	}

#undef TOSTR
}
#endif /* TRACE_ENABLED */
