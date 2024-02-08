/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
		
#include <sys/types.h>
#include <sys/wait.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <libtlmsp-cfg.h>
#include <libtlmsp-util.h>
#include <openssl/tlmsp.h>

#include "activity.h"
#include "app.h"
#include "connection.h"
#include "container_queue.h"
#include "print.h"
#include "splice.h"


/* XXX work around record size negotiation bug */
//#define MAX_CONTAINER_SIZE	(TLMSP_CONTAINER_MAX_SIZE - 1024)
#define MAX_CONTAINER_SIZE	(16000)

#define PIPE_READ_FD	0
#define PIPE_WRITE_FD	1


struct match_group {
	uint8_t *p;
	size_t len;
};

struct match_groups {
	unsigned int num_groups;
	struct match_group *groups;
};

struct demo_activity_match_state {
	bool contexts[TLMSP_UTIL_CONTEXT_ID_LUT_SIZE];
	struct tlmsp_cfg_activity *activity;
	struct container_queue_range match_range;
	size_t match_offset;
	uint64_t containers_inspected;
	uint64_t containers_matched;
	struct match_groups match_groups;
};

#define HANDLER_IN_BUF_REALLOC_THRESHOLD	(16*1024)

struct payload_handler_state {
	struct demo_connection *log_conn;
	
	ev_io stdin_watcher;
	ev_io stdout_watcher;
	ev_io stderr_watcher;

	/* feed stdin */
	uint8_t *out_buf;
	size_t out_offset;
	size_t out_remaining;

	/* capture stdout */
	uint8_t *in_buf;
	size_t in_size;
	size_t in_offset;

	/* capture stderr */
	char err_buf[1024];
	size_t err_offset;

	bool closed_stdin;
	bool success;
};


static bool demo_activity_queue_initial(struct demo_connection *from_conn,
                                        bool sends, bool replies);
static bool demo_activity_log_payload(struct demo_connection *conn,
                                        struct tlmsp_cfg_payload *payload,
                                        struct match_groups *match_groups,
                                        bool present);
static bool demo_activity_queue_payload(struct demo_connection *conn,
                                        struct tlmsp_cfg_payload *payload,
                                        struct match_groups *match_groups,
                                        bool present);
static bool demo_activity_queue_alert(struct demo_connection *conn,
                                      struct tlmsp_cfg_alert *alert,
                                      bool present);
static void demo_activity_time_triggered_cb(EV_P_ ev_timer *w, int revents);
static bool demo_activity_log_payload_data(struct demo_connection *conn,
                                           struct tlmsp_cfg_payload *payload,
                                           struct match_groups *match_groups,
                                           const uint8_t **buf, size_t *len,
                                           bool *free_data);
static bool demo_activity_get_payload_data(struct demo_connection *conn,
                                           struct tlmsp_cfg_payload *payload,
                                           struct match_groups *match_groups,
                                           const uint8_t **buf, size_t *len,
                                           bool *free_data);
static bool demo_activity_load_payload_file(struct demo_connection *conn,
                                            struct tlmsp_cfg_payload *payload,
                                            const uint8_t **buf, size_t *len);
static bool demo_activity_run_payload_handler(struct demo_connection *log_conn,
                                              struct tlmsp_cfg_payload *payload,
                                              struct match_groups *match_groups,
                                              const uint8_t **buf, size_t *len,
                                              bool connection_info_as_arguments);
static void demo_activity_handler_stdin_cb(EV_P_ ev_io *w, int revents);
static void demo_activity_handler_stdout_cb(EV_P_ ev_io *w, int revents);
static void demo_activity_handler_stderr_cb(EV_P_ ev_io *w, int revents);
static bool demo_activity_process_payload_template(struct demo_connection *conn,
                                                   struct tlmsp_cfg_payload *payload,
                                                   struct match_groups *match_groups,
                                                   const uint8_t **buf, size_t *len);
static bool demo_activity_container_match(struct demo_connection *conn,
                                          struct demo_activity_match_state *match_state,
                                          bool ignore_context_rights);
static bool demo_activity_pattern_match(struct demo_connection *conn,
                                        struct demo_activity_match_state *match_state);
static void demo_activity_free_match_groups(struct match_groups *groups);
static bool demo_activity_queue_range_to_buffer(struct container_queue_range *range,
                                                uint8_t **buf, size_t *len);
static bool demo_activity_apply_match_actions(struct demo_connection *inbound_conn,
                                              struct demo_activity_match_state *match_state);
static bool demo_activity_apply_actions(struct demo_connection *activity_conn,
                                        struct tlmsp_cfg_activity *activity,
                                        struct match_groups *match_groups, bool sends,
                                        bool replies);
static bool demo_activity_forward_match(struct demo_connection *log_conn, struct container_queue *read_q,
                                        struct container_queue *write_q, struct container_queue_range *match_range);
static bool demo_activity_drop_or_forward_match_preamble(struct demo_connection *log_conn,
                                                         struct container_queue *read_q,
                                                         struct container_queue *write_q,
                                                         struct container_queue_range *match_range,
                                                         bool drop);
static bool demo_activity_drop_or_delete_match(struct demo_connection *log_conn,
                                               struct container_queue *read_q,
                                               struct container_queue *write_q,
                                               struct container_queue_range *match_range,
                                               bool drop);
static struct demo_connection *demo_activity_get_dataflow_conn(struct demo_connection *conn,
                                                               bool replies);


/*
 * Determine if there are any containers that are to be initially sent on
 * this connection, and if so, add them to the write queue.
 */
bool
demo_activity_conn_queue_initial(struct demo_connection *to_conn)
{
	bool is_middlebox;

	is_middlebox = (to_conn->splice != NULL);

	/*
	 * Queue initial containers to this connection originating from this
	 * connection's activities.  For an endpoint that includes both
	 * sends and replies (which are synonymous), and for a middlebox
	 * that only includes replies.
	 */
	if (!demo_activity_queue_initial(to_conn, !is_middlebox, true))
		return (false);

	if (is_middlebox) {
		/*
		 * On a middlebox, queue initial containers to this
		 * connection originating from the other-side connection,
		 * which would only be sends.
		 */
		if (!demo_activity_queue_initial(to_conn->other_side, true, false))
			return (false);
	}

	return (true);
}

static bool
demo_activity_queue_initial(struct demo_connection *from_conn, bool sends,
    bool replies)
{
	struct tlmsp_cfg_activity *activity;
	unsigned int i;

	for (i = 0; i < from_conn->num_activities; i++) {
		activity = from_conn->activities[i];
		if (!activity->match.initial)
			continue;

		if (activity->present)
			demo_conn_present(from_conn, "Activity %s initial",
			    activity->tag);

		if (!demo_activity_apply_actions(from_conn, activity, NULL,
			sends, replies))
			return (false);
	}

	return (true);
}

/*
 * Arrange for all time-triggered containers originating from this
 * connection's activities to be queued at the proper time.
 */
bool
demo_activity_conn_set_up_time_triggered(struct demo_connection *from_conn)
{
	struct tlmsp_cfg_activity *activity;
	struct demo_time_triggered_msg *msg;
	unsigned int i;
	ev_tstamp at, every;

	for (i = 0; i < from_conn->num_activities; i++) {
		activity = from_conn->activities[i];

		/*
		 * skip non-time triggered messages and initial-only time-
		 * triggered messages
		 */
		if ((activity->match.at == 0.0) && (activity->match.every == 0.0))
			continue;

		msg = calloc(1, sizeof(*msg));
		if (msg == NULL)
			return (false);

		msg->conn = from_conn;
		at = activity->match.at;
		every = activity->match.every;
		ev_timer_init(&msg->timer, demo_activity_time_triggered_cb,
		    (at == 0.0) ? every : at, 0.0);
		msg->timer.data = msg;
		msg->interval = every;
		msg->activity = activity;

		if (every == 0.0)
			demo_conn_log(2, from_conn, "Adding one-shot activity %s at "
			    "%u ms", activity->tag, (unsigned int)(at * 1000.0));
		else
			demo_conn_log(2, from_conn, "Adding periodic activity %s at "
			    "%u ms, period %u ms", activity->tag,
			    (unsigned int)(((at == 0.0) ? every : at) * 1000.0),
			    (unsigned int)(every * 1000.0));

		if (from_conn->time_triggered_messages == NULL)
			from_conn->time_triggered_messages = msg;
		else {
			msg->next = from_conn->time_triggered_messages;
			from_conn->time_triggered_messages = msg;
		}
	}

	return (true);
}

void
demo_activity_conn_tear_down_time_triggered(struct demo_connection *from_conn)
{
	struct ev_loop *loop = from_conn->loop;
	struct demo_time_triggered_msg *msg, *next;

	msg = from_conn->time_triggered_messages;
	while (msg != NULL) {
		next = msg->next;
		ev_timer_stop(EV_A_ &msg->timer);
		free(msg);
		msg = next;
	}
}

bool
demo_activity_conn_start_time_triggered(struct demo_connection *from_conn)
{
	struct ev_loop *loop = from_conn->loop;
	struct demo_time_triggered_msg *msg;

	msg = from_conn->time_triggered_messages;
	while (msg != NULL) {
		ev_timer_start(EV_A_ &msg->timer);
		msg = msg->next;
	}

	return (true);
}

static bool
demo_activity_log_payload(struct demo_connection *conn,
			  struct tlmsp_cfg_payload *payload, struct match_groups *match_groups,
			  bool present) {
	const uint8_t *data;
	size_t len;
	bool result;
	bool free_data;

	/* skip if the payload is not configured */
	if (payload->type == TLMSP_CFG_PAYLOAD_NONE)
		return (true);

	data = NULL;
	free_data = false;
	result = false;
	if (!demo_activity_log_payload_data(conn, payload, match_groups, &data,
		&len, &free_data))
		goto out;

	result = true;

 out:
	if ((data != NULL) && free_data)
		free((void *) data);
	return (result);
}

static bool
demo_activity_queue_payload(struct demo_connection *conn,
    struct tlmsp_cfg_payload *payload, struct match_groups *match_groups,
    bool present)
{
	struct container_queue *q = &conn->write_queue;
	SSL *ssl = q->conn->ssl;
	TLMSP_Container *container;
	const uint8_t *data;
	size_t len;
	size_t offset;
	size_t remaining;
	size_t container_len;
	bool result;
	bool free_data;

	/* skip if the payload is not configured */
	if (payload->type == TLMSP_CFG_PAYLOAD_NONE)
		return (true);

	data = NULL;
	free_data = false;
	result = false;
	if (!demo_activity_get_payload_data(conn, payload, match_groups, &data,
		&len, &free_data))
		goto out;

	if (present)
		demo_conn_present_buf(conn, data, len, true, "Sent");
			    
	offset = 0;
	remaining = len;
	do {
		if (remaining > MAX_CONTAINER_SIZE)
			container_len = MAX_CONTAINER_SIZE;
		else
			container_len = remaining;
		if (!TLMSP_container_create(ssl, &container,
			payload->context->id, &data[offset],
			container_len)) {
			demo_conn_print_error_ssl_errq(conn,
			    "Failed to create container for payload");
			goto out;
		}

		if (!container_queue_add(q, container)) {
			demo_conn_print_error(conn,
			    "Failed to add payload container to queue");
			TLMSP_container_free(ssl, container);
			goto out;
		}
		demo_conn_log(2, conn, "Queued container (length=%u) in "
		    "context %u", container_len, payload->context->id);

		offset += container_len;
		remaining -= container_len;
	} while (remaining > 0);

	result = true;

 out:
	if ((data != NULL) && free_data)
		free((void *)data);
	return (result);
}

static bool
demo_activity_queue_alert(struct demo_connection *conn,
    struct tlmsp_cfg_alert *alert, bool present)
{
	struct container_queue *q = &conn->write_queue;
	SSL *ssl = q->conn->ssl;
	TLMSP_Container *container;
	tlmsp_context_id_t context_id;

	context_id = alert->context ? alert->context->id : 0;
	if (present)
		demo_conn_present(conn, "Sending %s alert %d in context %u",
		    alert->level == TLMSP_CFG_ACTION_ALERT_LEVEL_WARNING ?
		    "warning" : "fatal", alert->description, context_id);

	if (!TLMSP_container_create_alert(ssl, &container, context_id,
		(alert->level << 8) | alert->description)) {
		demo_conn_print_error_ssl_errq(conn,
		    "Failed to create container for alert");
		return (false);
	}

	if (!container_queue_add(q, container)) {
		demo_conn_print_error(conn,
		    "Failed to add alert container to queue");
		TLMSP_container_free(ssl, container);
		return (false);
	}

	demo_conn_log(2, conn, "Sending %s alert %d in context %u",
	    alert->level == TLMSP_CFG_ACTION_ALERT_LEVEL_WARNING ?
	    "warning" : "fatal", alert->description, context_id);

	return (true);
}

static void
demo_activity_time_triggered_cb(EV_P_ ev_timer *w, int revents)
{
	struct demo_time_triggered_msg *msg = w->data;
	struct demo_connection *conn = msg->conn;
	struct tlmsp_cfg_activity *activity = msg->activity;

	if (activity->present)
		demo_conn_present(conn, "Activity %s time-triggered",
		    activity->tag);

	if (!demo_activity_apply_actions(conn, activity, NULL, true, true))
		return;

	demo_connection_pause_io(conn);
	demo_connection_wait_for(conn, EV_WRITE);
	demo_connection_resume_io(conn);

	if (msg->interval != 0.0) {
		w->repeat = msg->interval;
		ev_timer_again(EV_A_ w);
	}
}

static bool
demo_activity_log_payload_data(struct demo_connection *conn,
    struct tlmsp_cfg_payload *payload, struct match_groups *match_groups,
    const uint8_t **buf, size_t *len, bool *free_data)
{
	switch (payload->type) {
	case TLMSP_CFG_PAYLOAD_NONE:
		*buf = NULL;
		*len = 0;
		break;
	case TLMSP_CFG_PAYLOAD_FILE:
		//Implement
		break;
	case TLMSP_CFG_PAYLOAD_HANDLER:
		if (!demo_activity_run_payload_handler(conn, payload,
			match_groups, buf, len, true))
			return (false);
		break;
	default:
		//Shouldn't happen
		break;
	}
	*free_data = true;

	return (true);
}

static bool
demo_activity_get_payload_data(struct demo_connection *conn,
    struct tlmsp_cfg_payload *payload, struct match_groups *match_groups,
    const uint8_t **buf, size_t *len, bool *free_data)
{
	bool needs_free;

	needs_free = true;
	switch (payload->type) {
	case TLMSP_CFG_PAYLOAD_NONE:
		*buf = NULL;
		*len = 0;
		break;
	case TLMSP_CFG_PAYLOAD_DATA:
		*buf = payload->param.data.p;
		*len = payload->param.data.len;
		needs_free = false;
		break;
	case TLMSP_CFG_PAYLOAD_FILE:
		if (!demo_activity_load_payload_file(conn, payload, buf, len))
			return (false);
		break;
	case TLMSP_CFG_PAYLOAD_HANDLER:
		if (!demo_activity_run_payload_handler(conn, payload,
			match_groups, buf, len, true))
			return (false);
		break;
	case TLMSP_CFG_PAYLOAD_TEMPLATE:
		if (!demo_activity_process_payload_template(conn, payload,
			match_groups, buf, len))
			return (false);
		break;
	}
	*free_data = needs_free;

	return (true);
}

static bool
demo_activity_load_payload_file(struct demo_connection *conn,
    struct tlmsp_cfg_payload *payload, const uint8_t **buf, size_t *len)
{
	char errbuf[DEMO_ERRBUF_SIZE];
		
	if (!tlmsp_util_load_file(payload->param.file, buf, len, errbuf,
		sizeof(errbuf))) {
		demo_conn_print_error(conn, "%s", errbuf);
		return (false);
	}

	return (true);
}

// https://stackoverflow.com/a/779960/23244567
// You must free the result if result is non-NULL.
char *str_replace(char *orig, char *rep, char *with) {
	char *result = NULL; // the return string
	char *ins;    // the next insert point
	char *tmp;    // varies
	size_t len_rep;  // length of rep (the string to remove)
	size_t len_with; // length of with (the string to replace rep with)
	size_t len_front; // distance between rep and end of last rep
	int count;    // number of replacements

	// sanity checks and initialization
	if (!orig || !rep)
		return NULL;
	len_rep = strlen(rep);
	if (len_rep == 0)
		return NULL; // empty rep causes infinite loop during count
	if (!with)
		with = "";
	len_with = strlen(with);

	// count the number of replacements needed
	ins = orig;
	for (count = 0; (tmp = strstr(ins, rep)); ++count) {
		ins = tmp + len_rep;
	}

	if (!count) {
		result = malloc(strlen(orig));
		strcpy(result, orig);
		return result;
	}

	tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

	if (!result)
		return NULL;

	// first time through the loop, all the variable are set correctly
	// from here on,
	//    tmp points to the end of the result string
	//    ins points to the next occurrence of rep in orig
	//    orig points to the remainder of orig after "end of rep"
	while (count--) {
		ins = strstr(orig, rep);
		len_front = ins - orig;
		tmp = strncpy(tmp, orig, len_front) + len_front;
		tmp = strcpy(tmp, with) + len_with;
		orig += len_front + len_rep; // move to next "end of rep"
	}
	strcpy(tmp, orig);
	return result;
}

static bool
demo_activity_run_payload_handler(struct demo_connection *log_conn,
    struct tlmsp_cfg_payload *payload, struct match_groups *match_groups,
    const uint8_t **buf, size_t *len, bool connection_info_as_arguments)
{
	int stdin_pipe[2];  /* handler's stdin */
	int stdout_pipe[2]; /* handler's stdout */
	int stderr_pipe[2]; /* handler's stderr */
	pid_t child_pid;
	int execlp_result;

	demo_conn_log(5, log_conn, "Running handler '%s'", payload->param.cmd);
	if (pipe2(stdin_pipe, O_NONBLOCK) == -1) {
		demo_conn_print_errno(log_conn,
		    "Failed to create pipe for handler stdin redirect");
		goto stdin_fail;
	}
	if (pipe2(stdout_pipe, O_NONBLOCK) == -1) {
		demo_conn_print_errno(log_conn,
		    "Failed to create pipe for handler stdout redirect");
		goto stdout_fail;
	}
	if (pipe2(stderr_pipe, O_NONBLOCK) == -1) {
		demo_conn_print_errno(log_conn,
		    "Failed to create pipe for handler stderr redirect");
		goto stderr_fail;
	}

	child_pid = fork();
	if (0 == child_pid) {
		/* child */
		
		/* redirections */
		if (dup2(stdin_pipe[PIPE_READ_FD], STDIN_FILENO) == -1) {
			fprintf(stderr, "Failed to dup2(STDIN)\n");
			exit(errno);
		}
		if (dup2(stdout_pipe[PIPE_WRITE_FD], STDOUT_FILENO) == -1) {
			fprintf(stderr, "Failed to dup2(STDOUT)\n");
			exit(errno);
		}
		if (dup2(stderr_pipe[PIPE_WRITE_FD], STDERR_FILENO) == -1) {
			fprintf(stderr, "Failed to dup2(STDOUT)\n");
			exit(errno);
		}

		/* no longer of interest to the child */
		close(stdin_pipe[PIPE_READ_FD]);
		close(stdin_pipe[PIPE_WRITE_FD]);
		close(stdout_pipe[PIPE_READ_FD]);
		close(stdout_pipe[PIPE_WRITE_FD]);
		close(stderr_pipe[PIPE_READ_FD]);
		close(stderr_pipe[PIPE_WRITE_FD]);

		if(connection_info_as_arguments)
		{
			size_t chars = 20 + 1 + 20 + 1 + 1 + 1;
			char params_buf[chars];
			snprintf(params_buf, chars, "%" PRIu64 " %" PRIu64 " %d", log_conn->id, log_conn->splice->id, log_conn->to_client);
			char *orig = malloc(strlen(payload->param.cmd) + 1);
			strcpy(orig, payload->param.cmd);
			char *replaced = str_replace(orig, "{}", params_buf);
			execlp_result = execlp("/usr/bin/stdbuf", "stdbuf", "-i0", "-o0", "-e0", "/bin/sh", "-c", replaced, NULL);
		}
		else
		{
			execlp_result = execlp("/usr/bin/stdbuf", "stdbuf", "-i0", "-o0", "-e0", "/bin/sh", "-c", payload->param.cmd, NULL);
		}
		if (execlp_result == -1) {
			fprintf(stderr,
			    "Failed to exec /bin/sh for handler '%s'\n",
			    payload->param.cmd);
			exit(errno);
		}
	} else if (child_pid > 0) {
		/* parent */
		struct payload_handler_state state;
		struct ev_loop *loop;

		/* close fds we don't need */
		close(stdin_pipe[PIPE_READ_FD]);
		close(stdout_pipe[PIPE_WRITE_FD]);
		close(stderr_pipe[PIPE_WRITE_FD]);


		state.log_conn = log_conn;
		
		/* we pass the handler the entire match */
		state.out_buf = match_groups ? match_groups->groups[0].p : NULL;
		state.out_offset = 0;
		state.out_remaining = match_groups ? match_groups->groups[0].len : 0;

		state.in_buf = NULL;
		state.in_size = 0;
		state.in_offset = 0;

		state.err_offset = 0;

		state.closed_stdin = false;
		state.success = false;
		
		loop = ev_loop_new(EVFLAG_AUTO);
		if (loop == NULL) {
			demo_conn_print_errno(log_conn,
			    "Failed to create event loop for handler");
			goto parent_out;
		}

		ev_io_init(&state.stdin_watcher, demo_activity_handler_stdin_cb,
		    stdin_pipe[PIPE_WRITE_FD], EV_WRITE);
		state.stdin_watcher.data = &state;
		ev_io_start(loop, &state.stdin_watcher);

		ev_io_init(&state.stdout_watcher, demo_activity_handler_stdout_cb,
		    stdout_pipe[PIPE_READ_FD], EV_READ);
		state.stdout_watcher.data = &state;
		ev_io_start(loop, &state.stdout_watcher);
		
		ev_io_init(&state.stderr_watcher, demo_activity_handler_stderr_cb,
		    stderr_pipe[PIPE_READ_FD], EV_READ);
		state.stderr_watcher.data = &state;
		ev_io_start(loop, &state.stderr_watcher);

		demo_conn_log(5, log_conn, "Waiting for handler to exit");
		ev_run(loop, 0);
		demo_conn_log(5, log_conn, "Handler has exited");		

		ev_loop_destroy(loop);

		if (state.success) {
			*buf = state.in_buf;
			*len = state.in_offset;
		}

	parent_out:
		if (!state.closed_stdin)
			close(stdin_pipe[PIPE_WRITE_FD]);
		close(stdout_pipe[PIPE_READ_FD]);
		close(stderr_pipe[PIPE_READ_FD]);

		if (!state.success)
		{
			return (false);
		}
		int status=0;
		waitpid(child_pid, &status, 0);
		demo_conn_log(5, log_conn, "Handler exited with status code %d", WEXITSTATUS(status));
		return(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}

	demo_conn_print_errno(log_conn, "Fork failed for handler '%s'",
	    payload->param.cmd);

	close(stdin_pipe[PIPE_READ_FD]);
	close(stdin_pipe[PIPE_WRITE_FD]);
stderr_fail:
	close(stdout_pipe[PIPE_READ_FD]);
	close(stdout_pipe[PIPE_WRITE_FD]);
stdout_fail:
	close(stdin_pipe[PIPE_READ_FD]);
	close(stdin_pipe[PIPE_WRITE_FD]);
stdin_fail:
	return (false);
}

static void
demo_activity_handler_stdin_cb(EV_P_ ev_io *w, int revents)
{
	struct payload_handler_state *state = w->data;
	ssize_t bytes_written;

	if (state->out_remaining > 0) {
		bytes_written = write(w->fd, state->out_buf, state->out_remaining);
		if (bytes_written == -1) {
			demo_conn_log(5, state->log_conn, "stdin -1");
			if (errno != EAGAIN)
			ev_break(EV_A_ EVBREAK_ONE);
			return;
		}
		demo_conn_log(5, state->log_conn,
		    "Wrote %zd bytes to handler's stdin", bytes_written);
		state->out_offset += bytes_written;
		state->out_remaining -= bytes_written;
	}
	if (state->out_remaining == 0) {
		/* provide EOF to handler */
		close(w->fd);
		ev_io_stop(EV_A_ w);
		state->closed_stdin = true;
	}
}

static void
demo_activity_handler_stdout_cb(EV_P_ ev_io *w, int revents)
{
	struct payload_handler_state *state = w->data;
	size_t space, new_size;
	ssize_t bytes_read;
	uint8_t *p;

	demo_conn_log(5, state->log_conn, "Handler stdout event");
	/*
	 * If we have less than the realloc threshold, extend the buffer.
	 */
	space = state->in_size - state->in_offset;
	if (space < HANDLER_IN_BUF_REALLOC_THRESHOLD) {
		new_size = state->in_size ?
		    (state->in_size * 2) : HANDLER_IN_BUF_REALLOC_THRESHOLD;
		p = realloc(state->in_buf, new_size);
		if (p == NULL) {
			ev_break(EV_A_ EVBREAK_ONE);
			return;
		}
		state->in_buf = p;
		state->in_size = new_size;
		space = state->in_size - state->in_offset;
	}
	bytes_read = read(w->fd, &state->in_buf[state->in_offset], space);
	if (bytes_read == -1) {
		demo_conn_print_errno(state->log_conn, "stdout -1  fd=%d", w->fd);
		if (errno != EAGAIN) {
			ev_break(EV_A_ EVBREAK_ONE);
		}
		return;
	}
	demo_conn_log(5, state->log_conn,
	    "Read %zd bytes from handler's stdout", bytes_read);
	if (bytes_read == 0) {
		demo_conn_log(5, state->log_conn, "EOF on handler's stdout");
		ev_io_stop(EV_A_ w);
		state->success = true;
	} else
		state->in_offset += bytes_read;
}

static void
demo_activity_handler_stderr_cb(EV_P_ ev_io *w, int revents)
{
	struct payload_handler_state *state = w->data;
	ssize_t bytes_read;
	size_t space;

	demo_conn_log(5, state->log_conn, "Handler stderr event");
	/* always leave one byte at the end for a NUL */
	space = sizeof(state->err_buf) - state->err_offset - 1;
	bytes_read = read(w->fd, &state->err_buf[state->err_offset], space);
	if (bytes_read == -1) {
		demo_conn_log(5, state->log_conn, "stderr -1");
			
		if (errno != EAGAIN)
			ev_break(EV_A_ EVBREAK_ONE);
		return;
	}
	if (bytes_read == 0) {
		demo_conn_log(5, state->log_conn, "EOF on handler's stderr");
		ev_io_stop(EV_A_ w);
	} else {
		demo_conn_log(5, state->log_conn,
		    "Read %zd bytes from handler's stderr", bytes_read);
		state->err_offset += bytes_read;
		state->err_buf[state->err_offset] = '\0';
		demo_conn_print_error(state->log_conn, "Handler stderr: %s",
		    state->err_buf);
	}
}

static bool
demo_activity_process_payload_template(struct demo_connection *conn,
    struct tlmsp_cfg_payload *payload, struct match_groups *match_groups,
    const uint8_t **buf, size_t *len)
{
	struct tlmsp_cfg_template_segment *segment;
	struct match_group *group;
	unsigned int i;
	size_t total_size;
	uint8_t *p;
		
	/*
	 * First, determine what the total size of the result will
	 * be.
	 */
	total_size = 0;
	for (i = 0; i < payload->param.template.num_segments; i++) {
		segment = &payload->param.template.segments[i];
		total_size += segment->data.len;

		/*
		 * References to non-existent match groups are
		 * treated as empty.
		 */
		if ((match_groups != NULL) &&
		    (segment->match_ref != TLMSP_CFG_MATCH_REF_END) &&
		    (segment->match_ref < match_groups->num_groups))
			total_size +=
			    match_groups->groups[segment->match_ref].len;
	}

	p = malloc(total_size);
	if (p == NULL) {
		demo_conn_print_errno(conn, "Failed to allocate %zu "
		    "bytes for template instantiation", total_size);
		return (false);
	}


	/*
	 * Now construct the result.
	 */
	total_size = 0;
	for (i = 0; i < payload->param.template.num_segments; i++) {
		segment = &payload->param.template.segments[i];
		memcpy(&p[total_size], segment->data.p, segment->data.len);
		total_size += segment->data.len;

		/*
		 * References to non-existent match groups are
		 * treated as empty.
		 */
		if ((match_groups != NULL) &&
		    (segment->match_ref != TLMSP_CFG_MATCH_REF_END) &&
		    (segment->match_ref < match_groups->num_groups)) {
			group = &match_groups->groups[segment->match_ref];
			memcpy(&p[total_size], group->p, group->len);
			total_size += group->len;
		}
	}

	*buf = p;
	*len = total_size;
	return (true);
}

struct demo_activity_match_state *
demo_activity_create_match_state(struct tlmsp_cfg_activity **activities,
    unsigned int num_activities)
{
	struct demo_activity_match_state *state;
	struct tlmsp_cfg_activity *activity;
	struct tlmsp_cfg_context *context;
	unsigned int i, j;

	state = calloc(num_activities, sizeof(*state));
	if (state == NULL)
		return (NULL);

	for (i = 0; i < num_activities; i++) {
		activity = activities[i];
		state[i].activity = activity;
		for (j = 0; j < activity->match.num_contexts; j++) {
			context = activity->match.contexts[j];
			state[i].contexts[context->id] = true;
		}
	}

	return (state);
}

bool
demo_activity_process_read_queue(struct demo_connection *conn)
{
	struct demo_activity_match_state *match_state;
	struct demo_activity_match_state *selected_match_state;
	TLMSP_Container *container;
	unsigned int i;
	bool return_false;

	/*
	 * There are more sophisticated approaches to finding and resolving
	 * matches given the possibility of multiple matches occurring with
	 * overlapping match ranges.  The approach here tries to keep things
	 * as simple as possible while being sufficiently useful for testing
	 * and demonstration.
	 *
	 * Approach:
	 *
	 *   1. Evaluate all activities for a match in the queue
	 *
	 *   2. Execute the match with the earliest match range in the read
	 *      queue.  If there is a tie, the activity with the lowest
	 *      index (listed earliest in this entity's function keyword in
	 *      the config file) wins.
	 *
	 *   3. Execute the action for the selected match.  All of the data
	 *      in the read queue through the end of the match range will be
	 *      consumed (whether it is forwarded or deleted in whole or in
	 *      part depends on the actions taken and whether this is an
	 *      endpoint or a middlebox).
	 *
	 *   4. Repeat until no matches are found.
	 */
	do {
		demo_conn_log(5, conn, "Looking for matches in read queue "
		    "(%u activities)", conn->num_activities);

		selected_match_state = NULL;
		for (i = 0; i < conn->num_activities; i++) {
			match_state = &conn->activity_states[i];

			/* time-triggered matches are ignored */
			
			if (!demo_activity_container_match(conn, match_state, false) &&
			    !demo_activity_pattern_match(conn, match_state))
				continue;

			if ((selected_match_state == NULL) ||
			    (match_state->match_offset < selected_match_state->match_offset))
				selected_match_state = match_state;
		}

		return_false = false;
		if (selected_match_state != NULL) {
			return_false = !demo_activity_apply_match_actions(conn,
			    selected_match_state);
			if (return_false)
				demo_conn_print_error(conn,
				    "Applying action for match failed");
		} else
			demo_conn_log(5, conn, "No matches found");

		/* Free all match groups */
		for (i = 0; i < conn->num_activities; i++) {
			match_state = &conn->activity_states[i];
			demo_activity_free_match_groups(&match_state->match_groups);
		}
		
		if (return_false)
			return (false);
	} while ((selected_match_state != NULL) && (conn->read_queue.head != NULL));

	/*
	 * If the read queue has a size limit and we are over it, either
	 * drop (endpoint) or forward (middlebox) containers until we are
	 * back under the limit.
	 */
	if ((conn->read_queue.max_length != 0) &&
	    (conn->read_queue.length > conn->read_queue.max_length)) {
		demo_conn_log(2, conn, "Read queue is over limit with "
		    "nothing matching, %s containers in queue until under limit.",
		    (conn->splice != NULL) ? "forwarding" : "deleting");

		while (conn->read_queue.length > conn->read_queue.max_length) {
			container = container_queue_remove_head(&conn->read_queue);
			if (conn->splice != NULL)
				container_queue_add(&conn->other_side->write_queue,
				    container);
			else
				TLMSP_container_free(conn->ssl, container);
		}
	}
	
	/*
	 * We may have added data to the connection's write queue as a
	 * result of the match-action activity processed above, so ensure
	 * the write event is set.
	 */
	if (demo_connection_writes_pending(conn))
		demo_connection_wait_for(conn, EV_WRITE);
	/*
	 * If this connection is part of a splice, the above match-action
	 * activity may have queued new data to the other side's write
	 * queue.
	 */
	if (conn->splice != NULL) {
		if (demo_connection_writes_pending(conn->other_side))
			demo_connection_wait_for(conn->other_side, EV_WRITE);
	}
	
	return (true);
}

static bool
demo_activity_container_match(struct demo_connection *conn,
    struct demo_activity_match_state *match_state, bool ignore_context_rights)
{
	struct container_queue *read_q = &conn->read_queue;
	struct tlmsp_cfg_match *match = &match_state->activity->match;
	struct container_queue_entry *entry;
	struct container_queue_range *match_range = &match_state->match_range;
	size_t offset = 0;
	bool match_found;

	if (match->container.type == TLMSP_CFG_MATCH_CONTAINER_NONE)
		return (false);

	match_found = false;
	for (entry = container_queue_head_entry(read_q);
	     entry != NULL; entry = entry->next) {
		if (!ignore_context_rights &&
		    !match_state->contexts[TLMSP_container_context(entry->container)])
			continue;

		if (entry->container_number > match_state->containers_inspected)
			match_state->containers_inspected = entry->container_number;
		
		switch (match->container.type) {
		case TLMSP_CFG_MATCH_CONTAINER_NONE:
			/* unreachable */
			match_found = false;
			break;
		case TLMSP_CFG_MATCH_CONTAINER_N:
			demo_conn_log(5, conn, "Checking container count match "
			    "(%"PRIu64" ?= %" PRIu64")", entry->container_number,
			    match->container.param.n);

			if (entry->container_number == match->container.param.n) {
				demo_conn_log(4, conn, "Found container number match");
				match_found = true;
			}
			break;
		case TLMSP_CFG_MATCH_CONTAINER_PROBABILITY:
			demo_conn_log(5, conn, "Checking container probability "
			    "match (%f ?< %f) ", (double)match_state->containers_matched,
			    match->container.param.p * match_state->containers_inspected);

			if ((double)match_state->containers_matched <
			    (match->container.param.p * match_state->containers_inspected)) {
				demo_conn_log(4, conn, "Found container probability match");
				match_found = true;
			}
			break;
		case TLMSP_CFG_MATCH_CONTAINER_ALL:
			demo_conn_log(4, conn, "Found all-containers match");
			match_found = true;
			break;
		}

		if (match_found) {
			demo_conn_log(5, conn, "Match found at offset %zu", offset);
			match_state->containers_matched++;
			match_range->first = entry;
			match_range->first_offset = 0;
			match_range->last = entry;
			match_range->last_remainder = 0;
			match_state->match_offset = offset;
			return (true);
		}

		offset += entry->length;
	}

	return (false);
}

static bool
demo_activity_pattern_match(struct demo_connection *conn,
    struct demo_activity_match_state *match_state)
{
	struct container_queue *read_q = &conn->read_queue;
	struct tlmsp_cfg_match *match = &match_state->activity->match;
	struct container_queue_range *match_range = &match_state->match_range;
	struct container_queue_entry *entry, *first, *last;
	struct match_groups *match_groups;
	struct match_group *group;
	struct container_queue_range search_range;	
	uint8_t *search_buf;
	size_t first_offset, offset;
	size_t search_len, match_len, match_offset;
	bool data_spans_end_of_queue;
	bool match_found;
	
	if (match->pattern.type == TLMSP_CFG_MATCH_PATTERN_NONE)
		return (false);

	/*
	 * Find the first accessible container, then find the end of the
	 * contiguous run of accessible containers starting at that point.
	 */
	first_offset = 0;
	for (entry = container_queue_head_entry(read_q);
	     entry != NULL; entry = entry->next) {
		if (match_state->contexts[TLMSP_container_context(entry->container)])
			break;
		first_offset += entry->length;
	}
	if (entry == NULL) {
		demo_conn_log(5, conn, "Pattern match found no accessible containers");
		return (false);
	}
	first = entry;
	last = first; /* to satisfy compiler - loop will always set it */
	for (entry = first; entry != NULL; entry = entry->next) {
		/*
		 * If this is the last entry in the queue or the next one is
		 * inaccessible, then it is the last accessible.
		 */
		if ((entry->next == NULL) ||
		    (!match_state->contexts[TLMSP_container_context(entry->next->container)])) {
			last = entry;
			break;
		}
	}
	data_spans_end_of_queue = (last->next == NULL);

	search_range.first = first;
	search_range.first_offset = 0;
	search_range.last = last;
	search_range.last_remainder = 0;
	if (!demo_activity_queue_range_to_buffer(&search_range, &search_buf,
		&search_len)) {
		demo_conn_print_error(conn,
		    "Failed to create pattern search buffer");
		return (false);
	}

	match_found = false;
	switch (match->pattern.type) {
	case TLMSP_CFG_MATCH_PATTERN_NONE:
		/* unreachable */
		break;
	case TLMSP_CFG_MATCH_PATTERN_DATA:
	case TLMSP_CFG_MATCH_PATTERN_FILE:
	{
		struct tlmsp_cfg_buf *pattern_buf;
		uint8_t *result;

		/*
		 * If file, it was been loaded into the pattern buffer at
		 * startup, so both file and data pattern matches proceed
		 * the same.
		 */
		pattern_buf = &match->pattern.param.data;
		demo_conn_log(5, conn, "Checking fixed pattern match "
		    "(search_len=%zu, pattern_len=%zu)", search_len,
		    pattern_buf->len);

		/* zero length patterns are considered to never match */
		if (pattern_buf->len == 0)
			goto out;

		result = memmem(search_buf, search_len, pattern_buf->p,
		    pattern_buf->len);
		if (result != NULL) {
			demo_conn_log(4, conn, "Found static pattern match");
			match_found = true;
			match_offset = result - search_buf;
			match_len = pattern_buf->len;

			match_groups = &match_state->match_groups;
			match_groups->num_groups = 1;
			match_groups->groups = malloc(sizeof(*match_groups->groups));
			group = &match_groups->groups[0];
			group->len = match_len;
			group->p = malloc(match_len);
			if (group->p == NULL) {
				match_found = false;
				demo_activity_free_match_groups(match_groups);
				break;
			}
			/* XXX could avoid the alloc and copy here*/
			memcpy(group->p, pattern_buf->p, group->len);
		}
		break;
	}
	case TLMSP_CFG_MATCH_PATTERN_REGEX:
	{
		pcre2_match_data *match_data;
		PCRE2_SIZE *output;
		int num_match_groups;
		int i;
		
		demo_conn_log(5, conn, "Checking regex match (search_len=%zu, "
		    "pattern=%s)", search_len, match->pattern.param.s);

		match_data = pcre2_match_data_create_from_pattern(
		    match->pattern.param.regex,
		    NULL);
		if (match_data == NULL) {
			demo_conn_print_error(conn,
			    "Failed to create regex result buffer");
			return (false);
		}
		num_match_groups = pcre2_match(match->pattern.param.regex,
		    search_buf, search_len, 0, 0, match_data, NULL);
		if (num_match_groups > 0) {
			demo_conn_log(4, conn, "Found regex match with %d groups",
			    num_match_groups);
			match_found = true;
			output = pcre2_get_ovector_pointer(match_data);
			match_offset = output[0];
			match_len = output[1] - output[0];

			/* build match groups */
			match_groups = &match_state->match_groups;
			match_groups->num_groups = num_match_groups;
			match_groups->groups = malloc(num_match_groups *
			    sizeof(*match_groups->groups));
			if (match_groups->groups != NULL) {
				for (i = 0; i < num_match_groups; i++) {
					group = &match_groups->groups[i];
					group->len =
					    output[2 * i + 1] - output[2 * i];
					group->p = malloc(group->len);
					if (group->p == NULL) {
						match_found = false;
						demo_activity_free_match_groups(
						    match_groups);
						break;
					}
					memcpy(group->p,
					    search_buf + output[2 * i],
					    group->len);
				}
			}
		}
		pcre2_match_data_free(match_data);
		break;
	}
	}
	
	if (match_found) {
		/*
		 * Set up the match result range
		 */
		offset = 0;
		for (entry = first; entry != last->next; entry = entry->next) {
			if ((match_offset >= offset) &&
			    (match_offset < (offset + entry->length))) {
				match_range->first = entry;
				match_range->first_offset = match_offset - offset;
			}
			if (((match_offset + match_len) > offset) &&
			    ((match_offset + match_len) <= (offset + entry->length))) {
				match_range->last = entry;
				match_range->last_remainder =
				    entry->length - (match_offset + match_len - offset);
			}
			offset += entry->length;
		}
		match_state->match_offset = first_offset + offset;
	}

out:
	free(search_buf);
	return (match_found);
}

static void
demo_activity_free_match_groups(struct match_groups *groups)
{
	struct match_group *group;
	unsigned int i;

	for (i = 0; i < groups->num_groups; i++) {
		group = &groups->groups[i];
		if (group->p != NULL)
			free(group->p);
	}
	free(groups->groups);
	groups->num_groups = 0;
	groups->groups = NULL;
}

bool
demo_activity_compile_regex(const struct tlmsp_cfg *cfg)
{
	struct tlmsp_cfg_activity *activity;
	struct tlmsp_cfg_match *match;
	pcre2_code *re;
	PCRE2_SIZE erroffset;
	int errcode;
	unsigned int i;
	char errbuf[160];
	
	for (i = 0; i < cfg->num_activities; i++) {
		activity = &cfg->activities[i];
		match = &activity->match;

		if (match->pattern.type != TLMSP_CFG_MATCH_PATTERN_REGEX)
			continue;

		re = pcre2_compile(
		    (PCRE2_SPTR8)match->pattern.param.s,
		    PCRE2_ZERO_TERMINATED,
		    PCRE2_ALT_BSUX | /* JavaScript-like treatment of \U \u \x */
		    PCRE2_DOLLAR_ENDONLY | /* $ matches the end of the search string only */
		    PCRE2_DOTALL, /* dot matches any character, including newline chars */
		    &errcode, &erroffset, NULL);
		if (re == NULL) {
			pcre2_get_error_message(errcode, (PCRE2_UCHAR8 *)errbuf,
			    sizeof(errbuf));
			demo_print_error("Regex compile failed: pattern '%s', "
			    "offset %u: %s", match->pattern.param.s, errcode,
			    erroffset, errbuf);
			return (false);
		}
		match->pattern.param.regex = re;
	}

	return (true);
}

void
demo_activity_free_regex(const struct tlmsp_cfg *cfg)
{
	struct tlmsp_cfg_activity *activity;
	struct tlmsp_cfg_match *match;
	unsigned int i;
	
	for (i = 0; i < cfg->num_activities; i++) {
		activity = &cfg->activities[i];
		match = &activity->match;

		if (match->pattern.type != TLMSP_CFG_MATCH_PATTERN_REGEX)
			continue;

		pcre2_code_free(match->pattern.param.regex);
	}
}

static bool
demo_activity_queue_range_to_buffer(struct container_queue_range *range,
    uint8_t **buf, size_t *len)
{
	struct container_queue_entry *entry;
	uint8_t *p;
	const uint8_t *src;
	size_t size, offset;

	size = 0;
	for (entry = range->first;
	     entry != range->last->next; entry = entry->next) {
		size += entry->length;
	}
	size -= (range->first_offset + range->last_remainder);

	p = malloc(size);
	if (p == NULL)
		return (false);

	offset = 0;
	size = range->first->length - range->first_offset;
	if (range->first == range->last)
		size -= range->last_remainder;
	src = TLMSP_container_get_data(range->first->container);
	memcpy(p, &src[range->first_offset], size);
	offset += size;
	if (range->first == range->last)
		goto out;

	for (entry = range->first->next; entry != range->last; entry = entry->next) {
		size = entry->length;
		memcpy(&p[offset], TLMSP_container_get_data(entry->container),
		    size);
		offset += size;
	}

	size = range->last->length;
	memcpy(&p[offset],
	    TLMSP_container_get_data(range->last->container),
	    size);
	offset += size;

out:
	*buf = p;
	*len = offset;
	return (true);
}

static bool
demo_activity_apply_match_actions(struct demo_connection *inbound_conn,
    struct demo_activity_match_state *match_state)
{
	struct tlmsp_cfg_activity *activity = match_state->activity;
	struct container_queue_range *match_range = &match_state->match_range;
	struct demo_connection *outbound_conn;
	uint8_t *match_buf;
	size_t match_buf_len;
	bool is_endpoint;

	demo_conn_log(5, inbound_conn, "match range: container %"PRIu64" offset "
	    "%zu to container %"PRIu64" remainder %zu",
	    match_range->first->container_number,
	    match_range->first_offset,
	    match_range->last->container_number,
	    match_range->last_remainder);

	if (activity->present) {
		if (activity->match.pattern.type != TLMSP_CFG_MATCH_PATTERN_NONE) {
			if (!demo_activity_queue_range_to_buffer(match_range,
				&match_buf, &match_buf_len))
				demo_conn_present(inbound_conn,
				    "Activity %s pattern-matched <data unavailable>",
				    activity->tag);
			else
				demo_conn_present_buf(inbound_conn, match_buf,
				    match_buf_len, true, "Activity %s pattern-matched",
				    activity->tag);
		} else if (activity->match.container.type != TLMSP_CFG_MATCH_CONTAINER_NONE) {
			if (match_range->first == match_range->last)
				demo_conn_present(inbound_conn,
				    "Activity %s matched container %" PRIu64,
				    activity->tag, match_range->first->container_number);
			else
				demo_conn_present(inbound_conn,
				    "Activity %s matched containers %" PRIu64 " to %" PRIu64,
				    activity->tag, match_range->first->container_number,
				    match_range->last->container_number);
		}
	}

	is_endpoint = (inbound_conn->splice == NULL);
	outbound_conn = demo_activity_get_dataflow_conn(inbound_conn, false);
        if(!activity->match.forward)
        {
		if (!demo_activity_drop_or_forward_match_preamble(outbound_conn,
			&inbound_conn->read_queue, &outbound_conn->write_queue,
			match_range, is_endpoint)) {
			return (false);
		}
        }

	if (!demo_activity_apply_actions(inbound_conn, activity,
		&match_state->match_groups, true, true))
		return (false);

        if(!activity->match.forward)
        {
		if (!demo_activity_drop_or_delete_match(outbound_conn,
			&inbound_conn->read_queue, &outbound_conn->write_queue,
			match_range, is_endpoint)) {
			return (false);
		}
        }

        if(activity->match.forward)
        {
		if (!demo_activity_forward_match(outbound_conn,
                                                 &inbound_conn->read_queue, &outbound_conn->write_queue,
                                                 match_range)) {
			return (false);
		}
        }
	return (true);
}

static bool
demo_activity_apply_actions(struct demo_connection *activity_conn,
    struct tlmsp_cfg_activity *activity, struct match_groups *match_groups,
    bool sends, bool replies)
{
	struct tlmsp_cfg_action *action;
	struct demo_connection *send_conn, *reply_conn;
	struct demo_connection *outbound_conn;
	unsigned int i;

	send_conn = demo_activity_get_dataflow_conn(activity_conn, false);
	reply_conn = demo_activity_get_dataflow_conn(activity_conn, true);
	for (i = 0; i < activity->num_actions; i++) {
		action = &activity->actions[i];

		/* XXX fault support */

		if (TLMSP_CFG_PAYLOAD_ENABLED(&action->send)) {
			/* Skip types that aren't to be evaluated */
			if (!((sends && !action->send.reply) ||
				(replies && action->send.reply)))
				continue;

			demo_conn_log(5, activity_conn, "Applying '%s' action",
			    action->send.reply ? "reply" : "send");
			outbound_conn = action->send.reply ?
			    reply_conn : send_conn;
			if (!demo_activity_queue_payload(outbound_conn,
				&action->send, match_groups, activity->present))
				return (false);
		} else if (TLMSP_CFG_PAYLOAD_ENABLED(&action->log)) {
			demo_conn_log(5, activity_conn, "Applying log action");
			if (!demo_activity_log_payload(send_conn,
				&action->log, match_groups, activity->present))
				return (false);
		} else if (action->alert.level != TLMSP_CFG_ACTION_ALERT_LEVEL_NONE) {
			if (!demo_activity_queue_alert(send_conn,
				&action->alert, activity->present))
				return (false);
		} else if (action->renegotiate) {
			if (!SSL_renegotiate_abbreviated(activity_conn->ssl)) {
				demo_conn_print_error_ssl_errq(activity_conn,
				    "Failed to schedule a renegotiation");
				return (false);
			}
		} else if (action->shutdown) {
			/*
			 * This will put the SSL into a state where our next
			 * attempt to read a container will return the
			 * appropriate WANT_WRITE, and we will transition into
			 * flushing the write part of the BIO.  Therefore, we
			 * just ignore any error here.
			 *
			 * We could narrow it to just ignore the expected
			 * errors.
			 */
			(void)SSL_shutdown(activity_conn->ssl);
		}
	}

	return (true);
}

static bool
demo_activity_forward_match(struct demo_connection *log_conn,
    struct container_queue *read_q, struct container_queue *write_q,
    struct container_queue_range *match_range)
{
	TLMSP_Container *container;

	demo_conn_log(5, log_conn, "Forward match preamble and contents");

	while (true) {
		container = container_queue_head(read_q);
		container_queue_remove_head(read_q);
		demo_conn_log(5, log_conn, "Forwarding container "
		    "(context=%u, length=%zu)",
		    TLMSP_container_context(container),
		    TLMSP_container_length(container));
		if (!container_queue_add(write_q, container)) {
			demo_conn_print_error(log_conn,
			    "Failed to add container to write queue");
			return (false);
		}
		if(container == match_range->last->container)
			break;
	}

	return (true);
}

static bool
demo_activity_drop_or_forward_match_preamble(struct demo_connection *log_conn,
    struct container_queue *read_q, struct container_queue *write_q,
    struct container_queue_range *match_range, bool drop)
{
	SSL *read_q_ssl = read_q->conn->ssl;
	TLMSP_Container *container, *new_container;
	const uint8_t *src;

	if (drop)
		demo_conn_log(5, log_conn, "Drop match preamble");
	else
		demo_conn_log(5, log_conn, "Forward match preamble");

	/*
	 * Drop or forward all containers ahead of the first match
	 * container.
	 */
	container = container_queue_head(read_q);
	while (container != match_range->first->container) {
		container_queue_remove_head(read_q);
		demo_conn_log(5, log_conn, "%s preamble container "
		    "(context=%u, length=%zu)",
		    drop ? "Freeing" : "Forwarding",
		    TLMSP_container_context(container),
		    TLMSP_container_length(container));
		if (drop)
			TLMSP_container_free(read_q_ssl, container);
		else if (!container_queue_add(write_q, container)) {
			demo_conn_print_error(log_conn,
			    "Failed to add preamble container to write queue");
			return (false);
		}
		container = container_queue_head(read_q);
	}

	/*
	 * If the match does not cover the entire first match container,
	 * remove the preamble data, possibly forwarding it.
	 */
	if (match_range->first_offset != 0) {
		container = container_queue_remove_head(read_q);
		src = TLMSP_container_get_data(container);

		/*
		 * Create a new container with the preamble data removed.
		 */
		if (!TLMSP_container_create(read_q_ssl, &new_container,
			TLMSP_container_context(container),
			&src[match_range->first_offset],
			TLMSP_container_length(container) -
			match_range->first_offset)) {
			demo_conn_print_error_ssl_errq(log_conn,
				    "Failed to create new container without "
			    "match preamble data");
			return (false);
		}

		if (drop) {
			demo_conn_log(5, log_conn, "Freeing preamble/match "
			    "container (context=%u, length=%zu)",
			    TLMSP_container_context(container),
			    TLMSP_container_length(container));
			TLMSP_container_free(read_q_ssl, container);
		} else {
			/*
			 * Modify container so it only has the preamble data
			 * in it and forward it.
			 */
			TLMSP_container_set_data(container, src,
			    match_range->first_offset);
			if (!container_queue_add(write_q, container)) {
				demo_conn_print_error(log_conn,
				    "Failed to add modified container with "
				    "preamble data to outbound write queue");
				return (false);
			}
		}

		/*
		 * Add the new container that does not contain the preamble
		 * data to the head of the queue and adjust the match range
		 * to begin with it.
		 */
		container_queue_remove_head(read_q);
		demo_conn_log(5, log_conn, "Adding first match container "
		    "with preamble data stripped back to head of read queue "
		    "(context=%u, length=%zu)",
		    TLMSP_container_context(new_container),
		    TLMSP_container_length(new_container));
		container_queue_add_head(read_q, new_container);
		if(match_range->last==match_range->first)
			match_range->last = container_queue_head_entry(read_q);
		match_range->first = container_queue_head_entry(read_q);
		match_range->first_offset = 0;
	}

	/*
	 * match_range->first_offset is always zero at this point.
	 */
	return (true);
}

static bool
demo_activity_drop_or_delete_match(struct demo_connection *log_conn,
    struct container_queue *read_q, struct container_queue *write_q,
    struct container_queue_range *match_range, bool drop)
{
	SSL *read_q_ssl = read_q->conn->ssl;
	TLMSP_Container *container;
	const uint8_t *src;
	size_t delete_bytes;
	
	demo_conn_log(5, log_conn, "Drop all to end of match");

	/*
	 * At this point, the head of the read queue contains match data
	 * beginning with the first byte in the container.  Drop or delete
	 * all containers in the queue that consist only of match data.
	 */
	container = container_queue_head(read_q);
	while ((container != NULL) &&
	      ((container != match_range->last->container) ||
		  (match_range->last_remainder == 0))) {
		container_queue_remove_head(read_q);
		if (drop) {
			demo_conn_log(5, log_conn, "Freeing match container "
			    "(context=%u, length=%zu)",
			    TLMSP_container_context(container),
			    TLMSP_container_length(container));
			TLMSP_container_free(read_q_ssl, container);
		} else {
			demo_conn_log(5, log_conn, "Deleting match container "
			    "(context=%u, length=%zu)",
			    TLMSP_container_context(container),
			    TLMSP_container_length(container));
			if (!TLMSP_container_delete(read_q_ssl, container)) {
				demo_conn_print_error_ssl_errq(log_conn,
				    "Failed to delete match container");
				return (false);
			}
			if (!container_queue_add(write_q, container)) {
				demo_conn_print_error(log_conn,
				    "Failed to add deleted match container to "
				    "write queue");
				return (false);
			}
		}
		if (container == match_range->last->container)
			break;
		container = container_queue_head(read_q);
	}

	/*
	 * If the match does not cover the entire last container, remove the
	 * match data from that container, leaving the rest in the queue.
	 */
	if (match_range->last_remainder != 0) {
		demo_conn_log(5, log_conn, "Modifying last match container to "
		    "contain only post-match tail data (context=%u, length=%zu)",
		    TLMSP_container_context(container),
		    match_range->last_remainder);
		container = container_queue_remove_head(read_q);
		src = TLMSP_container_get_data(container);
		delete_bytes = TLMSP_container_length(container) -
		    match_range->last_remainder;
		TLMSP_container_set_data(container, &src[delete_bytes],
		    match_range->last_remainder);
		if (!container_queue_add_head(read_q, container)) {
			demo_conn_print_error(log_conn,
			    "Failed to add modified container with post-match "
			    "tail data back to head of queue");
			return (false);
		}
	}

	return (true);
}

/*
 * Return the dataflow partner connection for the given connection for to
 * the given category of action (replies == true/false).  This answers
 * 'where does this type of read on conn send writes to' and 'writes of this
 * type on conn come from reads on what other conn?'
 */
static struct demo_connection *
demo_activity_get_dataflow_conn(struct demo_connection *conn, bool replies)
{
	struct demo_splice *splice = conn->splice;
	
	if (splice != NULL) {
		if (replies)
			return (conn);
		else
			return (conn->other_side);
	} else
		return (conn);
}

