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
	bool contexts[TLMSP_CONTEXT_ID_MAX + 1];
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


static bool demo_activity_queue_initial(struct demo_connection *conn,
                                        struct tlmsp_cfg_activity **activities,
                                        unsigned int num_activities,
                                        bool replies);
static bool demo_activity_set_up_time_triggered(struct demo_connection *conn,
                                                struct tlmsp_cfg_activity **activities,
                                                unsigned int num_activities,
                                                bool replies);
static void demo_activity_get_activities(struct demo_connection *conn,
                                         bool replies,
                                         struct tlmsp_cfg_activity ***activities,
                                         unsigned int *num_activities);
static bool demo_activity_queue_payload(struct demo_connection *conn,
                                        struct tlmsp_cfg_payload *payload,
                                        struct match_groups *match_groups,
                                        bool create_if_empty);
static bool demo_activity_add_time_triggered_message(struct demo_connection *conn,
                                                     struct tlmsp_cfg_payload *payload,
                                                     ev_tstamp at, ev_tstamp every,
                                                     bool create_if_empty);
static void demo_activity_time_triggered_cb(EV_P_ ev_timer *w, int revents);
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
                                              const uint8_t **buf, size_t *len);
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
static bool demo_activity_apply_match_action(struct demo_connection *inbound_conn,
                                             struct demo_activity_match_state *match_state);
static bool demo_activity_apply_match_delete_drop_or_forward(struct demo_connection *log_conn,
                                                             struct container_queue *read_q,
                                                             struct container_queue *write_q,
                                                             struct container_queue_range *match_range,
                                                             bool drop_all, bool delete_match);
static struct demo_connection *demo_activity_get_dataflow_conn(struct demo_connection *conn,
                                                               bool replies);


/*
 * Determine if there are any containers that are to be initially sent on
 * this connection, and if so, add them to the write queue.
 */
bool
demo_activity_conn_queue_initial(struct demo_connection *conn)
{
	struct tlmsp_cfg_activity **activities;
	unsigned int num_activities;

	demo_activity_get_activities(conn, false, &activities, &num_activities);
	if (!demo_activity_queue_initial(conn, activities, num_activities, false))
		return (false);

	if (conn->splice != NULL) {
		/*
		 * Middleboxes have an 'other side' for each connection that
		 * initial data can be queued to.  If the other side
		 * connection has any initial reply activities, queue them
		 * to this connection now.
		 */
		demo_activity_get_activities(conn, true, &activities,
		    &num_activities);
		if (!demo_activity_queue_initial(conn->other_side, activities,
			num_activities, true))
			return (false);
	}

	return (true);
}

static bool
demo_activity_queue_initial(struct demo_connection *conn,
    struct tlmsp_cfg_activity **activities, unsigned int num_activities,
    bool replies)
{
	struct tlmsp_cfg_activity *activity;
	unsigned int i;

	for (i = 0; i < num_activities; i++) {
		activity = activities[i];
		if (!activity->match.initial)
			continue;

		if (replies) {
			if (!demo_activity_queue_payload(conn,
				&activity->action.reply, NULL, true))
				return (false);
		} else {
			if (!demo_activity_queue_payload(conn,
				&activity->action.before, NULL, true))
				return (false);
			if (!demo_activity_queue_payload(conn,
				&activity->action.replace, NULL, false))
				return (false);
			if (!demo_activity_queue_payload(conn,
				&activity->action.after, NULL, true))
				return (false);
		}
	}

	return (true);
}

/*
 * Determine if there are any containers that are to be sent on this
 * connection on a time-triggered basis, and if so, set up timers for them.
 */
bool
demo_activity_conn_set_up_time_triggered(struct demo_connection *conn)
{
	struct tlmsp_cfg_activity **activities;
	unsigned int num_activities;

	demo_activity_get_activities(conn, false, &activities, &num_activities);
	if (!demo_activity_set_up_time_triggered(conn, activities, num_activities,
		false))
		return (false);

	if (conn->splice != NULL) {
		/*
		 * Middleboxes have an 'other side' for each connection that
		 * messages can be sent on.  If the other side connection
		 * has any time-triggered activities, set them up for this
		 * connection now.
		 */
		demo_activity_get_activities(conn, true, &activities,
		    &num_activities);
		if (!demo_activity_set_up_time_triggered(conn->other_side,
			activities, num_activities, true))
			return (false);
	}

	return (true);
}

void
demo_activity_conn_tear_down_time_triggered(struct demo_connection *conn)
{
	struct ev_loop *loop = conn->loop;
	struct demo_time_triggered_msg *msg, *next;

	msg = conn->time_triggered_messages;
	while (msg != NULL) {
		next = msg->next;
		ev_timer_stop(EV_A_ &msg->timer);
		if (msg->free_data)
			free((void *)msg->p);
		free(msg);
		msg = next;
	}
}

bool
demo_activity_conn_start_time_triggered(struct demo_connection *conn)
{
	struct ev_loop *loop = conn->loop;
	struct demo_time_triggered_msg *msg;

	msg = conn->time_triggered_messages;
	while (msg != NULL) {
		ev_timer_start(EV_A_ &msg->timer);
		msg = msg->next;
	}

	return (true);
}

static bool
demo_activity_set_up_time_triggered(struct demo_connection *conn,
    struct tlmsp_cfg_activity **activities, unsigned int num_activities,
    bool replies)
{
	struct tlmsp_cfg_activity *activity;
	unsigned int i;
	ev_tstamp at, every;
	
	for (i = 0; i < num_activities; i++) {
		activity = activities[i];

		/*
		 * skip non-time triggered messages and initial-only time-
		 * triggered messages
		 */
		if ((activity->match.at == 0.0) && (activity->match.every == 0.0))
			continue;

		at = activity->match.at;
		every = activity->match.every;
		if (replies) {
			if (!demo_activity_add_time_triggered_message(conn,
				&activity->action.reply, at, every, true))
				return (false);
		} else {
			if (!demo_activity_add_time_triggered_message(conn,
				&activity->action.before, at, every, true))
				return (false);
			if (!demo_activity_add_time_triggered_message(conn,
				&activity->action.replace, at, every, false))
				return (false);
			if (!demo_activity_add_time_triggered_message(conn,
				&activity->action.after, at, every, true))
				return (false);
		}
	}

	return (true);
}

/*
 * For the given connection, retrieve the list of activities that can send
 * data on it via time triggers or send-* actions (replies == false) or via
 * reply actions (replies == true).  The replies == true case only applies
 * to splices, as non-splices can only send via time triggers or send-*.
 */
static void
demo_activity_get_activities(struct demo_connection *conn, bool replies,
    struct tlmsp_cfg_activity ***activities, unsigned int *num_activities)
{
	struct demo_connection *source_conn;

	source_conn = demo_activity_get_dataflow_conn(conn, replies);

	*activities = source_conn->activities;
	*num_activities = source_conn->num_activities;
}

static bool
demo_activity_queue_payload(struct demo_connection *conn,
    struct tlmsp_cfg_payload *payload, struct match_groups *match_groups,
    bool create_if_empty)
{

	struct container_queue *q = &conn->write_queue;
	TLMSP_Container *container;
	const uint8_t *data;
	size_t len;
	size_t offset;
	size_t remaining;
	size_t container_len;
	bool result;
	bool free_data;

	if (payload->type == TLMSP_CFG_PAYLOAD_NONE)
		return (true);

	data = NULL;
	free_data = false;
	result = false;
	if (!demo_activity_get_payload_data(conn, payload, match_groups, &data,
		&len, &free_data))
		goto out;

	if ((len != 0) || create_if_empty) {
		offset = 0;
		remaining = len;
		do {
			if (remaining > MAX_CONTAINER_SIZE)
				container_len = MAX_CONTAINER_SIZE;
			else
				container_len = remaining;
			if (!TLMSP_container_create(q->ssl, &container,
				payload->context->id, &data[offset],
				container_len)) {
				demo_conn_print_error_ssl_errq(conn,
				    "Failed to create container for payload");
				goto out;
			}

			if (!container_queue_add(q, container)) {
				demo_conn_print_error(conn,
				    "Failed to add payload container to queue\n");
				TLMSP_container_free(q->ssl, container);
				goto out;
			}
			demo_conn_log(3, conn, "Queued container (length=%u) in "
			    "context %u", container_len, payload->context->id);

			offset += container_len;
			remaining -= container_len;
		} while (remaining > 0);
	}

	result = true;

out:
	if ((data != NULL) && free_data)
		free((void *)data);
	return (result);
}


static bool
demo_activity_add_time_triggered_message(struct demo_connection *conn,
    struct tlmsp_cfg_payload *payload, ev_tstamp at, ev_tstamp every,
    bool create_if_empty)
{
	struct demo_time_triggered_msg *msg;
	const uint8_t *data;
	size_t len;
	bool result;
	bool free_data;

	if (payload->type == TLMSP_CFG_PAYLOAD_NONE)
		return (true);

	data = NULL;
	free_data = false;
	result = false;
	if (!demo_activity_get_payload_data(conn, payload, NULL, &data, &len,
		&free_data))
		goto out;

	if ((len != 0) || create_if_empty) {
		msg = calloc(1, sizeof(*msg));
		if (msg == NULL)
			goto out;

		msg->conn = conn;
		ev_timer_init(&msg->timer, demo_activity_time_triggered_cb,
		    (at == 0.0) ? every : at, 0.0);
		msg->timer.data = msg;
		msg->interval = every;
		msg->context_id = payload->context->id;
		msg->p = data;
		msg->len = len;
		msg->free_data = free_data;

		if (every == 0.0)
			demo_conn_log(3, conn, "adding on-shot message at %u ms "
			    "(length=%u) in context %u", (unsigned int)(at * 1000.0),
			    len, msg->context_id);
		else
			demo_conn_log(3, conn, "adding periodic message at %u ms, "
			    "period %u ms (length=%u) in context %u",
			    (unsigned int)(((at == 0.0) ? every : at) * 1000.0),
			    (unsigned int)(every * 1000.0), len, msg->context_id);

		if (conn->time_triggered_messages == NULL)
			conn->time_triggered_messages = msg;
		else {
			msg->next = conn->time_triggered_messages;
			conn->time_triggered_messages = msg;
		}
	}

	result = true;

out:
	if (!result && (data != NULL) && free_data)
		free((void *)data);
	return (result);
}

static void
demo_activity_time_triggered_cb(EV_P_ ev_timer *w, int revents)
{
	struct demo_time_triggered_msg *msg = w->data;
	struct demo_connection *conn = msg->conn;
	TLMSP_Container *container;
	size_t offset;
	size_t remaining;
	size_t container_len;

	offset = 0;
	remaining = msg->len;
	do {
		if (remaining > MAX_CONTAINER_SIZE)
			container_len = MAX_CONTAINER_SIZE;
		else
			container_len = remaining;

		if (!TLMSP_container_create(conn->ssl, &container,
			msg->context_id, &msg->p[offset], container_len)) {
			demo_conn_print_error_ssl_errq(conn, "Failed to create "
			    "container for time-triggered message");
			return;
		}

		if (!container_queue_add(&conn->write_queue, container)) {
			demo_conn_print_error(conn,
			    "Failed to add time-triggered container to queue\n");
			TLMSP_container_free(conn->ssl, container);
			return;
		}
		demo_conn_log(3, conn, "Queued time-triggered container "
		    "(length=%u) in context %u", container_len, msg->context_id);

		offset += container_len;
		remaining -= container_len;
	} while (remaining > 0);

	demo_connection_stop_io(conn);
	demo_connection_wait_for(conn, EV_WRITE);
	demo_connection_resume_io(conn);

	if (msg->interval != 0.0) {
		w->repeat = msg->interval;
		ev_timer_again(EV_A_ w);
	}
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
			match_groups, buf, len))
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

static bool
demo_activity_run_payload_handler(struct demo_connection *log_conn,
    struct tlmsp_cfg_payload *payload, struct match_groups *match_groups,
    const uint8_t **buf, size_t *len)
{
	int stdin_pipe[2];  /* handler's stdin */
	int stdout_pipe[2]; /* handler's stdout */
	int stderr_pipe[2]; /* handler's stderr */
	pid_t child_pid;
	
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

	printf("stdin READ(%u)=%d WRITE(%u)=%d\n", PIPE_READ_FD, stdin_pipe[PIPE_READ_FD], PIPE_WRITE_FD, stdin_pipe[PIPE_WRITE_FD]);
	printf("stdout READ(%u)=%d WRITE(%u)=%d\n", PIPE_READ_FD, stdout_pipe[PIPE_READ_FD], PIPE_WRITE_FD, stdout_pipe[PIPE_WRITE_FD]);
	printf("stderr READ(%u)=%d WRITE(%u)=%d\n", PIPE_READ_FD, stderr_pipe[PIPE_READ_FD], PIPE_WRITE_FD, stderr_pipe[PIPE_WRITE_FD]);

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

		if (execlp("/usr/bin/stdbuf", "stdbuf", "-i0", "-o0", "-e0", "/bin/sh", "-c", payload->param.cmd, NULL) == -1) {
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
		state.out_buf = match_groups->groups[0].p;
		state.out_offset = 0;
		state.out_remaining = match_groups->groups[0].len;

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

		return (state.success);
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
			return_false = !demo_activity_apply_match_action(conn,
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

			if (entry->container_number == match->container.param.n)
				match_found = true;
			break;
		case TLMSP_CFG_MATCH_CONTAINER_PROBABILITY:
			demo_conn_log(5, conn, "Checking container probability "
			    "match (%f ?< %f) ", (double)match_state->containers_matched,
			    match->container.param.p * match_state->containers_inspected);

			if ((double)match_state->containers_matched <
			    (match->container.param.p * match_state->containers_inspected))
				match_found = true;
			break;
		case TLMSP_CFG_MATCH_CONTAINER_ALL:
			demo_conn_log(5, conn, "Matching all containers");
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
			demo_conn_log(5, conn, "Match with %d groups",
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
		demo_conn_log(5, conn, "Match found (offset=%zu, length=%zu)",
		    match_offset, match_len);
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
				    match_offset + match_len - offset;
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
		    PCRE2_ALT_BSUX, /* JavaScript-like treatment of \U \u \x */
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
demo_activity_apply_match_action(struct demo_connection *inbound_conn,
    struct demo_activity_match_state *match_state)
{
	struct tlmsp_cfg_action *action = &match_state->activity->action;
	struct container_queue_range *match_range = &match_state->match_range;
	struct demo_connection *outbound_conn_for_replies;
	struct demo_connection *outbound_conn;
	bool replaced;
	bool is_endpoint;

	/* XXX fault support */

	is_endpoint = (inbound_conn->splice == NULL);
	outbound_conn = demo_activity_get_dataflow_conn(inbound_conn, false);
	outbound_conn_for_replies = demo_activity_get_dataflow_conn(inbound_conn, true);

	if (TLMSP_CFG_PAYLOAD_ENABLED(&action->reply)) {
		demo_conn_log(5, inbound_conn, "Applying 'reply' action");
		if (!demo_activity_queue_payload(outbound_conn_for_replies,
			&action->reply, &match_state->match_groups, true))
			return (false);
	}

	if (TLMSP_CFG_PAYLOAD_ENABLED(&action->before)) {
		demo_conn_log(5, inbound_conn, "Applying 'before' action");
		if (!demo_activity_queue_payload(outbound_conn, &action->before,
			&match_state->match_groups, true))
			return (false);
	}

	replaced = false;
	if (TLMSP_CFG_PAYLOAD_ENABLED(&action->replace)) {
		demo_conn_log(5, inbound_conn, "Applying 'replace' action");
		if (!demo_activity_queue_payload(outbound_conn, &action->replace,
			&match_state->match_groups, false))
			return (false);
		replaced = true;
	}
	if (!demo_activity_apply_match_delete_drop_or_forward(outbound_conn,
		&inbound_conn->read_queue, &outbound_conn->write_queue,
		match_range, is_endpoint, replaced)) {
		return (false);
	}

	if (TLMSP_CFG_PAYLOAD_ENABLED(&action->after)) {
		demo_conn_log(5, inbound_conn, "Applying 'after' action");
		if (!demo_activity_queue_payload(outbound_conn, &action->after,
			&match_state->match_groups, true))
			return (false);
	}

	return (true);
}

static bool
demo_activity_apply_match_delete_drop_or_forward(struct demo_connection *log_conn,
    struct container_queue *read_q, struct container_queue *write_q,
    struct container_queue_range *match_range, bool drop_all,
    bool delete_match)
{
	TLMSP_Container *container, *new_container;
	const uint8_t *src;
	size_t delete_or_forward_bytes;

	if (drop_all)
		demo_conn_log(5, log_conn, "Drop all to end of match");
	else
		demo_conn_log(5, log_conn, "Forward preamble, %s match",
		    delete_match ? "delete" : "forward");

	/*
	 * If we aren't dropping all and we're deleting the match, we need a
	 * separate loop to handle the preamble.  If we are dropping all or
	 * are not deleting the match, then everything (in this case, either
	 * drop or forward) is handled in the second loop).
	 */
	if (!drop_all && delete_match) {
		container = container_queue_head(read_q);
		while (container != match_range->first->container) {
			container_queue_remove_head(read_q);
			demo_conn_log(5, log_conn, "Deleting preamble container "
			    "(context=%u, length=%zu)",
			    TLMSP_container_context(container),
			    TLMSP_container_length(container));
			if (!TLMSP_container_delete(write_q->ssl, container)) {
				demo_conn_print_error_ssl_errq(log_conn,
				    "Failed to add delete preamble container");
				return (false);
			}
			if (!container_queue_add(write_q, container)) {
				demo_conn_print_error(log_conn,
				    "Failed to add preamble container to write queue");
				return (false);
			}
			container = container_queue_head(read_q);
		}
	}
	
	/*
	 * Delete or forward all containers in the queue until we reach the
	 * match range end.
	 */
	container = container_queue_head(read_q);
	while (container != match_range->last->container) {
		container_queue_remove_head(read_q);
		if (drop_all) {
			demo_conn_log(5, log_conn, "Freeing preamble/match "
			    "container (context=%u, length=%zu)",
			    TLMSP_container_context(container),
			    TLMSP_container_length(container));
			TLMSP_container_free(write_q->ssl, container);
		} else {
			/* deleting or forwarding */
			if (delete_match) {
				demo_conn_log(5, log_conn, "Deleting preamble/match "
				    "container (context=%u, length=%zu)",
				    TLMSP_container_context(container),
				    TLMSP_container_length(container));
				if (!TLMSP_container_delete(write_q->ssl, container)) {
					demo_conn_print_error_ssl_errq(log_conn,
					    "Failed to add delete preamble/match container");
					return (false);
				}
			}
			if (!container_queue_add(write_q, container)) {
				demo_conn_print_error(log_conn,
				    "Failed to add preamble/match container to write queue");
				return (false);
			}
		}
		container = container_queue_head(read_q);
	}

	/*
	 * If the match does not cover the entire last container, split it
	 * into two containers at the match boundary and delete or forward
	 * the matched part, leaving the rest of the data in the queue for
	 * future matching.
	 */
	container = container_queue_remove_head(read_q);
	if (match_range->last_remainder != 0) {
		delete_or_forward_bytes = TLMSP_container_length(container) -
		    match_range->last_remainder;
		if (!drop_all && !delete_match) {
			if (!TLMSP_container_create(write_q->ssl,
				&new_container,
				TLMSP_container_context(container),
				TLMSP_container_get_data(container),
				delete_or_forward_bytes)) {
				demo_conn_print_error_ssl_errq(log_conn,
				    "Failed to create new container for tail "
				    "end of match data");
				return (false);
			}
			if (!container_queue_add(write_q, new_container)) {
				demo_conn_print_error(log_conn,
				    "Failed to add new container for tail end "
				    "of match data to write queue");
				return (false);
			}
		}
		/* remove leading data on container staying in queue */
		src = TLMSP_container_get_data(container); 
		TLMSP_container_set_data(container, &src[delete_or_forward_bytes],
		    match_range->last_remainder);
	} else {
		if (drop_all) {
			demo_conn_log(5, log_conn, "Freeing final match container "
			    "(context=%u, length=%zu)",
			    TLMSP_container_context(container),
			    TLMSP_container_length(container));
			TLMSP_container_free(write_q->ssl, container);
		} else {
			if (delete_match) {
				demo_conn_log(5, log_conn, "Deleting final match container "
				    "(context=%u, length=%zu)",
				    TLMSP_container_context(container),
				    TLMSP_container_length(container));
				if (!TLMSP_container_delete(write_q->ssl, container)) {
					demo_conn_print_error_ssl_errq(log_conn,
					    "Failed to delete complete container for "
					    "tail end of match data");
					return (false);
				}
			}
			if (!container_queue_add(write_q, container)) {
				demo_conn_print_error(log_conn,
				    "Failed to add complete container for tail end of "
				    "match data to write queue");
				return (false);
			}
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

