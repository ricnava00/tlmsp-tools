/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include <ev.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "app.h"
#include "signal.h"


#ifdef HAVE_SIGINFO
#define INFO_SIGNAL	SIGINFO
#else
#define INFO_SIGNAL	SIGUSR1
#endif

#define SIGINT_MESSAGE		"\nNotifying event loop...\n"
#define MULTIPLE_SIGINT_MESSAGE	"One more SIGINT to force termination...\n"


static void demo_signal_monitor_sighandler(int signo, siginfo_t *info,
                                           void *uap);
static void demo_signal_monitor_cb(EV_P_ ev_timer *w, int revents);


static struct {
	volatile sig_atomic_t shut_down;
	volatile sig_atomic_t sigint_count;
	volatile sig_atomic_t show_info;
} demo_signal_monitor_flags;
static ev_timer demo_signal_monitor_watcher;


void
demo_signal_handling_init(void)
{
	struct sigaction sa;

	sa.sa_sigaction = demo_signal_monitor_sighandler;
	sa.sa_flags = SA_SIGINFO;
	sigfillset(&sa.sa_mask);
	sigaction(INFO_SIGNAL, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	signal(SIGPIPE, SIG_IGN);
}

static void
demo_signal_monitor_sighandler(int signo, siginfo_t *info, void *uap)
{
	struct sigaction sa;
	int rc;

	switch (signo) {
	case SIGINT:
		/*
		 * Set the flag that should cause the event loop to cleanly
		 * shut down.  Just in case the event loop machinery is not
		 * working properly, count the number of times we receive
		 * this signal, and after the threshold humber, replace this
		 * handler with the default termination handler and let the
		 * user know the next SIGINT will terminate.
		 */
		rc = write(STDERR_FILENO, SIGINT_MESSAGE, strlen(SIGINT_MESSAGE));
		demo_signal_monitor_flags.shut_down = 1;
		demo_signal_monitor_flags.sigint_count++;
		if (demo_signal_monitor_flags.sigint_count >= 2) {
			rc = write(STDERR_FILENO, MULTIPLE_SIGINT_MESSAGE,
			    strlen(MULTIPLE_SIGINT_MESSAGE));
			sa.sa_handler = SIG_DFL;
			sigfillset(&sa.sa_mask);
			sigaction(SIGINT, &sa, NULL);
		}
		(void)rc; /* gcc requires this machinery to be able to quietly ignore write() results */
		break;
	case INFO_SIGNAL:
		demo_signal_monitor_flags.show_info = 1;
		break;
	}
}

void
demo_signal_monitor_start(EV_P)
{

	ev_timer_init(&demo_signal_monitor_watcher, demo_signal_monitor_cb,
	    0.5, 0.5);
	ev_timer_start(EV_A_ &demo_signal_monitor_watcher);
}

static void
demo_signal_monitor_cb(EV_P_ ev_timer *w, int revents)
{

	if (demo_signal_monitor_flags.shut_down)
		ev_break(EV_A_ EVBREAK_ALL);
	if (demo_signal_monitor_flags.show_info) {
		demo_app_show_info_all();
		demo_signal_monitor_flags.show_info = 0;
	}
}
