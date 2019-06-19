/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBDEMO_SIGNAL_H_
#define _LIBDEMO_SIGNAL_H_

#include <ev.h>


void demo_signal_handling_init(void);
void demo_signal_monitor_start(EV_P);

#endif /* _LIBDEMO_SIGNAL_H_ */
