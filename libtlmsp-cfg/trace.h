/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _TRACE_H_
#define _TRACE_H_

#ifdef TRACE_ENABLED
#include <stdio.h>

#define TRACE_RAW(...)	printf(__VA_ARGS__)
#define TRACE(...)					\
	do {						\
		printf("%32s: ", __func__);		\
		TRACE_RAW(__VA_ARGS__);			\
	} while (0)
#else
#define TRACE_RAW(...)
#define TRACE(...)
#endif

#endif /* _TRACE_H_ */
