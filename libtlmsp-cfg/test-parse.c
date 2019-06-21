/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#include <stdio.h>
#include <unistd.h>

#include "libtlmsp-cfg.h"

int
main(int argc, char **argv)
{
	const struct tlmsp_cfg *cfg;
	char errbuf[160];

	if (argc < 2) {
		printf("No filename given\n");
		return (1);
	}
	
	cfg = tlmsp_cfg_parse_file(argv[1], errbuf, sizeof(errbuf));
	if (cfg) {
		tlmsp_cfg_print(STDOUT_FILENO, cfg);
		tlmsp_cfg_free(cfg);
	} else
		printf("Parse failed: %s\n", errbuf);
		

	return (0);
}
