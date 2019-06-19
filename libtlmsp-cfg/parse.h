/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _PARSE_H_
#define _PARSE_H_


struct tlmsp_cfg *parse_string_or_file(const char *strarg, bool isfile,
                                       char *errbuf, size_t errbuflen);
void free_string(const char *str);

#endif /* _PARSE_H_ */
