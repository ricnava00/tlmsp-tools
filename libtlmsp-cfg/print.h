/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _PRINT_H_
#define _PRINT_H_


int indent_print(int fd, unsigned int indent, const char *format, ...);
void print_context(int fd, unsigned int indent,
                   const struct tlmsp_cfg_context *cfg);
void print_activity(int fd, unsigned int indent,
                    const struct tlmsp_cfg_activity *cfg);
void print_client(int fd, unsigned int indent,
                  const struct tlmsp_cfg_client *cfg);
void print_server(int fd, unsigned int indent,
                  const struct tlmsp_cfg_server *cfg);
void print_middlebox(int fd, unsigned int indent,
                     const struct tlmsp_cfg_middlebox *cfg);

#endif /* _PRINT_H_ */
