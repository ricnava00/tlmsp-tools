/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBDEMO_PKI_H_
#define _LIBDEMO_PKI_H_

struct SSL_CTX;

char *demo_pki_get_public_dir(void);
char *demo_pki_get_public_path(const char *initial_path);
char *demo_pki_get_private_dir(void);
char *demo_pki_get_private_path(const char *initial_path);

bool demo_pki_set_key_and_certificate(SSL_CTX *ctx, const char *key_path,
                                      const char *cert_path);

#endif /* _LIBDEMO_PKI_H_ */
