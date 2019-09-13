/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#include "pki.h"
#include "print.h"


static char *demo_pki_concat(const char *s1, const char *s2);


/*
 * NULL return means there isn't one
 */
char *
demo_pki_get_public_dir(void)
{
#ifdef LIBDEMO_PKI_DIR
	return (strdup(LIBDEMO_PKI_DIR));
#else
	return (NULL);
#endif
}

/*
 * NULL return is an error
 */
char *
demo_pki_get_public_path(const char *initial_path)
{
#ifdef LIBDEMO_PKI_DIR
	if (initial_path[0] == '/')
		return (strdup(initial_path));
	else
		return (demo_pki_concat(LIBDEMO_PKI_DIR, initial_path));
#else
	return (strdup(initial_path));
#endif
}

/*
 * NULL return means there isn't one
 */
char *
demo_pki_get_private_dir(void)
{
#ifdef LIBDEMO_PKI_PRIVATE_DIR
	return (strdup(LIBDEMO_PKI_PRIVATE_DIR));
#else
	return (NULL);
#endif
}

/*
 * NULL return is an error
 */
char *
demo_pki_get_private_path(const char *initial_path)
{
#ifdef LIBDEMO_PKI_PRIVATE_DIR
	if (initial_path[0] == '/')
		return (strdup(initial_path));
	else
		return (demo_pki_concat(LIBDEMO_PKI_PRIVATE_DIR, initial_path));
#else
	return (strdup(initial_path));
#endif
}

bool
demo_pki_set_key_and_certificate(SSL_CTX *ctx, const char *key_path,
    const char *cert_path)
{
	bool result = false;

	key_path = demo_pki_get_private_path(key_path);
	if (key_path == NULL)
		return (false);
	cert_path = demo_pki_get_public_path(cert_path);
	if (cert_path == NULL) {
		free((void *)key_path);
		return (false);
	}

	if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
		demo_print_error_ssl_errq("Failed to load certificate file '%s'",
		    cert_path);
		goto error;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
		demo_print_error_ssl_errq("Failed to load certificate key file "
		    "'%s'", key_path);
		goto error;
	}
	/* XXX This may already be checked during key load */
        if (!SSL_CTX_check_private_key(ctx)) {
		demo_print_error_ssl_errq(
		    "Certificate private key does not match the public key");
		goto error;
        }
	result = true;

error:
	free((void *)key_path);
	free((void *)cert_path);
	return (result);
}

static char *
demo_pki_concat(const char *s1, const char *s2)
{
	char *result;
	int len;
	bool need_slash;

	len = strlen(s1);
	if ((len > 0) && (s1[len - 1] != '/')) {
		need_slash = true;
		len++;
	} else
		need_slash = false;
	len += strlen(s2);
	result = malloc(len + 1);
	if (result == NULL)
		return (NULL);
	snprintf(result, len + 1, "%s%s%s", s1, need_slash ? "/" : "", s2);

	return (result);
}
