/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
#ifndef _LIBTLMSP_CFG_OPENSSL_H_
#define _LIBTLMSP_CFG_OPENSSL_H_

#include <openssl/tlmsp.h>


TLMSP_Contexts *tlmsp_cfg_contexts_to_openssl(const struct tlmsp_cfg *cfg);
bool tlmsp_cfg_middlebox_contexts_to_openssl(const struct tlmsp_cfg_middlebox *mb, TLMSP_ContextAccess **ca);
TLMSP_Middleboxes *tlmsp_cfg_initial_middlebox_list_to_openssl(const struct tlmsp_cfg*cfg);
bool tlmsp_cfg_middlebox_contexts_match_openssl(const struct tlmsp_cfg_middlebox *mb,
                                                const TLMSP_ContextAccess *ca);
bool tlmsp_cfg_validate_middlebox_list_client_openssl(const struct tlmsp_cfg *cfg,
                                                      TLMSP_Middleboxes *middleboxes);
bool tlmsp_cfg_process_middlebox_list_server_openssl(const struct tlmsp_cfg *cfg,
                                                     TLMSP_Middleboxes *middleboxes);

#endif /* _LIBTLMSP_CFG_OPENSSL_H_ */

