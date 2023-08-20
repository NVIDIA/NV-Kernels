/* SPDX-License-Identifier: GPL-2.0-or-later */
/* X.509 certificate parser internal definitions
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <keys/x509-parser.h>

/*
 * x509_cert_parser.c
 */
extern int x509_decode_time(time64_t *_t,  size_t hdrlen,
			    unsigned char tag,
			    const unsigned char *value, size_t vlen);

/*
 * x509_public_key.c
 */
extern int x509_get_sig_params(struct x509_certificate *cert);
extern int x509_check_for_self_signed(struct x509_certificate *cert);
