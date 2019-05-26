/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _VLCP256K1_ECDSA_
#define _VLCP256K1_ECDSA_

#include "scalar.h"
#include "group.h"

static void vlcp256k1_ecsda_start(void);
static void vlcp256k1_ecdsa_stop(void);

typedef struct {
    vlcp256k1_scalar_t r, s;
} vlcp256k1_ecdsa_sig_t;

static int vlcp256k1_ecdsa_sig_parse(vlcp256k1_ecdsa_sig_t *r, const unsigned char *sig, int size);
static int vlcp256k1_ecdsa_sig_serialize(unsigned char *sig, int *size, const vlcp256k1_ecdsa_sig_t *a);
static int vlcp256k1_ecdsa_sig_verify(const vlcp256k1_ecdsa_sig_t *sig, const vlcp256k1_ge_t *pubkey, const vlcp256k1_scalar_t *message);
static int vlcp256k1_ecdsa_sig_sign(vlcp256k1_ecdsa_sig_t *sig, const vlcp256k1_scalar_t *vlckey, const vlcp256k1_scalar_t *message, const vlcp256k1_scalar_t *nonce, int *recid);
static int vlcp256k1_ecdsa_sig_recover(const vlcp256k1_ecdsa_sig_t *sig, vlcp256k1_ge_t *pubkey, const vlcp256k1_scalar_t *message, int recid);
static void vlcp256k1_ecdsa_sig_set_rs(vlcp256k1_ecdsa_sig_t *sig, const vlcp256k1_scalar_t *r, const vlcp256k1_scalar_t *s);

#endif
