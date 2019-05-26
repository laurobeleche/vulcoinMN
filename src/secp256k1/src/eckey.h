/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _VLCP256K1_ECKEY_
#define _VLCP256K1_ECKEY_

#include "group.h"
#include "scalar.h"

static int vlcp256k1_eckey_pubkey_parse(vlcp256k1_ge_t *elem, const unsigned char *pub, int size);
static int vlcp256k1_eckey_pubkey_serialize(vlcp256k1_ge_t *elem, unsigned char *pub, int *size, int compressed);

static int vlcp256k1_eckey_privkey_parse(vlcp256k1_scalar_t *key, const unsigned char *privkey, int privkeylen);
static int vlcp256k1_eckey_privkey_serialize(unsigned char *privkey, int *privkeylen, const vlcp256k1_scalar_t *key, int compressed);

static int vlcp256k1_eckey_privkey_tweak_add(vlcp256k1_scalar_t *key, const vlcp256k1_scalar_t *tweak);
static int vlcp256k1_eckey_pubkey_tweak_add(vlcp256k1_ge_t *key, const vlcp256k1_scalar_t *tweak);
static int vlcp256k1_eckey_privkey_tweak_mul(vlcp256k1_scalar_t *key, const vlcp256k1_scalar_t *tweak);
static int vlcp256k1_eckey_pubkey_tweak_mul(vlcp256k1_ge_t *key, const vlcp256k1_scalar_t *tweak);

#endif
