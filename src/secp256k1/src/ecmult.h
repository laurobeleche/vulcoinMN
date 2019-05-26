/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _VLCP256K1_ECMULT_
#define _VLCP256K1_ECMULT_

#include "num.h"
#include "group.h"

static void vlcp256k1_ecmult_start(void);
static void vlcp256k1_ecmult_stop(void);

/** Double multiply: R = na*A + ng*G */
static void vlcp256k1_ecmult(vlcp256k1_gej_t *r, const vlcp256k1_gej_t *a, const vlcp256k1_scalar_t *na, const vlcp256k1_scalar_t *ng);

#endif
