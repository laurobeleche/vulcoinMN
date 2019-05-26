/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _VLCP256K1_SCALAR_REPR_
#define _VLCP256K1_SCALAR_REPR_

#include <stdint.h>

/** A scalar modulo the group order of the vlcp256k1 curve. */
typedef struct {
    uint32_t d[8];
} vlcp256k1_scalar_t;

#endif
