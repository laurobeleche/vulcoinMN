/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _VLCP256K1_TESTRAND_H_
#define _VLCP256K1_TESTRAND_H_

#if defined HAVE_CONFIG_H
#include "libvlcp256k1-config.h"
#endif

/** Seed the pseudorandom number generator. */
VLCP256K1_INLINE static void vlcp256k1_rand_seed(uint64_t v);

/** Generate a pseudorandom 32-bit number. */
static uint32_t vlcp256k1_rand32(void);

/** Generate a pseudorandom 32-byte array. */
static void vlcp256k1_rand256(unsigned char *b32);

/** Generate a pseudorandom 32-byte array with long sequences of zero and one bits. */
static void vlcp256k1_rand256_test(unsigned char *b32);

#endif
