/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _VLCP256K1_SCALAR_
#define _VLCP256K1_SCALAR_

#include "num.h"

#if defined HAVE_CONFIG_H
#include "libvlcp256k1-config.h"
#endif

#if defined(USE_SCALAR_4X64)
#include "scalar_4x64.h"
#elif defined(USE_SCALAR_8X32)
#include "scalar_8x32.h"
#else
#error "Please select scalar implementation"
#endif

static void vlcp256k1_scalar_start(void);
static void vlcp256k1_scalar_stop(void);

/** Clear a scalar to prevent the leak of sensitive data. */
static void vlcp256k1_scalar_clear(vlcp256k1_scalar_t *r);

/** Access bits from a scalar. All requested bits must belong to the same 32-bit limb. */
static unsigned int vlcp256k1_scalar_get_bits(const vlcp256k1_scalar_t *a, unsigned int offset, unsigned int count);

/** Access bits from a scalar. Not constant time. */
static unsigned int vlcp256k1_scalar_get_bits_var(const vlcp256k1_scalar_t *a, unsigned int offset, unsigned int count);

/** Set a scalar from a big endian byte array. */
static void vlcp256k1_scalar_set_b32(vlcp256k1_scalar_t *r, const unsigned char *bin, int *overflow);

/** Set a scalar to an unsigned integer. */
static void vlcp256k1_scalar_set_int(vlcp256k1_scalar_t *r, unsigned int v);

/** Convert a scalar to a byte array. */
static void vlcp256k1_scalar_get_b32(unsigned char *bin, const vlcp256k1_scalar_t* a);

/** Add two scalars together (modulo the group order). Returns whether it overflowed. */
static int vlcp256k1_scalar_add(vlcp256k1_scalar_t *r, const vlcp256k1_scalar_t *a, const vlcp256k1_scalar_t *b);

/** Add a power of two to a scalar. The result is not allowed to overflow. */
static void vlcp256k1_scalar_add_bit(vlcp256k1_scalar_t *r, unsigned int bit);

/** Multiply two scalars (modulo the group order). */
static void vlcp256k1_scalar_mul(vlcp256k1_scalar_t *r, const vlcp256k1_scalar_t *a, const vlcp256k1_scalar_t *b);

/** Compute the square of a scalar (modulo the group order). */
static void vlcp256k1_scalar_sqr(vlcp256k1_scalar_t *r, const vlcp256k1_scalar_t *a);

/** Compute the inverse of a scalar (modulo the group order). */
static void vlcp256k1_scalar_inverse(vlcp256k1_scalar_t *r, const vlcp256k1_scalar_t *a);

/** Compute the inverse of a scalar (modulo the group order), without constant-time guarantee. */
static void vlcp256k1_scalar_inverse_var(vlcp256k1_scalar_t *r, const vlcp256k1_scalar_t *a);

/** Compute the complement of a scalar (modulo the group order). */
static void vlcp256k1_scalar_negate(vlcp256k1_scalar_t *r, const vlcp256k1_scalar_t *a);

/** Check whether a scalar equals zero. */
static int vlcp256k1_scalar_is_zero(const vlcp256k1_scalar_t *a);

/** Check whether a scalar equals one. */
static int vlcp256k1_scalar_is_one(const vlcp256k1_scalar_t *a);

/** Check whether a scalar is higher than the group order divided by 2. */
static int vlcp256k1_scalar_is_high(const vlcp256k1_scalar_t *a);

#ifndef USE_NUM_NONE
/** Convert a scalar to a number. */
static void vlcp256k1_scalar_get_num(vlcp256k1_num_t *r, const vlcp256k1_scalar_t *a);

/** Get the order of the group as a number. */
static void vlcp256k1_scalar_order_get_num(vlcp256k1_num_t *r);
#endif

/** Compare two scalars. */
static int vlcp256k1_scalar_eq(const vlcp256k1_scalar_t *a, const vlcp256k1_scalar_t *b);

static void vlcp256k1_scalar_split_128(vlcp256k1_scalar_t *r1, vlcp256k1_scalar_t *r2, const vlcp256k1_scalar_t *a);

#ifdef USE_ENDOMORPHISM
/** Find r1 and r2 such that r1+r2*lambda = a, and r1 and r2 are maximum 128 bits long (see vlcp256k1_gej_mul_lambda). */
static void vlcp256k1_scalar_split_lambda_var(vlcp256k1_scalar_t *r1, vlcp256k1_scalar_t *r2, const vlcp256k1_scalar_t *a);
#endif

/** Multiply a and b (without taking the modulus!), divide by 2**shift, and round to the nearest integer. Shift must be at least 256. */
static void vlcp256k1_scalar_mul_shift_var(vlcp256k1_scalar_t *r, const vlcp256k1_scalar_t *a, const vlcp256k1_scalar_t *b, unsigned int shift);

#endif
