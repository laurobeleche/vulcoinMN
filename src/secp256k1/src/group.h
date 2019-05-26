/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _VLCP256K1_GROUP_
#define _VLCP256K1_GROUP_

#include "num.h"
#include "field.h"

/** A group element of the vlcp256k1 curve, in affine coordinates. */
typedef struct {
    vlcp256k1_fe_t x;
    vlcp256k1_fe_t y;
    int infinity; /* whether this represents the point at infinity */
} vlcp256k1_ge_t;

/** A group element of the vlcp256k1 curve, in jacobian coordinates. */
typedef struct {
    vlcp256k1_fe_t x; /* actual X: x/z^2 */
    vlcp256k1_fe_t y; /* actual Y: y/z^3 */
    vlcp256k1_fe_t z;
    int infinity; /* whether this represents the point at infinity */
} vlcp256k1_gej_t;

/** Global constants related to the group */
typedef struct {
    vlcp256k1_ge_t g; /* the generator point */

#ifdef USE_ENDOMORPHISM
    /* constants related to vlcp256k1's efficiently computable endomorphism */
    vlcp256k1_fe_t beta;
#endif
} vlcp256k1_ge_consts_t;

static const vlcp256k1_ge_consts_t *vlcp256k1_ge_consts = NULL;

/** Initialize the group module. */
static void vlcp256k1_ge_start(void);

/** De-initialize the group module. */
static void vlcp256k1_ge_stop(void);

/** Set a group element equal to the point at infinity */
static void vlcp256k1_ge_set_infinity(vlcp256k1_ge_t *r);

/** Set a group element equal to the point with given X and Y coordinates */
static void vlcp256k1_ge_set_xy(vlcp256k1_ge_t *r, const vlcp256k1_fe_t *x, const vlcp256k1_fe_t *y);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int vlcp256k1_ge_set_xo(vlcp256k1_ge_t *r, const vlcp256k1_fe_t *x, int odd);

/** Check whether a group element is the point at infinity. */
static int vlcp256k1_ge_is_infinity(const vlcp256k1_ge_t *a);

/** Check whether a group element is valid (i.e., on the curve). */
static int vlcp256k1_ge_is_valid(const vlcp256k1_ge_t *a);

static void vlcp256k1_ge_neg(vlcp256k1_ge_t *r, const vlcp256k1_ge_t *a);

/** Get a hex representation of a point. *rlen will be overwritten with the real length. */
static void vlcp256k1_ge_get_hex(char *r, int *rlen, const vlcp256k1_ge_t *a);

/** Set a group element equal to another which is given in jacobian coordinates */
static void vlcp256k1_ge_set_gej(vlcp256k1_ge_t *r, vlcp256k1_gej_t *a);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates */
static void vlcp256k1_ge_set_all_gej_var(size_t len, vlcp256k1_ge_t r[len], const vlcp256k1_gej_t a[len]);


/** Set a group element (jacobian) equal to the point at infinity. */
static void vlcp256k1_gej_set_infinity(vlcp256k1_gej_t *r);

/** Set a group element (jacobian) equal to the point with given X and Y coordinates. */
static void vlcp256k1_gej_set_xy(vlcp256k1_gej_t *r, const vlcp256k1_fe_t *x, const vlcp256k1_fe_t *y);

/** Set a group element (jacobian) equal to another which is given in affine coordinates. */
static void vlcp256k1_gej_set_ge(vlcp256k1_gej_t *r, const vlcp256k1_ge_t *a);

/** Get the X coordinate of a group element (jacobian). */
static void vlcp256k1_gej_get_x_var(vlcp256k1_fe_t *r, const vlcp256k1_gej_t *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void vlcp256k1_gej_neg(vlcp256k1_gej_t *r, const vlcp256k1_gej_t *a);

/** Check whether a group element is the point at infinity. */
static int vlcp256k1_gej_is_infinity(const vlcp256k1_gej_t *a);

/** Set r equal to the double of a. */
static void vlcp256k1_gej_double_var(vlcp256k1_gej_t *r, const vlcp256k1_gej_t *a);

/** Set r equal to the sum of a and b. */
static void vlcp256k1_gej_add_var(vlcp256k1_gej_t *r, const vlcp256k1_gej_t *a, const vlcp256k1_gej_t *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates, and not infinity). */
static void vlcp256k1_gej_add_ge(vlcp256k1_gej_t *r, const vlcp256k1_gej_t *a, const vlcp256k1_ge_t *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates). This is more efficient
    than vlcp256k1_gej_add_var. It is identical to vlcp256k1_gej_add_ge but without constant-time
    guarantee, and b is allowed to be infinity. */
static void vlcp256k1_gej_add_ge_var(vlcp256k1_gej_t *r, const vlcp256k1_gej_t *a, const vlcp256k1_ge_t *b);

/** Get a hex representation of a point. *rlen will be overwritten with the real length. */
static void vlcp256k1_gej_get_hex(char *r, int *rlen, const vlcp256k1_gej_t *a);

#ifdef USE_ENDOMORPHISM
/** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
static void vlcp256k1_gej_mul_lambda(vlcp256k1_gej_t *r, const vlcp256k1_gej_t *a);
#endif

/** Clear a vlcp256k1_gej_t to prevent leaking sensitive information. */
static void vlcp256k1_gej_clear(vlcp256k1_gej_t *r);

/** Clear a vlcp256k1_ge_t to prevent leaking sensitive information. */
static void vlcp256k1_ge_clear(vlcp256k1_ge_t *r);

#endif
