/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libvlcp256k1-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "vlcp256k1.c"
#include "testrand_impl.h"

#ifdef ENABLE_OPENSSL_TESTS
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#endif

static int count = 64;

void random_field_element_test(vlcp256k1_fe_t *fe) {
    do {
        unsigned char b32[32];
        vlcp256k1_rand256_test(b32);
        if (vlcp256k1_fe_set_b32(fe, b32)) {
            break;
        }
    } while(1);
}

void random_field_element_magnitude(vlcp256k1_fe_t *fe) {
    vlcp256k1_fe_normalize(fe);
    int n = vlcp256k1_rand32() % 4;
    for (int i = 0; i < n; i++) {
        vlcp256k1_fe_negate(fe, fe, 1 + 2*i);
        vlcp256k1_fe_negate(fe, fe, 2 + 2*i);
    }
}

void random_group_element_test(vlcp256k1_ge_t *ge) {
    vlcp256k1_fe_t fe;
    do {
        random_field_element_test(&fe);
        if (vlcp256k1_ge_set_xo(ge, &fe, vlcp256k1_rand32() & 1))
            break;
    } while(1);
}

void random_group_element_jacobian_test(vlcp256k1_gej_t *gej, const vlcp256k1_ge_t *ge) {
    do {
        random_field_element_test(&gej->z);
        if (!vlcp256k1_fe_is_zero(&gej->z)) {
            break;
        }
    } while(1);
    vlcp256k1_fe_t z2; vlcp256k1_fe_sqr(&z2, &gej->z);
    vlcp256k1_fe_t z3; vlcp256k1_fe_mul(&z3, &z2, &gej->z);
    vlcp256k1_fe_mul(&gej->x, &ge->x, &z2);
    vlcp256k1_fe_mul(&gej->y, &ge->y, &z3);
    gej->infinity = ge->infinity;
}

void random_scalar_order_test(vlcp256k1_scalar_t *num) {
    do {
        unsigned char b32[32];
        vlcp256k1_rand256_test(b32);
        int overflow = 0;
        vlcp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || vlcp256k1_scalar_is_zero(num))
            continue;
        break;
    } while(1);
}

void random_scalar_order(vlcp256k1_scalar_t *num) {
    do {
        unsigned char b32[32];
        vlcp256k1_rand256(b32);
        int overflow = 0;
        vlcp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || vlcp256k1_scalar_is_zero(num))
            continue;
        break;
    } while(1);
}

/***** NUM TESTS *****/

#ifndef USE_NUM_NONE
void random_num_negate(vlcp256k1_num_t *num) {
    if (vlcp256k1_rand32() & 1)
        vlcp256k1_num_negate(num);
}

void random_num_order_test(vlcp256k1_num_t *num) {
    vlcp256k1_scalar_t sc;
    random_scalar_order_test(&sc);
    vlcp256k1_scalar_get_num(num, &sc);
}

void random_num_order(vlcp256k1_num_t *num) {
    vlcp256k1_scalar_t sc;
    random_scalar_order(&sc);
    vlcp256k1_scalar_get_num(num, &sc);
}

void test_num_negate(void) {
    vlcp256k1_num_t n1;
    vlcp256k1_num_t n2;
    random_num_order_test(&n1); /* n1 = R */
    random_num_negate(&n1);
    vlcp256k1_num_copy(&n2, &n1); /* n2 = R */
    vlcp256k1_num_sub(&n1, &n2, &n1); /* n1 = n2-n1 = 0 */
    CHECK(vlcp256k1_num_is_zero(&n1));
    vlcp256k1_num_copy(&n1, &n2); /* n1 = R */
    vlcp256k1_num_negate(&n1); /* n1 = -R */
    CHECK(!vlcp256k1_num_is_zero(&n1));
    vlcp256k1_num_add(&n1, &n2, &n1); /* n1 = n2+n1 = 0 */
    CHECK(vlcp256k1_num_is_zero(&n1));
    vlcp256k1_num_copy(&n1, &n2); /* n1 = R */
    vlcp256k1_num_negate(&n1); /* n1 = -R */
    CHECK(vlcp256k1_num_is_neg(&n1) != vlcp256k1_num_is_neg(&n2));
    vlcp256k1_num_negate(&n1); /* n1 = R */
    CHECK(vlcp256k1_num_eq(&n1, &n2));
}

void test_num_add_sub(void) {
    int r = vlcp256k1_rand32();
    vlcp256k1_num_t n1;
    vlcp256k1_num_t n2;
    random_num_order_test(&n1); /* n1 = R1 */
    if (r & 1) {
        random_num_negate(&n1);
    }
    random_num_order_test(&n2); /* n2 = R2 */
    if (r & 2) {
        random_num_negate(&n2);
    }
    vlcp256k1_num_t n1p2, n2p1, n1m2, n2m1;
    vlcp256k1_num_add(&n1p2, &n1, &n2); /* n1p2 = R1 + R2 */
    vlcp256k1_num_add(&n2p1, &n2, &n1); /* n2p1 = R2 + R1 */
    vlcp256k1_num_sub(&n1m2, &n1, &n2); /* n1m2 = R1 - R2 */
    vlcp256k1_num_sub(&n2m1, &n2, &n1); /* n2m1 = R2 - R1 */
    CHECK(vlcp256k1_num_eq(&n1p2, &n2p1));
    CHECK(!vlcp256k1_num_eq(&n1p2, &n1m2));
    vlcp256k1_num_negate(&n2m1); /* n2m1 = -R2 + R1 */
    CHECK(vlcp256k1_num_eq(&n2m1, &n1m2));
    CHECK(!vlcp256k1_num_eq(&n2m1, &n1));
    vlcp256k1_num_add(&n2m1, &n2m1, &n2); /* n2m1 = -R2 + R1 + R2 = R1 */
    CHECK(vlcp256k1_num_eq(&n2m1, &n1));
    CHECK(!vlcp256k1_num_eq(&n2p1, &n1));
    vlcp256k1_num_sub(&n2p1, &n2p1, &n2); /* n2p1 = R2 + R1 - R2 = R1 */
    CHECK(vlcp256k1_num_eq(&n2p1, &n1));
}

void run_num_smalltests(void) {
    for (int i=0; i<100*count; i++) {
        test_num_negate();
        test_num_add_sub();
    }
}
#endif

/***** SCALAR TESTS *****/

void scalar_test(void) {
    unsigned char c[32];

    /* Set 's' to a random scalar, with value 'snum'. */
    vlcp256k1_scalar_t s;
    random_scalar_order_test(&s);

    /* Set 's1' to a random scalar, with value 's1num'. */
    vlcp256k1_scalar_t s1;
    random_scalar_order_test(&s1);

    /* Set 's2' to a random scalar, with value 'snum2', and byte array representation 'c'. */
    vlcp256k1_scalar_t s2;
    random_scalar_order_test(&s2);
    vlcp256k1_scalar_get_b32(c, &s2);

#ifndef USE_NUM_NONE
    vlcp256k1_num_t snum, s1num, s2num;
    vlcp256k1_scalar_get_num(&snum, &s);
    vlcp256k1_scalar_get_num(&s1num, &s1);
    vlcp256k1_scalar_get_num(&s2num, &s2);

    vlcp256k1_num_t order;
    vlcp256k1_scalar_order_get_num(&order);
    vlcp256k1_num_t half_order = order;
    vlcp256k1_num_shift(&half_order, 1);
#endif

    {
        /* Test that fetching groups of 4 bits from a scalar and recursing n(i)=16*n(i-1)+p(i) reconstructs it. */
        vlcp256k1_scalar_t n;
        vlcp256k1_scalar_set_int(&n, 0);
        for (int i = 0; i < 256; i += 4) {
            vlcp256k1_scalar_t t;
            vlcp256k1_scalar_set_int(&t, vlcp256k1_scalar_get_bits(&s, 256 - 4 - i, 4));
            for (int j = 0; j < 4; j++) {
                vlcp256k1_scalar_add(&n, &n, &n);
            }
            vlcp256k1_scalar_add(&n, &n, &t);
        }
        CHECK(vlcp256k1_scalar_eq(&n, &s));
    }

    {
        /* Test that fetching groups of randomly-sized bits from a scalar and recursing n(i)=b*n(i-1)+p(i) reconstructs it. */
        vlcp256k1_scalar_t n;
        vlcp256k1_scalar_set_int(&n, 0);
        int i = 0;
        while (i < 256) {
            int now = (vlcp256k1_rand32() % 15) + 1;
            if (now + i > 256) {
                now = 256 - i;
            }
            vlcp256k1_scalar_t t;
            vlcp256k1_scalar_set_int(&t, vlcp256k1_scalar_get_bits_var(&s, 256 - now - i, now));
            for (int j = 0; j < now; j++) {
                vlcp256k1_scalar_add(&n, &n, &n);
            }
            vlcp256k1_scalar_add(&n, &n, &t);
            i += now;
        }
        CHECK(vlcp256k1_scalar_eq(&n, &s));
    }

#ifndef USE_NUM_NONE
    {
        /* Test that adding the scalars together is equal to adding their numbers together modulo the order. */
        vlcp256k1_num_t rnum;
        vlcp256k1_num_add(&rnum, &snum, &s2num);
        vlcp256k1_num_mod(&rnum, &order);
        vlcp256k1_scalar_t r;
        vlcp256k1_scalar_add(&r, &s, &s2);
        vlcp256k1_num_t r2num;
        vlcp256k1_scalar_get_num(&r2num, &r);
        CHECK(vlcp256k1_num_eq(&rnum, &r2num));
    }

    {
        /* Test that multipying the scalars is equal to multiplying their numbers modulo the order. */
        vlcp256k1_num_t rnum;
        vlcp256k1_num_mul(&rnum, &snum, &s2num);
        vlcp256k1_num_mod(&rnum, &order);
        vlcp256k1_scalar_t r;
        vlcp256k1_scalar_mul(&r, &s, &s2);
        vlcp256k1_num_t r2num;
        vlcp256k1_scalar_get_num(&r2num, &r);
        CHECK(vlcp256k1_num_eq(&rnum, &r2num));
        /* The result can only be zero if at least one of the factors was zero. */
        CHECK(vlcp256k1_scalar_is_zero(&r) == (vlcp256k1_scalar_is_zero(&s) || vlcp256k1_scalar_is_zero(&s2)));
        /* The results can only be equal to one of the factors if that factor was zero, or the other factor was one. */
        CHECK(vlcp256k1_num_eq(&rnum, &snum) == (vlcp256k1_scalar_is_zero(&s) || vlcp256k1_scalar_is_one(&s2)));
        CHECK(vlcp256k1_num_eq(&rnum, &s2num) == (vlcp256k1_scalar_is_zero(&s2) || vlcp256k1_scalar_is_one(&s)));
    }

    {
        /* Check that comparison with zero matches comparison with zero on the number. */
        CHECK(vlcp256k1_num_is_zero(&snum) == vlcp256k1_scalar_is_zero(&s));
        /* Check that comparison with the half order is equal to testing for high scalar. */
        CHECK(vlcp256k1_scalar_is_high(&s) == (vlcp256k1_num_cmp(&snum, &half_order) > 0));
        vlcp256k1_scalar_t neg;
        vlcp256k1_scalar_negate(&neg, &s);
        vlcp256k1_num_t negnum;
        vlcp256k1_num_sub(&negnum, &order, &snum);
        vlcp256k1_num_mod(&negnum, &order);
        /* Check that comparison with the half order is equal to testing for high scalar after negation. */
        CHECK(vlcp256k1_scalar_is_high(&neg) == (vlcp256k1_num_cmp(&negnum, &half_order) > 0));
        /* Negating should change the high property, unless the value was already zero. */
        CHECK((vlcp256k1_scalar_is_high(&s) == vlcp256k1_scalar_is_high(&neg)) == vlcp256k1_scalar_is_zero(&s));
        vlcp256k1_num_t negnum2;
        vlcp256k1_scalar_get_num(&negnum2, &neg);
        /* Negating a scalar should be equal to (order - n) mod order on the number. */
        CHECK(vlcp256k1_num_eq(&negnum, &negnum2));
        vlcp256k1_scalar_add(&neg, &neg, &s);
        /* Adding a number to its negation should result in zero. */
        CHECK(vlcp256k1_scalar_is_zero(&neg));
        vlcp256k1_scalar_negate(&neg, &neg);
        /* Negating zero should still result in zero. */
        CHECK(vlcp256k1_scalar_is_zero(&neg));
    }

    {
        /* Test vlcp256k1_scalar_mul_shift_var. */
        vlcp256k1_scalar_t r;
        unsigned int shift = 256 + (vlcp256k1_rand32() % 257);
        vlcp256k1_scalar_mul_shift_var(&r, &s1, &s2, shift);
        vlcp256k1_num_t rnum;
        vlcp256k1_num_mul(&rnum, &s1num, &s2num);
        vlcp256k1_num_shift(&rnum, shift - 1);
        vlcp256k1_num_t one;
        unsigned char cone[1] = {0x01};
        vlcp256k1_num_set_bin(&one, cone, 1);
        vlcp256k1_num_add(&rnum, &rnum, &one);
        vlcp256k1_num_shift(&rnum, 1);
        vlcp256k1_num_t rnum2;
        vlcp256k1_scalar_get_num(&rnum2, &r);
        CHECK(vlcp256k1_num_eq(&rnum, &rnum2));
    }
#endif

    {
        /* Test that scalar inverses are equal to the inverse of their number modulo the order. */
        if (!vlcp256k1_scalar_is_zero(&s)) {
            vlcp256k1_scalar_t inv;
            vlcp256k1_scalar_inverse(&inv, &s);
#ifndef USE_NUM_NONE
            vlcp256k1_num_t invnum;
            vlcp256k1_num_mod_inverse(&invnum, &snum, &order);
            vlcp256k1_num_t invnum2;
            vlcp256k1_scalar_get_num(&invnum2, &inv);
            CHECK(vlcp256k1_num_eq(&invnum, &invnum2));
#endif
            vlcp256k1_scalar_mul(&inv, &inv, &s);
            /* Multiplying a scalar with its inverse must result in one. */
            CHECK(vlcp256k1_scalar_is_one(&inv));
            vlcp256k1_scalar_inverse(&inv, &inv);
            /* Inverting one must result in one. */
            CHECK(vlcp256k1_scalar_is_one(&inv));
        }
    }

    {
        /* Test commutativity of add. */
        vlcp256k1_scalar_t r1, r2;
        vlcp256k1_scalar_add(&r1, &s1, &s2);
        vlcp256k1_scalar_add(&r2, &s2, &s1);
        CHECK(vlcp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test add_bit. */
        int bit = vlcp256k1_rand32() % 256;
        vlcp256k1_scalar_t b;
        vlcp256k1_scalar_set_int(&b, 1);
        CHECK(vlcp256k1_scalar_is_one(&b));
        for (int i = 0; i < bit; i++) {
            vlcp256k1_scalar_add(&b, &b, &b);
        }
        vlcp256k1_scalar_t r1 = s1, r2 = s1;
        if (!vlcp256k1_scalar_add(&r1, &r1, &b)) {
            /* No overflow happened. */
            vlcp256k1_scalar_add_bit(&r2, bit);
            CHECK(vlcp256k1_scalar_eq(&r1, &r2));
        }
    }

    {
        /* Test commutativity of mul. */
        vlcp256k1_scalar_t r1, r2;
        vlcp256k1_scalar_mul(&r1, &s1, &s2);
        vlcp256k1_scalar_mul(&r2, &s2, &s1);
        CHECK(vlcp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test associativity of add. */
        vlcp256k1_scalar_t r1, r2;
        vlcp256k1_scalar_add(&r1, &s1, &s2);
        vlcp256k1_scalar_add(&r1, &r1, &s);
        vlcp256k1_scalar_add(&r2, &s2, &s);
        vlcp256k1_scalar_add(&r2, &s1, &r2);
        CHECK(vlcp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test associativity of mul. */
        vlcp256k1_scalar_t r1, r2;
        vlcp256k1_scalar_mul(&r1, &s1, &s2);
        vlcp256k1_scalar_mul(&r1, &r1, &s);
        vlcp256k1_scalar_mul(&r2, &s2, &s);
        vlcp256k1_scalar_mul(&r2, &s1, &r2);
        CHECK(vlcp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test distributitivity of mul over add. */
        vlcp256k1_scalar_t r1, r2, t;
        vlcp256k1_scalar_add(&r1, &s1, &s2);
        vlcp256k1_scalar_mul(&r1, &r1, &s);
        vlcp256k1_scalar_mul(&r2, &s1, &s);
        vlcp256k1_scalar_mul(&t, &s2, &s);
        vlcp256k1_scalar_add(&r2, &r2, &t);
        CHECK(vlcp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test square. */
        vlcp256k1_scalar_t r1, r2;
        vlcp256k1_scalar_sqr(&r1, &s1);
        vlcp256k1_scalar_mul(&r2, &s1, &s1);
        CHECK(vlcp256k1_scalar_eq(&r1, &r2));
    }

}

void run_scalar_tests(void) {
    for (int i = 0; i < 128 * count; i++) {
        scalar_test();
    }

    {
        /* (-1)+1 should be zero. */
        vlcp256k1_scalar_t s, o;
        vlcp256k1_scalar_set_int(&s, 1);
        vlcp256k1_scalar_negate(&o, &s);
        vlcp256k1_scalar_add(&o, &o, &s);
        CHECK(vlcp256k1_scalar_is_zero(&o));
    }

#ifndef USE_NUM_NONE
    {
        /* A scalar with value of the curve order should be 0. */
        vlcp256k1_num_t order;
        vlcp256k1_scalar_order_get_num(&order);
        unsigned char bin[32];
        vlcp256k1_num_get_bin(bin, 32, &order);
        vlcp256k1_scalar_t zero;
        int overflow = 0;
        vlcp256k1_scalar_set_b32(&zero, bin, &overflow);
        CHECK(overflow == 1);
        CHECK(vlcp256k1_scalar_is_zero(&zero));
    }
#endif
}

/***** FIELD TESTS *****/

void random_fe(vlcp256k1_fe_t *x) {
    unsigned char bin[32];
    do {
        vlcp256k1_rand256(bin);
        if (vlcp256k1_fe_set_b32(x, bin)) {
            return;
        }
    } while(1);
}

void random_fe_non_zero(vlcp256k1_fe_t *nz) {
    int tries = 10;
    while (--tries >= 0) {
        random_fe(nz);
        vlcp256k1_fe_normalize(nz);
        if (!vlcp256k1_fe_is_zero(nz))
            break;
    }
    /* Infinitesimal probability of spurious failure here */
    CHECK(tries >= 0);
}

void random_fe_non_square(vlcp256k1_fe_t *ns) {
    random_fe_non_zero(ns);
    vlcp256k1_fe_t r;
    if (vlcp256k1_fe_sqrt(&r, ns)) {
        vlcp256k1_fe_negate(ns, ns, 1);
    }
}

int check_fe_equal(const vlcp256k1_fe_t *a, const vlcp256k1_fe_t *b) {
    vlcp256k1_fe_t an = *a; vlcp256k1_fe_normalize(&an);
    vlcp256k1_fe_t bn = *b; vlcp256k1_fe_normalize(&bn);
    return vlcp256k1_fe_equal(&an, &bn);
}

int check_fe_inverse(const vlcp256k1_fe_t *a, const vlcp256k1_fe_t *ai) {
    vlcp256k1_fe_t x; vlcp256k1_fe_mul(&x, a, ai);
    vlcp256k1_fe_t one; vlcp256k1_fe_set_int(&one, 1);
    return check_fe_equal(&x, &one);
}

void run_field_inv(void) {
    vlcp256k1_fe_t x, xi, xii;
    for (int i=0; i<10*count; i++) {
        random_fe_non_zero(&x);
        vlcp256k1_fe_inv(&xi, &x);
        CHECK(check_fe_inverse(&x, &xi));
        vlcp256k1_fe_inv(&xii, &xi);
        CHECK(check_fe_equal(&x, &xii));
    }
}

void run_field_inv_var(void) {
    vlcp256k1_fe_t x, xi, xii;
    for (int i=0; i<10*count; i++) {
        random_fe_non_zero(&x);
        vlcp256k1_fe_inv_var(&xi, &x);
        CHECK(check_fe_inverse(&x, &xi));
        vlcp256k1_fe_inv_var(&xii, &xi);
        CHECK(check_fe_equal(&x, &xii));
    }
}

void run_field_inv_all(void) {
    vlcp256k1_fe_t x[16], xi[16], xii[16];
    /* Check it's safe to call for 0 elements */
    vlcp256k1_fe_inv_all(0, xi, x);
    for (int i=0; i<count; i++) {
        size_t len = (vlcp256k1_rand32() & 15) + 1;
        for (size_t j=0; j<len; j++)
            random_fe_non_zero(&x[j]);
        vlcp256k1_fe_inv_all(len, xi, x);
        for (size_t j=0; j<len; j++)
            CHECK(check_fe_inverse(&x[j], &xi[j]));
        vlcp256k1_fe_inv_all(len, xii, xi);
        for (size_t j=0; j<len; j++)
            CHECK(check_fe_equal(&x[j], &xii[j]));
    }
}

void run_field_inv_all_var(void) {
    vlcp256k1_fe_t x[16], xi[16], xii[16];
    /* Check it's safe to call for 0 elements */
    vlcp256k1_fe_inv_all_var(0, xi, x);
    for (int i=0; i<count; i++) {
        size_t len = (vlcp256k1_rand32() & 15) + 1;
        for (size_t j=0; j<len; j++)
            random_fe_non_zero(&x[j]);
        vlcp256k1_fe_inv_all_var(len, xi, x);
        for (size_t j=0; j<len; j++)
            CHECK(check_fe_inverse(&x[j], &xi[j]));
        vlcp256k1_fe_inv_all_var(len, xii, xi);
        for (size_t j=0; j<len; j++)
            CHECK(check_fe_equal(&x[j], &xii[j]));
    }
}

void run_sqr(void) {
    vlcp256k1_fe_t x, s;

    {
        vlcp256k1_fe_set_int(&x, 1);
        vlcp256k1_fe_negate(&x, &x, 1);

        for (int i=1; i<=512; ++i) {
            vlcp256k1_fe_mul_int(&x, 2);
            vlcp256k1_fe_normalize(&x);
            vlcp256k1_fe_sqr(&s, &x);
        }
    }
}

void test_sqrt(const vlcp256k1_fe_t *a, const vlcp256k1_fe_t *k) {
    vlcp256k1_fe_t r1, r2;
    int v = vlcp256k1_fe_sqrt(&r1, a);
    CHECK((v == 0) == (k == NULL));

    if (k != NULL) {
        /* Check that the returned root is +/- the given known answer */
        vlcp256k1_fe_negate(&r2, &r1, 1);
        vlcp256k1_fe_add(&r1, k); vlcp256k1_fe_add(&r2, k);
        vlcp256k1_fe_normalize(&r1); vlcp256k1_fe_normalize(&r2);
        CHECK(vlcp256k1_fe_is_zero(&r1) || vlcp256k1_fe_is_zero(&r2));
    }
}

void run_sqrt(void) {
    vlcp256k1_fe_t ns, x, s, t;

    /* Check sqrt(0) is 0 */
    vlcp256k1_fe_set_int(&x, 0);
    vlcp256k1_fe_sqr(&s, &x);
    test_sqrt(&s, &x);

    /* Check sqrt of small squares (and their negatives) */
    for (int i=1; i<=100; i++) {
        vlcp256k1_fe_set_int(&x, i);
        vlcp256k1_fe_sqr(&s, &x);
        test_sqrt(&s, &x);
        vlcp256k1_fe_negate(&t, &s, 1);
        test_sqrt(&t, NULL);
    }

    /* Consistency checks for large random values */
    for (int i=0; i<10; i++) {
        random_fe_non_square(&ns);
        for (int j=0; j<count; j++) {
            random_fe(&x);
            vlcp256k1_fe_sqr(&s, &x);
            test_sqrt(&s, &x);
            vlcp256k1_fe_negate(&t, &s, 1);
            test_sqrt(&t, NULL);
            vlcp256k1_fe_mul(&t, &s, &ns);
            test_sqrt(&t, NULL);
        }
    }
}

/***** GROUP TESTS *****/

int ge_equals_ge(const vlcp256k1_ge_t *a, const vlcp256k1_ge_t *b) {
    if (a->infinity && b->infinity)
        return 1;
    return check_fe_equal(&a->x, &b->x) && check_fe_equal(&a->y, &b->y);
}

void ge_equals_gej(const vlcp256k1_ge_t *a, const vlcp256k1_gej_t *b) {
    vlcp256k1_ge_t bb;
    vlcp256k1_gej_t bj = *b;
    vlcp256k1_ge_set_gej_var(&bb, &bj);
    CHECK(ge_equals_ge(a, &bb));
}

void gej_equals_gej(const vlcp256k1_gej_t *a, const vlcp256k1_gej_t *b) {
    vlcp256k1_ge_t aa, bb;
    vlcp256k1_gej_t aj = *a, bj = *b;
    vlcp256k1_ge_set_gej_var(&aa, &aj);
    vlcp256k1_ge_set_gej_var(&bb, &bj);
    CHECK(ge_equals_ge(&aa, &bb));
}

void test_ge(void) {
    char ca[135];
    char cb[68];
    int rlen;
    vlcp256k1_ge_t a, b, i, n;
    random_group_element_test(&a);
    random_group_element_test(&b);
    rlen = sizeof(ca);
    vlcp256k1_ge_get_hex(ca,&rlen,&a);
    CHECK(rlen > 4 && rlen <= (int)sizeof(ca));
    rlen = sizeof(cb);
    vlcp256k1_ge_get_hex(cb,&rlen,&b); /* Intentionally undersized buffer. */
    n = a;
    vlcp256k1_fe_normalize(&a.y);
    vlcp256k1_fe_negate(&n.y, &a.y, 1);
    vlcp256k1_ge_set_infinity(&i);
    random_field_element_magnitude(&a.x);
    random_field_element_magnitude(&a.y);
    random_field_element_magnitude(&b.x);
    random_field_element_magnitude(&b.y);
    random_field_element_magnitude(&n.x);
    random_field_element_magnitude(&n.y);

    vlcp256k1_gej_t aj, bj, ij, nj;
    random_group_element_jacobian_test(&aj, &a);
    random_group_element_jacobian_test(&bj, &b);
    vlcp256k1_gej_set_infinity(&ij);
    random_group_element_jacobian_test(&nj, &n);
    random_field_element_magnitude(&aj.x);
    random_field_element_magnitude(&aj.y);
    random_field_element_magnitude(&aj.z);
    random_field_element_magnitude(&bj.x);
    random_field_element_magnitude(&bj.y);
    random_field_element_magnitude(&bj.z);
    random_field_element_magnitude(&nj.x);
    random_field_element_magnitude(&nj.y);
    random_field_element_magnitude(&nj.z);

    /* gej + gej adds */
    vlcp256k1_gej_t aaj; vlcp256k1_gej_add_var(&aaj, &aj, &aj);
    vlcp256k1_gej_t abj; vlcp256k1_gej_add_var(&abj, &aj, &bj);
    vlcp256k1_gej_t aij; vlcp256k1_gej_add_var(&aij, &aj, &ij);
    vlcp256k1_gej_t anj; vlcp256k1_gej_add_var(&anj, &aj, &nj);
    vlcp256k1_gej_t iaj; vlcp256k1_gej_add_var(&iaj, &ij, &aj);
    vlcp256k1_gej_t iij; vlcp256k1_gej_add_var(&iij, &ij, &ij);

    /* gej + ge adds */
    vlcp256k1_gej_t aa; vlcp256k1_gej_add_ge_var(&aa, &aj, &a);
    vlcp256k1_gej_t ab; vlcp256k1_gej_add_ge_var(&ab, &aj, &b);
    vlcp256k1_gej_t ai; vlcp256k1_gej_add_ge_var(&ai, &aj, &i);
    vlcp256k1_gej_t an; vlcp256k1_gej_add_ge_var(&an, &aj, &n);
    vlcp256k1_gej_t ia; vlcp256k1_gej_add_ge_var(&ia, &ij, &a);
    vlcp256k1_gej_t ii; vlcp256k1_gej_add_ge_var(&ii, &ij, &i);

    /* const gej + ge adds */
    vlcp256k1_gej_t aac; vlcp256k1_gej_add_ge(&aac, &aj, &a);
    vlcp256k1_gej_t abc; vlcp256k1_gej_add_ge(&abc, &aj, &b);
    vlcp256k1_gej_t anc; vlcp256k1_gej_add_ge(&anc, &aj, &n);
    vlcp256k1_gej_t iac; vlcp256k1_gej_add_ge(&iac, &ij, &a);

    CHECK(vlcp256k1_gej_is_infinity(&an));
    CHECK(vlcp256k1_gej_is_infinity(&anj));
    CHECK(vlcp256k1_gej_is_infinity(&anc));
    gej_equals_gej(&aa, &aaj);
    gej_equals_gej(&aa, &aac);
    gej_equals_gej(&ab, &abj);
    gej_equals_gej(&ab, &abc);
    gej_equals_gej(&an, &anj);
    gej_equals_gej(&an, &anc);
    gej_equals_gej(&ia, &iaj);
    gej_equals_gej(&ai, &aij);
    gej_equals_gej(&ii, &iij);
    ge_equals_gej(&a, &ai);
    ge_equals_gej(&a, &ai);
    ge_equals_gej(&a, &iaj);
    ge_equals_gej(&a, &iaj);
    ge_equals_gej(&a, &iac);
}

void run_ge(void) {
    for (int i = 0; i < 2000*count; i++) {
        test_ge();
    }
}

/***** ECMULT TESTS *****/

void run_ecmult_chain(void) {
    /* random starting point A (on the curve) */
    vlcp256k1_fe_t ax; VERIFY_CHECK(vlcp256k1_fe_set_hex(&ax, "8b30bbe9ae2a990696b22f670709dff3727fd8bc04d3362c6c7bf458e2846004", 64));
    vlcp256k1_fe_t ay; VERIFY_CHECK(vlcp256k1_fe_set_hex(&ay, "a357ae915c4a65281309edf20504740f0eb3343990216b4f81063cb65f2f7e0f", 64));
    vlcp256k1_gej_t a; vlcp256k1_gej_set_xy(&a, &ax, &ay);
    /* two random initial factors xn and gn */
    static const unsigned char xni[32] = {
        0x84, 0xcc, 0x54, 0x52, 0xf7, 0xfd, 0xe1, 0xed,
        0xb4, 0xd3, 0x8a, 0x8c, 0xe9, 0xb1, 0xb8, 0x4c,
        0xce, 0xf3, 0x1f, 0x14, 0x6e, 0x56, 0x9b, 0xe9,
        0x70, 0x5d, 0x35, 0x7a, 0x42, 0x98, 0x54, 0x07
    };
    vlcp256k1_scalar_t xn;
    vlcp256k1_scalar_set_b32(&xn, xni, NULL);
    static const unsigned char gni[32] = {
        0xa1, 0xe5, 0x8d, 0x22, 0x55, 0x3d, 0xcd, 0x42,
        0xb2, 0x39, 0x80, 0x62, 0x5d, 0x4c, 0x57, 0xa9,
        0x6e, 0x93, 0x23, 0xd4, 0x2b, 0x31, 0x52, 0xe5,
        0xca, 0x2c, 0x39, 0x90, 0xed, 0xc7, 0xc9, 0xde
    };
    vlcp256k1_scalar_t gn;
    vlcp256k1_scalar_set_b32(&gn, gni, NULL);
    /* two small multipliers to be applied to xn and gn in every iteration: */
    static const unsigned char xfi[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x13,0x37};
    vlcp256k1_scalar_t xf;
    vlcp256k1_scalar_set_b32(&xf, xfi, NULL);
    static const unsigned char gfi[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x71,0x13};
    vlcp256k1_scalar_t gf;
    vlcp256k1_scalar_set_b32(&gf, gfi, NULL);
    /* accumulators with the resulting coefficients to A and G */
    vlcp256k1_scalar_t ae;
    vlcp256k1_scalar_set_int(&ae, 1);
    vlcp256k1_scalar_t ge;
    vlcp256k1_scalar_set_int(&ge, 0);
    /* the point being computed */
    vlcp256k1_gej_t x = a;
    for (int i=0; i<200*count; i++) {
        /* in each iteration, compute X = xn*X + gn*G; */
        vlcp256k1_ecmult(&x, &x, &xn, &gn);
        /* also compute ae and ge: the actual accumulated factors for A and G */
        /* if X was (ae*A+ge*G), xn*X + gn*G results in (xn*ae*A + (xn*ge+gn)*G) */
        vlcp256k1_scalar_mul(&ae, &ae, &xn);
        vlcp256k1_scalar_mul(&ge, &ge, &xn);
        vlcp256k1_scalar_add(&ge, &ge, &gn);
        /* modify xn and gn */
        vlcp256k1_scalar_mul(&xn, &xn, &xf);
        vlcp256k1_scalar_mul(&gn, &gn, &gf);

        /* verify */
        if (i == 51474) {
            char res[132]; int resl = 132;
            vlcp256k1_gej_get_hex(res, &resl, &x);
            CHECK(strcmp(res, "(D6E96687F9B10D092A6F35439D86CEBEA4535D0D409F53586440BD74B933E830,B95CBCA2C77DA786539BE8FD53354D2D3B4F566AE658045407ED6015EE1B2A88)") == 0);
        }
    }
    /* redo the computation, but directly with the resulting ae and ge coefficients: */
    vlcp256k1_gej_t x2; vlcp256k1_ecmult(&x2, &a, &ae, &ge);
    char res[132]; int resl = 132;
    char res2[132]; int resl2 = 132;
    vlcp256k1_gej_get_hex(res, &resl, &x);
    vlcp256k1_gej_get_hex(res2, &resl2, &x2);
    CHECK(strcmp(res, res2) == 0);
    CHECK(strlen(res) == 131);
}

void test_point_times_order(const vlcp256k1_gej_t *point) {
    /* X * (point + G) + (order-X) * (pointer + G) = 0 */
    vlcp256k1_scalar_t x;
    random_scalar_order_test(&x);
    vlcp256k1_scalar_t nx;
    vlcp256k1_scalar_negate(&nx, &x);
    vlcp256k1_gej_t res1, res2;
    vlcp256k1_ecmult(&res1, point, &x, &x); /* calc res1 = x * point + x * G; */
    vlcp256k1_ecmult(&res2, point, &nx, &nx); /* calc res2 = (order - x) * point + (order - x) * G; */
    vlcp256k1_gej_add_var(&res1, &res1, &res2);
    CHECK(vlcp256k1_gej_is_infinity(&res1));
    CHECK(vlcp256k1_gej_is_valid(&res1) == 0);
    vlcp256k1_ge_t res3;
    vlcp256k1_ge_set_gej(&res3, &res1);
    CHECK(vlcp256k1_ge_is_infinity(&res3));
    CHECK(vlcp256k1_ge_is_valid(&res3) == 0);
}

void run_point_times_order(void) {
    vlcp256k1_fe_t x; VERIFY_CHECK(vlcp256k1_fe_set_hex(&x, "02", 2));
    for (int i=0; i<500; i++) {
        vlcp256k1_ge_t p;
        if (vlcp256k1_ge_set_xo(&p, &x, 1)) {
            CHECK(vlcp256k1_ge_is_valid(&p));
            vlcp256k1_gej_t j;
            vlcp256k1_gej_set_ge(&j, &p);
            CHECK(vlcp256k1_gej_is_valid(&j));
            test_point_times_order(&j);
        }
        vlcp256k1_fe_sqr(&x, &x);
    }
    char c[65]; int cl=65;
    vlcp256k1_fe_get_hex(c, &cl, &x);
    CHECK(strcmp(c, "7603CB59B0EF6C63FE6084792A0C378CDB3233A80F8A9A09A877DEAD31B38C45") == 0);
}

void test_wnaf(const vlcp256k1_scalar_t *number, int w) {
    vlcp256k1_scalar_t x, two, t;
    vlcp256k1_scalar_set_int(&x, 0);
    vlcp256k1_scalar_set_int(&two, 2);
    int wnaf[256];
    int bits = vlcp256k1_ecmult_wnaf(wnaf, number, w);
    CHECK(bits <= 256);
    int zeroes = -1;
    for (int i=bits-1; i>=0; i--) {
        vlcp256k1_scalar_mul(&x, &x, &two);
        int v = wnaf[i];
        if (v) {
            CHECK(zeroes == -1 || zeroes >= w-1); /* check that distance between non-zero elements is at least w-1 */
            zeroes=0;
            CHECK((v & 1) == 1); /* check non-zero elements are odd */
            CHECK(v <= (1 << (w-1)) - 1); /* check range below */
            CHECK(v >= -(1 << (w-1)) - 1); /* check range above */
        } else {
            CHECK(zeroes != -1); /* check that no unnecessary zero padding exists */
            zeroes++;
        }
        if (v >= 0) {
            vlcp256k1_scalar_set_int(&t, v);
        } else {
            vlcp256k1_scalar_set_int(&t, -v);
            vlcp256k1_scalar_negate(&t, &t);
        }
        vlcp256k1_scalar_add(&x, &x, &t);
    }
    CHECK(vlcp256k1_scalar_eq(&x, number)); /* check that wnaf represents number */
}

void run_wnaf(void) {
    vlcp256k1_scalar_t n;
    for (int i=0; i<count; i++) {
        random_scalar_order(&n);
        if (i % 1)
            vlcp256k1_scalar_negate(&n, &n);
        test_wnaf(&n, 4+(i%10));
    }
}

void random_sign(vlcp256k1_ecdsa_sig_t *sig, const vlcp256k1_scalar_t *key, const vlcp256k1_scalar_t *msg, int *recid) {
    vlcp256k1_scalar_t nonce;
    do {
        random_scalar_order_test(&nonce);
    } while(!vlcp256k1_ecdsa_sig_sign(sig, key, msg, &nonce, recid));
}

void test_ecdsa_sign_verify(void) {
    int recid;
    int getrec;
    vlcp256k1_scalar_t msg, key;
    random_scalar_order_test(&msg);
    random_scalar_order_test(&key);
    vlcp256k1_gej_t pubj; vlcp256k1_ecmult_gen(&pubj, &key);
    vlcp256k1_ge_t pub; vlcp256k1_ge_set_gej(&pub, &pubj);
    vlcp256k1_ecdsa_sig_t sig;
    getrec = vlcp256k1_rand32()&1;
    random_sign(&sig, &key, &msg, getrec?&recid:NULL);
    if (getrec) CHECK(recid >= 0 && recid < 4);
    CHECK(vlcp256k1_ecdsa_sig_verify(&sig, &pub, &msg));
    vlcp256k1_scalar_t one;
    vlcp256k1_scalar_set_int(&one, 1);
    vlcp256k1_scalar_add(&msg, &msg, &one);
    CHECK(!vlcp256k1_ecdsa_sig_verify(&sig, &pub, &msg));
}

void run_ecdsa_sign_verify(void) {
    for (int i=0; i<10*count; i++) {
        test_ecdsa_sign_verify();
    }
}

void test_ecdsa_end_to_end(void) {
    unsigned char privkey[32];
    unsigned char message[32];

    /* Generate a random key and message. */
    {
        vlcp256k1_scalar_t msg, key;
        random_scalar_order_test(&msg);
        random_scalar_order_test(&key);
        vlcp256k1_scalar_get_b32(privkey, &key);
        vlcp256k1_scalar_get_b32(message, &msg);
    }

    /* Construct and verify corresponding public key. */
    CHECK(vlcp256k1_ec_vlckey_verify(privkey) == 1);
    unsigned char pubkey[65]; int pubkeylen = 65;
    CHECK(vlcp256k1_ec_pubkey_create(pubkey, &pubkeylen, privkey, vlcp256k1_rand32() % 2) == 1);
    CHECK(vlcp256k1_ec_pubkey_verify(pubkey, pubkeylen));

    /* Verify private key import and export. */
    unsigned char vlckey[300]; int vlckeylen = 300;
    CHECK(vlcp256k1_ec_privkey_export(privkey, vlckey, &vlckeylen, vlcp256k1_rand32() % 2) == 1);
    unsigned char privkey2[32];
    CHECK(vlcp256k1_ec_privkey_import(privkey2, vlckey, vlckeylen) == 1);
    CHECK(memcmp(privkey, privkey2, 32) == 0);

    /* Optionally tweak the keys using addition. */
    if (vlcp256k1_rand32() % 3 == 0) {
        unsigned char rnd[32];
        vlcp256k1_rand256_test(rnd);
        int ret1 = vlcp256k1_ec_privkey_tweak_add(privkey, rnd);
        int ret2 = vlcp256k1_ec_pubkey_tweak_add(pubkey, pubkeylen, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) return;
        unsigned char pubkey2[65]; int pubkeylen2 = 65;
        CHECK(vlcp256k1_ec_pubkey_create(pubkey2, &pubkeylen2, privkey, pubkeylen == 33) == 1);
        CHECK(memcmp(pubkey, pubkey2, pubkeylen) == 0);
    }

    /* Optionally tweak the keys using multiplication. */
    if (vlcp256k1_rand32() % 3 == 0) {
        unsigned char rnd[32];
        vlcp256k1_rand256_test(rnd);
        int ret1 = vlcp256k1_ec_privkey_tweak_mul(privkey, rnd);
        int ret2 = vlcp256k1_ec_pubkey_tweak_mul(pubkey, pubkeylen, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) return;
        unsigned char pubkey2[65]; int pubkeylen2 = 65;
        CHECK(vlcp256k1_ec_pubkey_create(pubkey2, &pubkeylen2, privkey, pubkeylen == 33) == 1);
        CHECK(memcmp(pubkey, pubkey2, pubkeylen) == 0);
    }

    /* Sign. */
    unsigned char signature[72]; int signaturelen = 72;
    while(1) {
        unsigned char rnd[32];
        vlcp256k1_rand256_test(rnd);
        if (vlcp256k1_ecdsa_sign(message, 32, signature, &signaturelen, privkey, rnd) == 1) {
            break;
        }
    }
    /* Verify. */
    CHECK(vlcp256k1_ecdsa_verify(message, 32, signature, signaturelen, pubkey, pubkeylen) == 1);
    /* Destroy signature and verify again. */
    signature[signaturelen - 1 - vlcp256k1_rand32() % 20] += 1 + (vlcp256k1_rand32() % 255);
    CHECK(vlcp256k1_ecdsa_verify(message, 32, signature, signaturelen, pubkey, pubkeylen) != 1);

    /* Compact sign. */
    unsigned char csignature[64]; int recid = 0;
    while(1) {
        unsigned char rnd[32];
        vlcp256k1_rand256_test(rnd);
        if (vlcp256k1_ecdsa_sign_compact(message, 32, csignature, privkey, rnd, &recid) == 1) {
            break;
        }
    }
    /* Recover. */
    unsigned char recpubkey[65]; int recpubkeylen = 0;
    CHECK(vlcp256k1_ecdsa_recover_compact(message, 32, csignature, recpubkey, &recpubkeylen, pubkeylen == 33, recid) == 1);
    CHECK(recpubkeylen == pubkeylen);
    CHECK(memcmp(pubkey, recpubkey, pubkeylen) == 0);
    /* Destroy signature and verify again. */
    csignature[vlcp256k1_rand32() % 64] += 1 + (vlcp256k1_rand32() % 255);
    CHECK(vlcp256k1_ecdsa_recover_compact(message, 32, csignature, recpubkey, &recpubkeylen, pubkeylen == 33, recid) != 1 ||
          memcmp(pubkey, recpubkey, pubkeylen) != 0);
    CHECK(recpubkeylen == pubkeylen);

}

void run_ecdsa_end_to_end(void) {
    for (int i=0; i<64*count; i++) {
        test_ecdsa_end_to_end();
    }
}

/* Tests several edge cases. */
void test_ecdsa_edge_cases(void) {
    const unsigned char msg32[32] = {
        'T', 'h', 'i', 's', ' ', 'i', 's', ' ',
        'a', ' ', 'v', 'e', 'r', 'y', ' ', 's',
        'e', 'c', 'r', 'e', 't', ' ', 'm', 'e',
        's', 's', 'a', 'g', 'e', '.', '.', '.'
    };
    const unsigned char sig64[64] = {
        /* Generated by signing the above message with nonce 'This is the nonce we will use...'
         * and vlcret key 0 (which is not valid), resulting in recid 0. */
        0x67, 0xCB, 0x28, 0x5F, 0x9C, 0xD1, 0x94, 0xE8,
        0x40, 0xD6, 0x29, 0x39, 0x7A, 0xF5, 0x56, 0x96,
        0x62, 0xFD, 0xE4, 0x46, 0x49, 0x99, 0x59, 0x63,
        0x17, 0x9A, 0x7D, 0xD1, 0x7B, 0xD2, 0x35, 0x32,
        0x4B, 0x1B, 0x7D, 0xF3, 0x4C, 0xE1, 0xF6, 0x8E,
        0x69, 0x4F, 0xF6, 0xF1, 0x1A, 0xC7, 0x51, 0xDD,
        0x7D, 0xD7, 0x3E, 0x38, 0x7E, 0xE4, 0xFC, 0x86,
        0x6E, 0x1B, 0xE8, 0xEC, 0xC7, 0xDD, 0x95, 0x57
    };
    unsigned char pubkey[65];
    int pubkeylen = 65;
    CHECK(!vlcp256k1_ecdsa_recover_compact(msg32, 32, sig64, pubkey, &pubkeylen, 0, 0));
    CHECK(vlcp256k1_ecdsa_recover_compact(msg32, 32, sig64, pubkey, &pubkeylen, 0, 1));
    CHECK(!vlcp256k1_ecdsa_recover_compact(msg32, 32, sig64, pubkey, &pubkeylen, 0, 2));
    CHECK(!vlcp256k1_ecdsa_recover_compact(msg32, 32, sig64, pubkey, &pubkeylen, 0, 3));

    /* signature (r,s) = (4,4), which can be recovered with all 4 recids. */
    const unsigned char sigb64[64] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    };
    unsigned char pubkeyb[33];
    int pubkeyblen = 33;
    for (int recid = 0; recid < 4; recid++) {
        /* (4,4) encoded in DER. */
        unsigned char sigbder[8] = {0x30, 0x06, 0x02, 0x01, 0x04, 0x02, 0x01, 0x04};
        /* (order + r,4) encoded in DER. */
        unsigned char sigbderlong[40] = {
            0x30, 0x26, 0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC,
            0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E,
            0x8C, 0xD0, 0x36, 0x41, 0x45, 0x02, 0x01, 0x04
        };
        CHECK(vlcp256k1_ecdsa_recover_compact(msg32, 32, sigb64, pubkeyb, &pubkeyblen, 1, recid));
        CHECK(vlcp256k1_ecdsa_verify(msg32, 32, sigbder, sizeof(sigbder), pubkeyb, pubkeyblen) == 1);
        for (int recid2 = 0; recid2 < 4; recid2++) {
            unsigned char pubkey2b[33];
            int pubkey2blen = 33;
            CHECK(vlcp256k1_ecdsa_recover_compact(msg32, 32, sigb64, pubkey2b, &pubkey2blen, 1, recid2));
            /* Verifying with (order + r,4) should always fail. */
            CHECK(vlcp256k1_ecdsa_verify(msg32, 32, sigbderlong, sizeof(sigbderlong), pubkey2b, pubkey2blen) != 1);
        }
        /* Damage signature. */
        sigbder[7]++;
        CHECK(vlcp256k1_ecdsa_verify(msg32, 32, sigbder, sizeof(sigbder), pubkeyb, pubkeyblen) == 0);
    }

    /* Test the case where ECDSA recomputes a point that is infinity. */
    {
        vlcp256k1_ecdsa_sig_t sig;
        vlcp256k1_scalar_set_int(&sig.s, 1);
        vlcp256k1_scalar_negate(&sig.s, &sig.s);
        vlcp256k1_scalar_inverse(&sig.s, &sig.s);
        vlcp256k1_scalar_set_int(&sig.r, 1);
        vlcp256k1_gej_t keyj;
        vlcp256k1_ecmult_gen(&keyj, &sig.r);
        vlcp256k1_ge_t key;
        vlcp256k1_ge_set_gej(&key, &keyj);
        vlcp256k1_scalar_t msg = sig.s;
        CHECK(vlcp256k1_ecdsa_sig_verify(&sig, &key, &msg) == 0);
    }

    /* Test r/s equal to zero */
    {
        /* (1,1) encoded in DER. */
        unsigned char sigcder[8] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        unsigned char sigc64[64] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };
        unsigned char pubkeyc[65];
        int pubkeyclen = 65;
        CHECK(vlcp256k1_ecdsa_recover_compact(msg32, 32, sigc64, pubkeyc, &pubkeyclen, 0, 0) == 1);
        CHECK(vlcp256k1_ecdsa_verify(msg32, 32, sigcder, sizeof(sigcder), pubkeyc, pubkeyclen) == 1);
        sigcder[4] = 0;
        sigc64[31] = 0;
        CHECK(vlcp256k1_ecdsa_recover_compact(msg32, 32, sigc64, pubkeyb, &pubkeyblen, 1, 0) == 0);
        CHECK(vlcp256k1_ecdsa_verify(msg32, 32, sigcder, sizeof(sigcder), pubkeyc, pubkeyclen) == 0);
        sigcder[4] = 1;
        sigcder[7] = 0;
        sigc64[31] = 1;
        sigc64[63] = 0;
        CHECK(vlcp256k1_ecdsa_recover_compact(msg32, 32, sigc64, pubkeyb, &pubkeyblen, 1, 0) == 0);
        CHECK(vlcp256k1_ecdsa_verify(msg32, 32, sigcder, sizeof(sigcder), pubkeyc, pubkeyclen) == 0);
    }
}

void run_ecdsa_edge_cases(void) {
    test_ecdsa_edge_cases();
}

#ifdef ENABLE_OPENSSL_TESTS
EC_KEY *get_openssl_key(const vlcp256k1_scalar_t *key) {
    unsigned char privkey[300];
    int privkeylen;
    int compr = vlcp256k1_rand32() & 1;
    const unsigned char* pbegin = privkey;
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_vlcp256k1);
    CHECK(vlcp256k1_eckey_privkey_serialize(privkey, &privkeylen, key, compr));
    CHECK(d2i_ECPrivateKey(&ec_key, &pbegin, privkeylen));
    CHECK(EC_KEY_check_key(ec_key));
    return ec_key;
}

void test_ecdsa_openssl(void) {
    vlcp256k1_scalar_t key, msg;
    unsigned char message[32];
    vlcp256k1_rand256_test(message);
    vlcp256k1_scalar_set_b32(&msg, message, NULL);
    random_scalar_order_test(&key);
    vlcp256k1_gej_t qj;
    vlcp256k1_ecmult_gen(&qj, &key);
    vlcp256k1_ge_t q;
    vlcp256k1_ge_set_gej(&q, &qj);
    EC_KEY *ec_key = get_openssl_key(&key);
    CHECK(ec_key);
    unsigned char signature[80];
    unsigned int sigsize = 80;
    CHECK(ECDSA_sign(0, message, sizeof(message), signature, &sigsize, ec_key));
    vlcp256k1_ecdsa_sig_t sig;
    CHECK(vlcp256k1_ecdsa_sig_parse(&sig, signature, sigsize));
    CHECK(vlcp256k1_ecdsa_sig_verify(&sig, &q, &msg));
    vlcp256k1_scalar_t one;
    vlcp256k1_scalar_set_int(&one, 1);
    vlcp256k1_scalar_t msg2;
    vlcp256k1_scalar_add(&msg2, &msg, &one);
    CHECK(!vlcp256k1_ecdsa_sig_verify(&sig, &q, &msg2));

    random_sign(&sig, &key, &msg, NULL);
    int vlcp_sigsize = 80;
    CHECK(vlcp256k1_ecdsa_sig_serialize(signature, &vlcp_sigsize, &sig));
    CHECK(ECDSA_verify(0, message, sizeof(message), signature, vlcp_sigsize, ec_key) == 1);

    EC_KEY_free(ec_key);
}

void run_ecdsa_openssl(void) {
    for (int i=0; i<10*count; i++) {
        test_ecdsa_openssl();
    }
}
#endif

int main(int argc, char **argv) {
    /* find iteration count */
    if (argc > 1) {
        count = strtol(argv[1], NULL, 0);
    }

    /* find random seed */
    uint64_t seed;
    if (argc > 2) {
        seed = strtoull(argv[2], NULL, 0);
    } else {
        FILE *frand = fopen("/dev/urandom", "r");
        if (!frand || !fread(&seed, sizeof(seed), 1, frand)) {
            seed = time(NULL) * 1337;
        }
        fclose(frand);
    }
    vlcp256k1_rand_seed(seed);

    printf("test count = %i\n", count);
    printf("random seed = %llu\n", (unsigned long long)seed);

    /* initialize */
    vlcp256k1_start(VLCP256K1_START_SIGN | VLCP256K1_START_VERIFY);

    /* initializing a vlcond time shouldn't cause any harm or memory leaks. */
    vlcp256k1_start(VLCP256K1_START_SIGN | VLCP256K1_START_VERIFY);

    /* Likewise, re-running the internal init functions should be harmless. */
    vlcp256k1_fe_start();
    vlcp256k1_ge_start();
    vlcp256k1_scalar_start();
    vlcp256k1_ecdsa_start();

#ifndef USE_NUM_NONE
    /* num tests */
    run_num_smalltests();
#endif

    /* scalar tests */
    run_scalar_tests();

    /* field tests */
    run_field_inv();
    run_field_inv_var();
    run_field_inv_all();
    run_field_inv_all_var();
    run_sqr();
    run_sqrt();

    /* group tests */
    run_ge();

    /* ecmult tests */
    run_wnaf();
    run_point_times_order();
    run_ecmult_chain();

    /* ecdsa tests */
    run_ecdsa_sign_verify();
    run_ecdsa_end_to_end();
    run_ecdsa_edge_cases();
#ifdef ENABLE_OPENSSL_TESTS
    run_ecdsa_openssl();
#endif

    printf("random run = %llu\n", (unsigned long long)vlcp256k1_rand32() + ((unsigned long long)vlcp256k1_rand32() << 32));

    /* shutdown */
    vlcp256k1_stop();

    /* shutting down twice shouldn't cause any double frees. */
    vlcp256k1_stop();

    /* Same for the internal shutdown functions. */
    vlcp256k1_fe_stop();
    vlcp256k1_ge_stop();
    vlcp256k1_scalar_stop();
    vlcp256k1_ecdsa_stop();
    return 0;
}
