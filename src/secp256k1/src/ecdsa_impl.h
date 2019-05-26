/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/


#ifndef _VLCP256K1_ECDSA_IMPL_H_
#define _VLCP256K1_ECDSA_IMPL_H_

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"
#include "ecdsa.h"

typedef struct {
    vlcp256k1_fe_t order_as_fe;
    vlcp256k1_fe_t p_minus_order;
} vlcp256k1_ecdsa_consts_t;

static const vlcp256k1_ecdsa_consts_t *vlcp256k1_ecdsa_consts = NULL;

static void vlcp256k1_ecdsa_start(void) {
    if (vlcp256k1_ecdsa_consts != NULL)
        return;

    /* Allocate. */
    vlcp256k1_ecdsa_consts_t *ret = (vlcp256k1_ecdsa_consts_t*)malloc(sizeof(vlcp256k1_ecdsa_consts_t));

    static const unsigned char order[] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
    };

    vlcp256k1_fe_set_b32(&ret->order_as_fe, order);
    vlcp256k1_fe_negate(&ret->p_minus_order, &ret->order_as_fe, 1);
    vlcp256k1_fe_normalize(&ret->p_minus_order);

    /* Set the global pointer. */
    vlcp256k1_ecdsa_consts = ret;
}

static void vlcp256k1_ecdsa_stop(void) {
    if (vlcp256k1_ecdsa_consts == NULL)
        return;

    vlcp256k1_ecdsa_consts_t *c = (vlcp256k1_ecdsa_consts_t*)vlcp256k1_ecdsa_consts;
    vlcp256k1_ecdsa_consts = NULL;
    free(c);
}

static int vlcp256k1_ecdsa_sig_parse(vlcp256k1_ecdsa_sig_t *r, const unsigned char *sig, int size) {
    if (sig[0] != 0x30) return 0;
    int lenr = sig[3];
    if (5+lenr >= size) return 0;
    int lens = sig[lenr+5];
    if (sig[1] != lenr+lens+4) return 0;
    if (lenr+lens+6 > size) return 0;
    if (sig[2] != 0x02) return 0;
    if (lenr == 0) return 0;
    if (sig[lenr+4] != 0x02) return 0;
    if (lens == 0) return 0;
    const unsigned char *sp = sig + 6 + lenr;
    while (lens > 0 && sp[0] == 0) {
        lens--;
        sp++;
    }
    if (lens > 32) return 0;
    const unsigned char *rp = sig + 4;
    while (lenr > 0 && rp[0] == 0) {
        lenr--;
        rp++;
    }
    if (lenr > 32) return 0;
    unsigned char ra[32] = {0}, sa[32] = {0};
    memcpy(ra + 32 - lenr, rp, lenr);
    memcpy(sa + 32 - lens, sp, lens);
    int overflow = 0;
    vlcp256k1_scalar_set_b32(&r->r, ra, &overflow);
    if (overflow) return 0;
    vlcp256k1_scalar_set_b32(&r->s, sa, &overflow);
    if (overflow) return 0;
    return 1;
}

static int vlcp256k1_ecdsa_sig_serialize(unsigned char *sig, int *size, const vlcp256k1_ecdsa_sig_t *a) {
    unsigned char r[33] = {0}, s[33] = {0};
    vlcp256k1_scalar_get_b32(&r[1], &a->r);
    vlcp256k1_scalar_get_b32(&s[1], &a->s);
    unsigned char *rp = r, *sp = s;
    int lenR = 33, lenS = 33;
    while (lenR > 1 && rp[0] == 0 && rp[1] < 0x80) { lenR--; rp++; }
    while (lenS > 1 && sp[0] == 0 && sp[1] < 0x80) { lenS--; sp++; }
    if (*size < 6+lenS+lenR)
        return 0;
    *size = 6 + lenS + lenR;
    sig[0] = 0x30;
    sig[1] = 4 + lenS + lenR;
    sig[2] = 0x02;
    sig[3] = lenR;
    memcpy(sig+4, rp, lenR);
    sig[4+lenR] = 0x02;
    sig[5+lenR] = lenS;
    memcpy(sig+lenR+6, sp, lenS);
    return 1;
}

static int vlcp256k1_ecdsa_sig_recompute(vlcp256k1_scalar_t *r2, const vlcp256k1_ecdsa_sig_t *sig, const vlcp256k1_ge_t *pubkey, const vlcp256k1_scalar_t *message) {
    if (vlcp256k1_scalar_is_zero(&sig->r) || vlcp256k1_scalar_is_zero(&sig->s))
        return 0;

    int ret = 0;
    vlcp256k1_scalar_t sn, u1, u2;
    vlcp256k1_scalar_inverse_var(&sn, &sig->s);
    vlcp256k1_scalar_mul(&u1, &sn, message);
    vlcp256k1_scalar_mul(&u2, &sn, &sig->r);
    vlcp256k1_gej_t pubkeyj; vlcp256k1_gej_set_ge(&pubkeyj, pubkey);
    vlcp256k1_gej_t pr; vlcp256k1_ecmult(&pr, &pubkeyj, &u2, &u1);
    if (!vlcp256k1_gej_is_infinity(&pr)) {
        vlcp256k1_fe_t xr; vlcp256k1_gej_get_x_var(&xr, &pr);
        vlcp256k1_fe_normalize(&xr);
        unsigned char xrb[32]; vlcp256k1_fe_get_b32(xrb, &xr);
        vlcp256k1_scalar_set_b32(r2, xrb, NULL);
        ret = 1;
    }
    return ret;
}

static int vlcp256k1_ecdsa_sig_recover(const vlcp256k1_ecdsa_sig_t *sig, vlcp256k1_ge_t *pubkey, const vlcp256k1_scalar_t *message, int recid) {
    if (vlcp256k1_scalar_is_zero(&sig->r) || vlcp256k1_scalar_is_zero(&sig->s))
        return 0;

    unsigned char brx[32];
    vlcp256k1_scalar_get_b32(brx, &sig->r);
    vlcp256k1_fe_t fx;
    VERIFY_CHECK(vlcp256k1_fe_set_b32(&fx, brx)); /* brx comes from a scalar, so is less than the order; certainly less than p */
    if (recid & 2) {
        if (vlcp256k1_fe_cmp_var(&fx, &vlcp256k1_ecdsa_consts->p_minus_order) >= 0)
            return 0;
        vlcp256k1_fe_add(&fx, &vlcp256k1_ecdsa_consts->order_as_fe);
    }
    vlcp256k1_ge_t x;
    if (!vlcp256k1_ge_set_xo(&x, &fx, recid & 1))
        return 0;
    vlcp256k1_gej_t xj;
    vlcp256k1_gej_set_ge(&xj, &x);
    vlcp256k1_scalar_t rn, u1, u2;
    vlcp256k1_scalar_inverse_var(&rn, &sig->r);
    vlcp256k1_scalar_mul(&u1, &rn, message);
    vlcp256k1_scalar_negate(&u1, &u1);
    vlcp256k1_scalar_mul(&u2, &rn, &sig->s);
    vlcp256k1_gej_t qj;
    vlcp256k1_ecmult(&qj, &xj, &u2, &u1);
    vlcp256k1_ge_set_gej_var(pubkey, &qj);
    return !vlcp256k1_gej_is_infinity(&qj);
}

static int vlcp256k1_ecdsa_sig_verify(const vlcp256k1_ecdsa_sig_t *sig, const vlcp256k1_ge_t *pubkey, const vlcp256k1_scalar_t *message) {
    vlcp256k1_scalar_t r2;
    int ret = 0;
    ret = vlcp256k1_ecdsa_sig_recompute(&r2, sig, pubkey, message) && vlcp256k1_scalar_eq(&sig->r, &r2);
    return ret;
}

static int vlcp256k1_ecdsa_sig_sign(vlcp256k1_ecdsa_sig_t *sig, const vlcp256k1_scalar_t *vlckey, const vlcp256k1_scalar_t *message, const vlcp256k1_scalar_t *nonce, int *recid) {
    vlcp256k1_gej_t rp;
    vlcp256k1_ecmult_gen(&rp, nonce);
    vlcp256k1_ge_t r;
    vlcp256k1_ge_set_gej(&r, &rp);
    unsigned char b[32];
    vlcp256k1_fe_normalize(&r.x);
    vlcp256k1_fe_normalize(&r.y);
    vlcp256k1_fe_get_b32(b, &r.x);
    int overflow = 0;
    vlcp256k1_scalar_set_b32(&sig->r, b, &overflow);
    if (recid)
        *recid = (overflow ? 2 : 0) | (vlcp256k1_fe_is_odd(&r.y) ? 1 : 0);
    vlcp256k1_scalar_t n;
    vlcp256k1_scalar_mul(&n, &sig->r, vlckey);
    vlcp256k1_scalar_add(&n, &n, message);
    vlcp256k1_scalar_inverse(&sig->s, nonce);
    vlcp256k1_scalar_mul(&sig->s, &sig->s, &n);
    vlcp256k1_scalar_clear(&n);
    vlcp256k1_gej_clear(&rp);
    vlcp256k1_ge_clear(&r);
    if (vlcp256k1_scalar_is_zero(&sig->s))
        return 0;
    if (vlcp256k1_scalar_is_high(&sig->s)) {
        vlcp256k1_scalar_negate(&sig->s, &sig->s);
        if (recid)
            *recid ^= 1;
    }
    return 1;
}

static void vlcp256k1_ecdsa_sig_set_rs(vlcp256k1_ecdsa_sig_t *sig, const vlcp256k1_scalar_t *r, const vlcp256k1_scalar_t *s) {
    sig->r = *r;
    sig->s = *s;
}

#endif
