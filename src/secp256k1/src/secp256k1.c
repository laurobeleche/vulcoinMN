/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#define VLCP256K1_BUILD (1)

#include "include/vlcp256k1.h"

#include "util.h"
#include "num_impl.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "ecmult_gen_impl.h"
#include "ecdsa_impl.h"
#include "eckey_impl.h"

void vlcp256k1_start(unsigned int flags) {
    vlcp256k1_fe_start();
    vlcp256k1_ge_start();
    vlcp256k1_scalar_start();
    vlcp256k1_ecdsa_start();
    if (flags & VLCP256K1_START_SIGN) {
        vlcp256k1_ecmult_gen_start();
    }
    if (flags & VLCP256K1_START_VERIFY) {
        vlcp256k1_ecmult_start();
    }
}

void vlcp256k1_stop(void) {
    vlcp256k1_ecmult_stop();
    vlcp256k1_ecmult_gen_stop();
    vlcp256k1_ecdsa_stop();
    vlcp256k1_scalar_stop();
    vlcp256k1_ge_stop();
    vlcp256k1_fe_stop();
}

int vlcp256k1_ecdsa_verify(const unsigned char *msg, int msglen, const unsigned char *sig, int siglen, const unsigned char *pubkey, int pubkeylen) {
    DEBUG_CHECK(vlcp256k1_ecmult_consts != NULL);
    DEBUG_CHECK(msg != NULL);
    DEBUG_CHECK(msglen <= 32);
    DEBUG_CHECK(sig != NULL);
    DEBUG_CHECK(pubkey != NULL);

    unsigned char msg32[32] = {0};
    memcpy(msg32 + 32 - msglen, msg, msglen);
    int ret = -3;
    vlcp256k1_scalar_t m;
    vlcp256k1_ecdsa_sig_t s;
    vlcp256k1_ge_t q;
    vlcp256k1_scalar_set_b32(&m, msg32, NULL);

    if (!vlcp256k1_eckey_pubkey_parse(&q, pubkey, pubkeylen)) {
        ret = -1;
        goto end;
    }
    if (!vlcp256k1_ecdsa_sig_parse(&s, sig, siglen)) {
        ret = -2;
        goto end;
    }
    if (!vlcp256k1_ecdsa_sig_verify(&s, &q, &m)) {
        ret = 0;
        goto end;
    }
    ret = 1;
end:
    return ret;
}

int vlcp256k1_ecdsa_sign(const unsigned char *message, int messagelen, unsigned char *signature, int *signaturelen, const unsigned char *vlckey, const unsigned char *nonce) {
    DEBUG_CHECK(vlcp256k1_ecmult_gen_consts != NULL);
    DEBUG_CHECK(message != NULL);
    DEBUG_CHECK(messagelen <= 32);
    DEBUG_CHECK(signature != NULL);
    DEBUG_CHECK(signaturelen != NULL);
    DEBUG_CHECK(vlckey != NULL);
    DEBUG_CHECK(nonce != NULL);

    vlcp256k1_scalar_t vlc, non, msg;
    vlcp256k1_scalar_set_b32(&vlc, vlckey, NULL);
    int overflow = 0;
    vlcp256k1_scalar_set_b32(&non, nonce, &overflow);
    {
        unsigned char c[32] = {0};
        memcpy(c + 32 - messagelen, message, messagelen);
        vlcp256k1_scalar_set_b32(&msg, c, NULL);
        memset(c, 0, 32);
    }
    int ret = !vlcp256k1_scalar_is_zero(&non) && !overflow;
    vlcp256k1_ecdsa_sig_t sig;
    if (ret) {
        ret = vlcp256k1_ecdsa_sig_sign(&sig, &vlc, &msg, &non, NULL);
    }
    if (ret) {
        vlcp256k1_ecdsa_sig_serialize(signature, signaturelen, &sig);
    }
    vlcp256k1_scalar_clear(&msg);
    vlcp256k1_scalar_clear(&non);
    vlcp256k1_scalar_clear(&vlc);
    return ret;
}

int vlcp256k1_ecdsa_sign_compact(const unsigned char *message, int messagelen, unsigned char *sig64, const unsigned char *vlckey, const unsigned char *nonce, int *recid) {
    DEBUG_CHECK(vlcp256k1_ecmult_gen_consts != NULL);
    DEBUG_CHECK(message != NULL);
    DEBUG_CHECK(messagelen <= 32);
    DEBUG_CHECK(sig64 != NULL);
    DEBUG_CHECK(vlckey != NULL);
    DEBUG_CHECK(nonce != NULL);

    vlcp256k1_scalar_t vlc, non, msg;
    vlcp256k1_scalar_set_b32(&vlc, vlckey, NULL);
    int overflow = 0;
    vlcp256k1_scalar_set_b32(&non, nonce, &overflow);
    {
        unsigned char c[32] = {0};
        memcpy(c + 32 - messagelen, message, messagelen);
        vlcp256k1_scalar_set_b32(&msg, c, NULL);
        memset(c, 0, 32);
    }
    int ret = !vlcp256k1_scalar_is_zero(&non) && !overflow;
    vlcp256k1_ecdsa_sig_t sig;
    if (ret) {
        ret = vlcp256k1_ecdsa_sig_sign(&sig, &vlc, &msg, &non, recid);
    }
    if (ret) {
        vlcp256k1_scalar_get_b32(sig64, &sig.r);
        vlcp256k1_scalar_get_b32(sig64 + 32, &sig.s);
    }
    vlcp256k1_scalar_clear(&msg);
    vlcp256k1_scalar_clear(&non);
    vlcp256k1_scalar_clear(&vlc);
    return ret;
}

int vlcp256k1_ecdsa_recover_compact(const unsigned char *msg, int msglen, const unsigned char *sig64, unsigned char *pubkey, int *pubkeylen, int compressed, int recid) {
    DEBUG_CHECK(vlcp256k1_ecmult_consts != NULL);
    DEBUG_CHECK(msg != NULL);
    DEBUG_CHECK(msglen <= 32);
    DEBUG_CHECK(sig64 != NULL);
    DEBUG_CHECK(pubkey != NULL);
    DEBUG_CHECK(pubkeylen != NULL);
    DEBUG_CHECK(recid >= 0 && recid <= 3);

    int ret = 0;
    unsigned char msg32[32] = {0};
    memcpy(msg32 + 32 - msglen, msg, msglen);
    vlcp256k1_scalar_t m;
    vlcp256k1_ecdsa_sig_t sig;
    int overflow = 0;
    vlcp256k1_scalar_set_b32(&sig.r, sig64, &overflow);
    if (overflow) {
        return 0;
    }
    vlcp256k1_scalar_set_b32(&sig.s, sig64 + 32, &overflow);
    if (overflow) {
        return 0;
    }
    vlcp256k1_scalar_set_b32(&m, msg32, NULL);

    vlcp256k1_ge_t q;
    if (vlcp256k1_ecdsa_sig_recover(&sig, &q, &m, recid)) {
        ret = vlcp256k1_eckey_pubkey_serialize(&q, pubkey, pubkeylen, compressed);
    }
    return ret;
}

int vlcp256k1_ec_vlckey_verify(const unsigned char *vlckey) {
    DEBUG_CHECK(vlckey != NULL);

    vlcp256k1_scalar_t vlc;
    int overflow;
    vlcp256k1_scalar_set_b32(&vlc, vlckey, &overflow);
    int ret = !vlcp256k1_scalar_is_zero(&vlc) && !overflow;
    vlcp256k1_scalar_clear(&vlc);
    return ret;
}

int vlcp256k1_ec_pubkey_verify(const unsigned char *pubkey, int pubkeylen) {
    DEBUG_CHECK(pubkey != NULL);

    vlcp256k1_ge_t q;
    return vlcp256k1_eckey_pubkey_parse(&q, pubkey, pubkeylen);
}

int vlcp256k1_ec_pubkey_create(unsigned char *pubkey, int *pubkeylen, const unsigned char *vlckey, int compressed) {
    DEBUG_CHECK(vlcp256k1_ecmult_gen_consts != NULL);
    DEBUG_CHECK(pubkey != NULL);
    DEBUG_CHECK(pubkeylen != NULL);
    DEBUG_CHECK(vlckey != NULL);

    vlcp256k1_scalar_t vlc;
    vlcp256k1_scalar_set_b32(&vlc, vlckey, NULL);
    vlcp256k1_gej_t pj;
    vlcp256k1_ecmult_gen(&pj, &vlc);
    vlcp256k1_scalar_clear(&vlc);
    vlcp256k1_ge_t p;
    vlcp256k1_ge_set_gej(&p, &pj);
    return vlcp256k1_eckey_pubkey_serialize(&p, pubkey, pubkeylen, compressed);
}

int vlcp256k1_ec_pubkey_decompress(unsigned char *pubkey, int *pubkeylen) {
    DEBUG_CHECK(pubkey != NULL);
    DEBUG_CHECK(pubkeylen != NULL);

    vlcp256k1_ge_t p;
    if (!vlcp256k1_eckey_pubkey_parse(&p, pubkey, *pubkeylen))
        return 0;
    return vlcp256k1_eckey_pubkey_serialize(&p, pubkey, pubkeylen, 0);
}

int vlcp256k1_ec_privkey_tweak_add(unsigned char *vlckey, const unsigned char *tweak) {
    DEBUG_CHECK(vlckey != NULL);
    DEBUG_CHECK(tweak != NULL);

    vlcp256k1_scalar_t term;
    int overflow = 0;
    vlcp256k1_scalar_set_b32(&term, tweak, &overflow);
    vlcp256k1_scalar_t vlc;
    vlcp256k1_scalar_set_b32(&vlc, vlckey, NULL);

    int ret = vlcp256k1_eckey_privkey_tweak_add(&vlc, &term) && !overflow;
    if (ret) {
        vlcp256k1_scalar_get_b32(vlckey, &vlc);
    }

    vlcp256k1_scalar_clear(&vlc);
    vlcp256k1_scalar_clear(&term);
    return ret;
}

int vlcp256k1_ec_pubkey_tweak_add(unsigned char *pubkey, int pubkeylen, const unsigned char *tweak) {
    DEBUG_CHECK(vlcp256k1_ecmult_consts != NULL);
    DEBUG_CHECK(pubkey != NULL);
    DEBUG_CHECK(tweak != NULL);

    vlcp256k1_scalar_t term;
    int overflow = 0;
    vlcp256k1_scalar_set_b32(&term, tweak, &overflow);
    if (overflow) {
        return 0;
    }
    vlcp256k1_ge_t p;
    int ret = vlcp256k1_eckey_pubkey_parse(&p, pubkey, pubkeylen);
    if (ret) {
        ret = vlcp256k1_eckey_pubkey_tweak_add(&p, &term);
    }
    if (ret) {
        int oldlen = pubkeylen;
        ret = vlcp256k1_eckey_pubkey_serialize(&p, pubkey, &pubkeylen, oldlen <= 33);
        VERIFY_CHECK(pubkeylen == oldlen);
    }

    return ret;
}

int vlcp256k1_ec_privkey_tweak_mul(unsigned char *vlckey, const unsigned char *tweak) {
    DEBUG_CHECK(vlckey != NULL);
    DEBUG_CHECK(tweak != NULL);

    vlcp256k1_scalar_t factor;
    int overflow = 0;
    vlcp256k1_scalar_set_b32(&factor, tweak, &overflow);
    vlcp256k1_scalar_t vlc;
    vlcp256k1_scalar_set_b32(&vlc, vlckey, NULL);
    int ret = vlcp256k1_eckey_privkey_tweak_mul(&vlc, &factor) && !overflow;
    if (ret) {
        vlcp256k1_scalar_get_b32(vlckey, &vlc);
    }

    vlcp256k1_scalar_clear(&vlc);
    vlcp256k1_scalar_clear(&factor);
    return ret;
}

int vlcp256k1_ec_pubkey_tweak_mul(unsigned char *pubkey, int pubkeylen, const unsigned char *tweak) {
    DEBUG_CHECK(vlcp256k1_ecmult_consts != NULL);
    DEBUG_CHECK(pubkey != NULL);
    DEBUG_CHECK(tweak != NULL);

    vlcp256k1_scalar_t factor;
    int overflow = 0;
    vlcp256k1_scalar_set_b32(&factor, tweak, &overflow);
    if (overflow) {
        return 0;
    }
    vlcp256k1_ge_t p;
    int ret = vlcp256k1_eckey_pubkey_parse(&p, pubkey, pubkeylen);
    if (ret) {
        ret = vlcp256k1_eckey_pubkey_tweak_mul(&p, &factor);
    }
    if (ret) {
        int oldlen = pubkeylen;
        ret = vlcp256k1_eckey_pubkey_serialize(&p, pubkey, &pubkeylen, oldlen <= 33);
        VERIFY_CHECK(pubkeylen == oldlen);
    }

    return ret;
}

int vlcp256k1_ec_privkey_export(const unsigned char *vlckey, unsigned char *privkey, int *privkeylen, int compressed) {
    DEBUG_CHECK(vlckey != NULL);
    DEBUG_CHECK(privkey != NULL);
    DEBUG_CHECK(privkeylen != NULL);

    vlcp256k1_scalar_t key;
    vlcp256k1_scalar_set_b32(&key, vlckey, NULL);
    int ret = vlcp256k1_eckey_privkey_serialize(privkey, privkeylen, &key, compressed);
    vlcp256k1_scalar_clear(&key);
    return ret;
}

int vlcp256k1_ec_privkey_import(unsigned char *vlckey, const unsigned char *privkey, int privkeylen) {
    DEBUG_CHECK(vlckey != NULL);
    DEBUG_CHECK(privkey != NULL);

    vlcp256k1_scalar_t key;
    int ret = vlcp256k1_eckey_privkey_parse(&key, privkey, privkeylen);
    if (ret)
        vlcp256k1_scalar_get_b32(vlckey, &key);
    vlcp256k1_scalar_clear(&key);
    return ret;
}
