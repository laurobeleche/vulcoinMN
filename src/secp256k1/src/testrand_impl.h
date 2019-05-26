/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _VLCP256K1_TESTRAND_IMPL_H_
#define _VLCP256K1_TESTRAND_IMPL_H_

#include <stdint.h>
#include <string.h>

#include "testrand.h"

static uint32_t vlcp256k1_Rz = 11, vlcp256k1_Rw = 11;

VLCP256K1_INLINE static void vlcp256k1_rand_seed(uint64_t v) {
    vlcp256k1_Rz = v >> 32;
    vlcp256k1_Rw = v;

    if (vlcp256k1_Rz == 0 || vlcp256k1_Rz == 0x9068ffffU) {
        vlcp256k1_Rz = 111;
    }
    if (vlcp256k1_Rw == 0 || vlcp256k1_Rw == 0x464fffffU) {
        vlcp256k1_Rw = 111;
    }
}

VLCP256K1_INLINE static uint32_t vlcp256k1_rand32(void) {
    vlcp256k1_Rz = 36969 * (vlcp256k1_Rz & 0xFFFF) + (vlcp256k1_Rz >> 16);
    vlcp256k1_Rw = 18000 * (vlcp256k1_Rw & 0xFFFF) + (vlcp256k1_Rw >> 16);
    return (vlcp256k1_Rw << 16) + (vlcp256k1_Rw >> 16) + vlcp256k1_Rz;
}

static void vlcp256k1_rand256(unsigned char *b32) {
    for (int i=0; i<8; i++) {
        uint32_t r = vlcp256k1_rand32();
        b32[i*4 + 0] = (r >>  0) & 0xFF;
        b32[i*4 + 1] = (r >>  8) & 0xFF;
        b32[i*4 + 2] = (r >> 16) & 0xFF;
        b32[i*4 + 3] = (r >> 24) & 0xFF;
    }
}

static void vlcp256k1_rand256_test(unsigned char *b32) {
    int bits=0;
    memset(b32, 0, 32);
    while (bits < 256) {
        uint32_t ent = vlcp256k1_rand32();
        int now = 1 + ((ent % 64)*((ent >> 6) % 32)+16)/31;
        uint32_t val = 1 & (ent >> 11);
        while (now > 0 && bits < 256) {
            b32[bits / 8] |= val << (bits % 8);
            now--;
            bits++;
        }
    }
}

#endif
