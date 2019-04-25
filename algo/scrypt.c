/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011-2014 pooler
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 *
 * *** (27-08-2018) 	Edited by Rollmeister for 2ways aarch64 support, inlineable sha256 and memcpy alternatives. 
 *			≈13+% performance improvement on 1gb 4 core armv8 boards, with small enough kernel (below 8mb)
 *			and reduced background task memory footprint. No perfomance regression in most cases for 2ways 
 *			compared to original 3ways while reducing memory requirements by 1/3rd. 
 *			Possibly due to significantly improved possibility of dual issue instruction ordering 
 *			which gcc8 does well. Refer to github repo or readme.md for compile instructions.
 *			Currently only works for arm64. aarch32 support has been tested to work by g4b.
 *			Might add support for it (Odroid XU4 users) in future. #UPDATE: Neon based stores, loads/eqxor.
			xor_salsa8() replaced.
 */

#include "miner.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#ifdef __linux__
#include <sys/mman.h>
#include <errno.h>
#endif

#if defined(__aarch64__)
#undef HAVE_SHA256_4WAY
#undef HAVE_SHA256_8WAY
#endif

#ifndef __aarch64__

static const uint32_t keypad[12] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280
};
static const uint32_t innerpad[11] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000004a0
};
static const uint32_t outerpad[8] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300
};

static const uint32_t finalblk[16] = {
	0x00000001, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000620
};

static inline void HMAC_SHA256_80_init(const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate)
{
	uint32_t ihash[8];
	uint32_t pad[16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	newmemcpy(pad, key + 16, 16);
	newmemcpy(pad + 4, keypad, 48);
	sha256_transform(tstate, pad, 0);
	newmemcpy(ihash, tstate, 32);

	sha256_init(ostate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform(ostate, pad, 0);

	sha256_init(tstate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	sha256_transform(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128(const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t istate[8], ostate2[8];
	uint32_t ibuf[16], obuf[16];
	int i, j;

	newmemcpy(istate, tstate, 32);
	sha256_transform(istate, salt, 0);
	
	newmemcpy(ibuf, salt + 16, 16);
	newmemcpy(ibuf + 5, innerpad, 44);
	newmemcpy(obuf + 8, outerpad, 32);

	for (i = 0; i < 4; i++) {
		newmemcpy(obuf, istate, 32);
		ibuf[4] = i + 1;
		sha256_transform(obuf, ibuf, 0);

		newmemcpy(ostate2, ostate, 32);
		sha256_transform(ostate2, obuf, 0);
		for (j = 0; j < 8; j++)
			output[8 * i + j] = swab32(ostate2[j]);
	}
}

static inline void PBKDF2_SHA256_128_32(uint32_t *tstate, uint32_t *ostate,
	const uint32_t *salt, uint32_t *output)
{
	uint32_t buf[16];
	int i;
	
	sha256_transform(tstate, salt, 1);
	sha256_transform(tstate, salt + 16, 1);
	sha256_transform(tstate, finalblk, 0);
	newmemcpy(buf, tstate, 32);
	newmemcpy(buf + 8, outerpad, 32);

	sha256_transform(ostate, buf, 0);
	for (i = 0; i < 8; i++)
		output[i] = swab32(ostate[i]);
}
#endif

#ifdef HAVE_SHA256_4WAY

static const uint32_t keypad_4way[4 * 12] = {
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000280, 0x00000280, 0x00000280, 0x00000280
};
static const uint32_t innerpad_4way[4 * 11] = {
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x000004a0, 0x000004a0, 0x000004a0, 0x000004a0
};
static const uint32_t outerpad_4way[4 * 8] = {
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000300, 0x00000300, 0x00000300, 0x00000300
};
static const uint32_t _ALIGN(16) finalblk_4way[4 * 16] = {
	0x00000001, 0x00000001, 0x00000001, 0x00000001,
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000620, 0x00000620, 0x00000620, 0x00000620
};

static inline void HMAC_SHA256_80_init_4way(const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate)
{
	uint32_t _ALIGN(16) ihash[4 * 8];
	uint32_t _ALIGN(16) pad[4 * 16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	newmemcpy(pad, key + 4 * 16, 4 * 16);
	newmemcpy(pad + 4 * 4, keypad_4way, 4 * 48);
	sha256_transform_4way(tstate, pad, 0);
	newmemcpy(ihash, tstate, 4 * 32);

	sha256_init_4way(ostate);
	for (i = 0; i < 4 * 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 4 * 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform_4way(ostate, pad, 0);

	sha256_init_4way(tstate);
	for (i = 0; i < 4 * 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 4 * 16; i++)
		pad[i] = 0x36363636;
	sha256_transform_4way(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128_4way(const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t _ALIGN(16) istate[4 * 8];
	uint32_t _ALIGN(16) ostate2[4 * 8];
	uint32_t _ALIGN(16) ibuf[4 * 16];
	uint32_t _ALIGN(16) obuf[4 * 16];
	int i, j;

	newmemcpy(istate, tstate, 4 * 32);
	sha256_transform_4way(istate, salt, 0);
	
	newmemcpy(ibuf, salt + 4 * 16, 4 * 16);
	newmemcpy(ibuf + 4 * 5, innerpad_4way, 4 * 44);
	newmemcpy(obuf + 4 * 8, outerpad_4way, 4 * 32);

	for (i = 0; i < 4; i++) {
		newmemcpy(obuf, istate, 4 * 32);
		ibuf[4 * 4 + 0] = i + 1;
		ibuf[4 * 4 + 1] = i + 1;
		ibuf[4 * 4 + 2] = i + 1;
		ibuf[4 * 4 + 3] = i + 1;
		sha256_transform_4way(obuf, ibuf, 0);

		newmemcpy(ostate2, ostate, 4 * 32);
		sha256_transform_4way(ostate2, obuf, 0);
		for (j = 0; j < 4 * 8; j++)
			output[4 * 8 * i + j] = swab32(ostate2[j]);
	}
}

static inline void PBKDF2_SHA256_128_32_4way(uint32_t *tstate,
	uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t _ALIGN(16) buf[4 * 16];
	int i;
	
	sha256_transform_4way(tstate, salt, 1);
	sha256_transform_4way(tstate, salt + 4 * 16, 1);
	sha256_transform_4way(tstate, finalblk_4way, 0);
	newmemcpy(buf, tstate, 4 * 32);
	newmemcpy(buf + 4 * 8, outerpad_4way, 4 * 32);

	sha256_transform_4way(ostate, buf, 0);
	for (i = 0; i < 4 * 8; i++)
		output[i] = swab32(ostate[i]);
}

#endif /* HAVE_SHA256_4WAY */


#ifdef HAVE_SHA256_8WAY

static const uint32_t _ALIGN(32) finalblk_8way[8 * 16] = {
	0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
	0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620
};

static inline void HMAC_SHA256_80_init_8way(const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate)
{
	uint32_t _ALIGN(32) ihash[8 * 8];
	uint32_t _ALIGN(32)  pad[8 * 16];
	int i;
	
	/* tstate is assumed to contain the midstate of key */
	newmemcpy(pad, key + 8 * 16, 8 * 16);
	for (i = 0; i < 8; i++)
		pad[8 * 4 + i] = 0x80000000;
	memset(pad + 8 * 5, 0x00, 8 * 40);
	for (i = 0; i < 8; i++)
		pad[8 * 15 + i] = 0x00000280;
	sha256_transform_8way(tstate, pad, 0);
	newmemcpy(ihash, tstate, 8 * 32);
	
	sha256_init_8way(ostate);
	for (i = 0; i < 8 * 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 8 * 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform_8way(ostate, pad, 0);
	
	sha256_init_8way(tstate);
	for (i = 0; i < 8 * 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 8 * 16; i++)
		pad[i] = 0x36363636;
	sha256_transform_8way(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128_8way(const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t _ALIGN(32) istate[8 * 8];
	uint32_t _ALIGN(32) ostate2[8 * 8];
	uint32_t _ALIGN(32) ibuf[8 * 16];
	uint32_t _ALIGN(32) obuf[8 * 16];
	int i, j;
	
	newmemcpy(istate, tstate, 8 * 32);
	sha256_transform_8way(istate, salt, 0);
	
	newmemcpy(ibuf, salt + 8 * 16, 8 * 16);
	for (i = 0; i < 8; i++)
		ibuf[8 * 5 + i] = 0x80000000;
	memset(ibuf + 8 * 6, 0x00, 8 * 36);
	for (i = 0; i < 8; i++)
		ibuf[8 * 15 + i] = 0x000004a0;
	
	for (i = 0; i < 8; i++)
		obuf[8 * 8 + i] = 0x80000000;
	memset(obuf + 8 * 9, 0x00, 8 * 24);
	for (i = 0; i < 8; i++)
		obuf[8 * 15 + i] = 0x00000300;
	
	for (i = 0; i < 4; i++) {
		newmemcpy(obuf, istate, 8 * 32);
		ibuf[8 * 4 + 0] = i + 1;
		ibuf[8 * 4 + 1] = i + 1;
		ibuf[8 * 4 + 2] = i + 1;
		ibuf[8 * 4 + 3] = i + 1;
		ibuf[8 * 4 + 4] = i + 1;
		ibuf[8 * 4 + 5] = i + 1;
		ibuf[8 * 4 + 6] = i + 1;
		ibuf[8 * 4 + 7] = i + 1;
		sha256_transform_8way(obuf, ibuf, 0);
		
		newmemcpy(ostate2, ostate, 8 * 32);
		sha256_transform_8way(ostate2, obuf, 0);
		for (j = 0; j < 8 * 8; j++)
			output[8 * 8 * i + j] = swab32(ostate2[j]);
	}
}

static inline void PBKDF2_SHA256_128_32_8way(uint32_t *tstate,
	uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t _ALIGN(32) buf[8 * 16];
	int i;
	
	sha256_transform_8way(tstate, salt, 1);
	sha256_transform_8way(tstate, salt + 8 * 16, 1);
	sha256_transform_8way(tstate, finalblk_8way, 0);
	
	newmemcpy(buf, tstate, 8 * 32);
	for (i = 0; i < 8; i++)
		buf[8 * 8 + i] = 0x80000000;
	memset(buf + 8 * 9, 0x00, 8 * 24);
	for (i = 0; i < 8; i++)
		buf[8 * 15 + i] = 0x00000300;
	sha256_transform_8way(ostate, buf, 0);
	
	for (i = 0; i < 8 * 8; i++)
		output[i] = swab32(ostate[i]);
}

#endif /* HAVE_SHA256_8WAY */


#if defined(USE_ASM) && defined(__x86_64__)

#define SCRYPT_MAX_WAYS 12
#define HAVE_SCRYPT_3WAY 1
int scrypt_best_throughput();
void scrypt_core(uint32_t *X, uint32_t *V, int N);
void scrypt_core_3way(uint32_t *X, uint32_t *V, int N);
#if defined(USE_AVX2)
#undef SCRYPT_MAX_WAYS
#define SCRYPT_MAX_WAYS 24
#define HAVE_SCRYPT_6WAY 1
void scrypt_core_6way(uint32_t *X, uint32_t *V, int N);
#endif

#elif defined(USE_ASM) && defined(__i386__)

#define SCRYPT_MAX_WAYS 4
#define scrypt_best_throughput() 1
void scrypt_core(uint32_t *X, uint32_t *V, int N);

#elif defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)

void scrypt_core(uint32_t *X, uint32_t *V, int N);
#if defined(__ARM_NEON)
#undef HAVE_SHA256_4WAY
#define SCRYPT_MAX_WAYS 3
#define HAVE_SCRYPT_3WAY 1
#define scrypt_best_throughput() 3
void scrypt_core_3way(uint32_t *X, uint32_t *V, int N);
#endif

#elif defined(__aarch64__)

#include <stdint.h>
#include <arm_neon.h>

#undef HAVE_SHA256_4WAY
#define SCRYPT_MAX_WAYS 2
#define HAVE_SCRYPT_2WAY 1
#define scrypt_best_throughput() 2

//simplified & inlinable neon version of memcpy. "128-bit" copying.
static inline void newmemcpy(uint32_t *dstp, const uint32_t *srcp, uint len)
{
	uint32x4_t *dst = (uint32x4_t *) dstp;
	uint32x4_t *src = (uint32x4_t *) srcp;
	uint i;

	for(i = 0; i < (len / sizeof(uint32x4_t)); i++)
		*dst++ = *src++;
}

//simplified & inlinable neon version of memcpy with "tail" handling.
static inline void newmemcpytail(uint32_t *dstp, const uint32_t *srcp, uint len)
{
	uint32x4_t *dst = (uint32x4_t *) dstp;
	uint32x4_t *src = (uint32x4_t *) srcp;
	uint i, tail;

	for(i = 0; i < (len / sizeof(uint32x4_t)); i++)
		*dst++ = *src++;

	tail = len & (sizeof(uint32x4_t) - 1);
	//if(tail) { //one instance requires this
		uchar *dstb = (uchar *) dstp;
		uchar *srcb = (uchar *) srcp;

		for(i = len - tail; i < len; i++)
			dstb[i] = srcb[i];
	//}
}

// Obsolete variables used in sha256 steps
/*static const uint32_t sha256_h[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};*/

/*static uint32_t bufouterpad[16] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x80000000, 0, 0, 0, 
	0, 0, 0, 0x00000300
};*/
/*
static uint32_t finalblock[48] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x00000001, 0x80000000, 0, 0, 
	0, 0, 0, 0, 
	0, 0, 0, 0, 
	0, 0, 0, 0x00000620
};*/

/*static uint32_t pad[16] = {
	0, 0, 0, 0, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280
};

static uint32_t pad2[16] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
};

static uint32_t pad3[16] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x36363636, 0x36363636, 0x36363636, 0x36363636,
	0x36363636, 0x36363636, 0x36363636, 0x36363636,
};*/

typedef struct uint32x4x8_t
{
  uint32x4_t one,two,three,four,five,six,seven,eight;
} uint32x4x8_t;

static const uint32x4x2_t sha256_h_neon = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32x4x4_t k0 = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
};

static const uint32x4x4_t k4 = {
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
};

static const uint32x4x4_t k8 = {
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
};

static const uint32x4x4_t kc = {
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

/*static inline void sha256_init_armv8(uint32_t *state)
{
	newmemcpy(state, sha256_h, 32);
}*/

#define Rx(T0, T1, K, W0, W1, W2, W3)      \
	W0 = vsha256su0q_u32( W0, W1 );    \
	ddtmp = dd.val[0];                           \
	T1 = vaddq_u32( W1, K );           \
	dd.val[0] = vsha256hq_u32( dd.val[0], dd.val[1], T0 );  \
	dd.val[1] = vsha256h2q_u32( dd.val[1], ddtmp, T0 ); \
	W0 = vsha256su1q_u32( W0, W2, W3 );

#define Ry(T0, T1, K, W1)                  \
	ddtmp = dd.val[0];                           \
	T1 = vaddq_u32( W1, K  );          \
	dd.val[0] = vsha256hq_u32( dd.val[0], dd.val[1], T0 );  \
	dd.val[1] = vsha256h2q_u32( dd.val[1], ddtmp, T0 );

#define Rz(T0)                             \
	ddtmp = dd.val[0];                       	   \
	dd.val[0] = vsha256hq_u32( dd.val[0], dd.val[1], T0 );  \
	dd.val[1] = vsha256h2q_u32( dd.val[1], ddtmp, T0 );

#define __swap32gen(x)							\
    (__uint32_t)(((__uint32_t)(x) & 0xff) << 24 |			\
    ((__uint32_t)(x) & 0xff00) << 8 | ((__uint32_t)(x) & 0xff0000) >> 8 |\
    ((__uint32_t)(x) & 0xff000000) >> 24)

//based on sha2armv8.c in new vrm wallet. Minor performance gain from inlineable shrunken code.
static inline void sha256_transform_armv8(uint32_t state[8], const uint32_t data[16])
{
	static uint32x4_t w0, w1, w2, w3, ddtmp;
	static uint32x4x2_t dd, sta;
	static uint32x4_t t0, t1;

	/* load state */
	sta.val[0] = vld1q_u32(&state[0]);
	sta.val[1] = vld1q_u32(&state[4]);
 
	/* load message */
	w0 = vld1q_u32(data);
	w1 = vld1q_u32(data + 4);
	t0 = vaddq_u32(w0, k0.val[0]);
	w2 = vld1q_u32(data + 8);
	dd = sta;
	w3 = vld1q_u32(data + 12);

	/*if (__builtin_expect(swap, 0)) { moved to sha256 compress function
		w0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w0)));
		w1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w1)));
		w2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w2)));
		w3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w3)));
	}*/

	//dd.val[1] = s1;

	/* perform rounds of four */
	Rx(t0, t1, k0.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k0.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k0.val[3], w2, w3, w0, w1);
	Rx(t1, t0, k4.val[0], w3, w0, w1, w2);
	Rx(t0, t1, k4.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k4.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k4.val[3], w2, w3, w0, w1);
	Rx(t1, t0, k8.val[0], w3, w0, w1, w2);
	Rx(t0, t1, k8.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k8.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k8.val[3], w2, w3, w0, w1);
	Rx(t1, t0, kc.val[0], w3, w0, w1, w2);
	Ry(t0, t1, kc.val[1], w1);
	Ry(t1, t0, kc.val[2], w2);
	Ry(t0, t1, kc.val[3], w3);
	Rz(t1);

	/* update state */
	sta.val[0] = vaddq_u32(sta.val[0], dd.val[0]);
	sta.val[1] = vaddq_u32(sta.val[1], dd.val[1]);

	/* save state */
	vst1q_u32(&state[0], sta.val[0]);
	vst1q_u32(&state[4], sta.val[1]);
}

static inline void sha256_transform_armv8_init(uint32_t state[8], const uint32_t data[16])
{
	static uint32x4_t w0, w1, w2, w3, ddtmp;
	static uint32x4x2_t dd, sta;
	static uint32x4_t t0, t1;

	/* load message */
	w0 = vld1q_u32(data);
	w1 = vld1q_u32(data + 4);
	t0 = vaddq_u32(w0, k0.val[0]);
	w2 = vld1q_u32(data + 8);
	w3 = vld1q_u32(data + 12);

	/* initialize t0, dd.val[0], dd.val[1] */
 
	dd = sha256_h_neon;
	//dd.val[1] = s1;

	/* perform rounds of four */
	Rx(t0, t1, k0.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k0.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k0.val[3], w2, w3, w0, w1);
	Rx(t1, t0, k4.val[0], w3, w0, w1, w2);
	Rx(t0, t1, k4.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k4.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k4.val[3], w2, w3, w0, w1);
	Rx(t1, t0, k8.val[0], w3, w0, w1, w2);
	Rx(t0, t1, k8.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k8.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k8.val[3], w2, w3, w0, w1);
	Rx(t1, t0, kc.val[0], w3, w0, w1, w2);
	Ry(t0, t1, kc.val[1], w1);
	Ry(t1, t0, kc.val[2], w2);
	Ry(t0, t1, kc.val[3], w3);
	Rz(t1);

	/* update state */
	sta.val[0] = vaddq_u32(sha256_h_neon.val[0], dd.val[0]);
	sta.val[1] = vaddq_u32(sha256_h_neon.val[1], dd.val[1]);

	/* save state */
	vst1q_u32(&state[0], sta.val[0]);
	vst1q_u32(&state[4], sta.val[1]);
}

static inline void sha256_transform_80_128_armv8(uint32_t *state, const uint32_t *data, const uint32_t *tstate, uint32_t *output, bool finalstep)
{
	static uint32x4_t w0, w1, w2, w3, ddtmp;
	static uint32x4x2_t dd, sta;
	static uint32x4_t t0, t1;

	/* load state */
	sta.val[0] = vld1q_u32(&tstate[0]);
	sta.val[1] = vld1q_u32(&tstate[4]);
	dd = sta;
	/* load message */
	w0 = vld1q_u32(data);
	w1 = vld1q_u32(data + 4);
	t0 = vaddq_u32(w0, k0.val[0]);
	w2 = vld1q_u32(data + 8);
	w3 = vld1q_u32(data + 12);

	/* initialize t0, dd.val[0], dd.val[1] */
 
	//dd.val[1] = s1;

	/* perform rounds of four */
	Rx(t0, t1, k0.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k0.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k0.val[3], w2, w3, w0, w1);
	Rx(t1, t0, k4.val[0], w3, w0, w1, w2);
	Rx(t0, t1, k4.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k4.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k4.val[3], w2, w3, w0, w1);
	Rx(t1, t0, k8.val[0], w3, w0, w1, w2);
	Rx(t0, t1, k8.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k8.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k8.val[3], w2, w3, w0, w1);
	Rx(t1, t0, kc.val[0], w3, w0, w1, w2);
	Ry(t0, t1, kc.val[1], w1);
	Ry(t1, t0, kc.val[2], w2);
	Ry(t0, t1, kc.val[3], w3);
	Rz(t1);

	/* update state */
	sta.val[0] = vaddq_u32(sta.val[0], dd.val[0]);
	sta.val[1] = vaddq_u32(sta.val[1], dd.val[1]);

	/* save state */
	if(!finalstep) {
		vst1q_u32(&state[0], sta.val[0]);
		vst1q_u32(&state[4], sta.val[1]);
	} else {
		sta.val[0] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(sta.val[0])));
		sta.val[1] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(sta.val[1])));
		vst1q_u32(output + 0, sta.val[0]);
		vst1q_u32(output + 4, sta.val[1]);
	}
}

// Not a true compress function. Last block is not reversed. Customised for specific use.
static void sha256_compress_armv8(uint32_t *state, const uint32_t *data, int blocks, uint32_t *output, bool finalstep)
{
	static uint32x4_t w0, w1, w2, w3, ddtmp;
	static uint32x4x2_t dd, sta;
	static uint32x4_t t0, t1;

	/* load state */
	sta.val[0] = vld1q_u32(&state[0]);
	sta.val[1] = vld1q_u32(&state[4]);

while (blocks)
      {
 
	/* load message */
	w0 = vld1q_u32(data);
	w1 = vld1q_u32(data + 4);
	dd = sta;
	w2 = vld1q_u32(data + 8);
	w3 = vld1q_u32(data + 12);

	if (blocks != 1) {
		w0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w0)));
		w1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w1)));
		w2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w2)));
		w3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w3)));
	}

	/* initialize t0, dd.val[0], dd.val[1] */
	t0 = vaddq_u32(w0, k0.val[0]);
 
	//dd.val[1] = s1;

	/* perform rounds of four */
	Rx(t0, t1, k0.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k0.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k0.val[3], w2, w3, w0, w1);
	Rx(t1, t0, k4.val[0], w3, w0, w1, w2);
	Rx(t0, t1, k4.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k4.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k4.val[3], w2, w3, w0, w1);
	Rx(t1, t0, k8.val[0], w3, w0, w1, w2);
	Rx(t0, t1, k8.val[1], w0, w1, w2, w3);
	Rx(t1, t0, k8.val[2], w1, w2, w3, w0);
	Rx(t0, t1, k8.val[3], w2, w3, w0, w1);
	Rx(t1, t0, kc.val[0], w3, w0, w1, w2);
	Ry(t0, t1, kc.val[1], w1);
	Ry(t1, t0, kc.val[2], w2);
	Ry(t0, t1, kc.val[3], w3);
	Rz(t1);

	/* update state */
	sta.val[0] = vaddq_u32(sta.val[0], dd.val[0]);
	sta.val[1] = vaddq_u32(sta.val[1], dd.val[1]);

      data += 16;
      blocks--;
}
	/* save state */
	vst1q_u32(&state[0], sta.val[0]);
	vst1q_u32(&state[4], sta.val[1]);

	/* save state */
	if(!finalstep) {
		vst1q_u32(&state[0], sta.val[0]);
		vst1q_u32(&state[4], sta.val[1]);
	} else {
		sta.val[0] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(sta.val[0])));
		sta.val[1] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(sta.val[1])));
		vst1q_u32(output + 0, sta.val[0]);
		vst1q_u32(output + 4, sta.val[1]);
	}
}

static inline void HMAC_SHA256_80_init_armv8(const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate, uint32_t numways)
{
	//uint32_t ihash[8];
	//uint32_t pad[16];
	//size_t numkeys = (sizeof(key)/sizeof(key[0]));
	uint32_t pad[48] = {
	0, 0, 0, 0, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x36363636, 0x36363636, 0x36363636, 0x36363636,
	0x36363636, 0x36363636, 0x36363636, 0x36363636,
	};
/*
	uint32_t pad2[16] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	};

	uint32_t pad3[16] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x36363636, 0x36363636, 0x36363636, 0x36363636,
	0x36363636, 0x36363636, 0x36363636, 0x36363636,
	};*/

	int i;
	while (numways)
	{
	/* tstate is assumed to contain the midstate of key */
	newmemcpy(pad, key + 16, 16);
	//newmemcpy(pad + 4, keypad, 48);
	sha256_transform_armv8(tstate, pad);
	//newmemcpy(ihash, tstate, 32);

	uint32x4_t *dst = (uint32x4_t *) &pad[16];
	uint32x4_t *dst2 = (uint32x4_t *) tstate;
	*dst++ = *dst2++ ^ 0x5c5c5c5c;	*dst++ = *dst2++ ^ 0x5c5c5c5c;

	//sha256_init_armv8(ostate);
/*	for (i = 0; i < 8; i++)
		pad2[i] = tstate[i] ^ 1549556828;*/
	/*for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;*/
	sha256_transform_armv8_init(ostate, &pad[16]);

	//sha256_init_armv8(tstate);
	for (i = 0; i < 8; i++)
		pad[i+32] = tstate[i] ^ 0x36363636;
	/*for (; i < 16; i++)
		pad[i] = 0x36363636;*/
	sha256_transform_armv8_init(tstate, &pad[32]);
	key += 20;
	ostate += 8;
	tstate += 8;
	numways--;
	}
}

static inline void PBKDF2_SHA256_80_128_armv8(const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t istate[8], ostate2[8];
	/*uint32_t ibuf[16], obuf[16];*/

	uint32_t ibuf[16] = {
	0, 0, 0, 0,
	0, 0x80000000, 0, 0,
	0, 0, 0, 0, 
	0, 0, 0, 0x000004a0
	};
	uint32_t bufouterpad[16] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x80000000, 0, 0, 0, 
	0, 0, 0, 0x00000300
	};
	int i, j;

	//newmemcpy(istate, tstate, 32);
	sha256_transform_80_128_armv8(istate, salt, tstate, output, false);
	
	newmemcpy(ibuf, salt + 16, 16);
	//newmemcpytail(ibuf + 5, innerpad, 44);
	//newmemcpy(obuf + 8, outerpad, 32);

	for (i = 0; i < 4; i++) {
		//newmemcpy(obuf, istate, 32);
		ibuf[4] = i + 1;
		//sha256_transform_80_128_armv8(obuf, ibuf, istate);
		sha256_transform_80_128_armv8(bufouterpad, ibuf, istate, output, false);
	asm("":::"memory");
		//newmemcpy(ostate2, ostate, 32);
		sha256_transform_80_128_armv8(ostate2, bufouterpad, ostate, output, true);
		/*for (j = 0; j < 8; j++)
			output[8 * i + j] = __builtin_bswap32(ostate2[j]);*/
		output+=8;
	}
}

static void PBKDF2_SHA256_128_32_armv8(uint32_t *tstate, uint32_t *ostate,
	const uint32_t *salt, uint32_t *output, uint32_t numways)
{
	//uint32_t buf[16];
	//uint32_t blocks[48];
	uint32_t finalblock[48] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x00000001, 0x80000000, 0, 0, 
	0, 0, 0, 0, 
	0, 0, 0, 0, 
	0, 0, 0, 0x00000620
	};
	uint32_t bufouterpad[16] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0x80000000, 0, 0, 0, 
	0, 0, 0, 0x00000300
	};
	//int i;
	while (numways)
	{
	//newmemcpy(blocks, salt, 128);
	//newmemcpy(blocks + 32, finalblk, 64);
	newmemcpy(finalblock, salt, 128);

	//printf("0x%08x 0x%08x\n", finalblk[15], __builtin_bswap32(finalblk[15]));
	
	sha256_compress_armv8(tstate, finalblock, 3, output, false);

/*	sha256_transform_armv8(tstate, salt, 1);
	sha256_transform_armv8(tstate, salt + 16, 1);
	sha256_transform_armv8(tstate, finalblk, 0);*/
	//newmemcpy(buf, tstate, 32);
	newmemcpy(bufouterpad, tstate, 32);
	//newmemcpy(buf + 8, outerpad, 32);

	sha256_compress_armv8(ostate, bufouterpad, 1, output, true);
	/*for (i = 0; i < 8; i++)
		output[i] = __builtin_bswap32(ostate[i]);*/
	salt += 32;
	ostate += 8;
	tstate += 8;
	output += 8;
	numways--;
	}
}

/*
  Replacing uint64_t with uint32x4_t for pointer causes gcc8 to implement neon & arm "mov" instructions.
  Halved the incremented pointer operations to account for "128-bit".
*/
//Neon based preloop load for xor_salsa8() or salsa20_block(). B & Xxx must be uint32_t[16]
static inline void salsa8load64(uint32_t *Xxx, uint32_t *B)
{	
	uint32x4_t *dst = (uint32x4_t *) Xxx;
	uint32x4_t *src = (uint32x4_t *) B;

	*dst++ = *src++;*dst++ = *src++;*dst++ = *src++;*dst++ = *src++;
}

//Neon based post loop add & save for salsa20_block(). B & Xxx must be uint32_t[16]
static inline void salsa8addsave64(uint32_t *B, uint32_t *Xxx)
{	
	uint32x4_t *dst = (uint32x4_t *) B;
	uint32x4_t *src = (uint32x4_t *) Xxx;

	*dst++ += *src++;*dst++ += *src++;*dst++ += *src++;*dst++ += *src++;
}

//Neon based eqxor for xor_salsa8() or  & salsa20_block(). B & Bx must be uint32_t[16]
static inline void salsa8eqxorload64(uint32_t *B, const uint32_t *Bx)
{	
	uint32x4_t *dst = (uint32x4_t *) B;
	uint32x4_t *src = (uint32x4_t *) Bx;

	*dst++ ^= *src++;*dst++ ^= *src++;*dst++ ^= *src++;*dst++ ^= *src++;
}

static inline void xor_salsa_prefetch_addsave(uint32_t *B, uint32_t *X/*, uint32_t *V*/)
{
	uint32x2_t *dst = (uint32x2_t *) B;
	uint32x2_t *src = (uint32x2_t *) X;

	*dst++ += *src++;
	*dst++ += *src++;
	*dst++ += *src++;
	*dst++ += *src++;
	*dst++ += *src++;
	*dst++ += *src++;
	*dst++ += *src++;//*dst++ += *src++;
	//asm("":::"memory");
}
/*
 Wikipedia based xorsalsa (inner loop) with 64-bit store/load/eqadd/eqxor operations.
 gcc8 does an excellent job of instruction ordering for dual issue.
*/
static inline void salsa20_block(uint32_t *B, const uint32_t *Bx)
{
	register int i;
	uint32_t x[16];

	salsa8eqxorload64(B,Bx);

	salsa8load64(x,B);
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d)(		\
	b ^= ROTL(a + d, 7),	\
	c ^= ROTL(b + a, 9),	\
	d ^= ROTL(c + b,13),	\
	a ^= ROTL(d + c,18))

	for (i = 0; i < 4; i ++) {
		// Odd round
		QR(x[ 0], x[ 4], x[ 8], x[12]);	// column 1
		QR(x[ 5], x[ 9], x[13], x[ 1]);	// column 2
		QR(x[10], x[14], x[ 2], x[ 6]);	// column 3
		QR(x[15], x[ 3], x[ 7], x[11]);	// column 4
		// Even round
		QR(x[ 0], x[ 1], x[ 2], x[ 3]);	// row 1
		QR(x[ 5], x[ 6], x[ 7], x[ 4]);	// row 2
		QR(x[10], x[11], x[ 8], x[ 9]);	// row 3
		QR(x[15], x[12], x[13], x[14]);	// row 4
	}
#undef ROTL
#undef QR
	salsa8addsave64(B,x);
}
/* Slower than xor_salsa_prefetch implementation.
static inline void salsa20_block_prefetch(uint32_t *B, const uint32_t *Bx, uint32x4x8_t *V)
{
	register int i;
	uint32_t x[16];

	salsa8eqxorload64(B,Bx);

	salsa8load64(x,B);
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d)(		\
	b ^= ROTL(a + d, 7),	\
	c ^= ROTL(b + a, 9),	\
	d ^= ROTL(c + b,13),	\
	a ^= ROTL(d + c,18))

		QR(x[ 0], x[ 4], x[ 8], x[12]);	// column 1
		QR(x[ 5], x[ 9], x[13], x[ 1]);	// column 2
		QR(x[10], x[14], x[ 2], x[ 6]);	// column 3
		QR(x[15], x[ 3], x[ 7], x[11]);	// column 4
		// Even round
		QR(x[ 0], x[ 1], x[ 2], x[ 3]);	// row 1
		QR(x[ 5], x[ 6], x[ 7], x[ 4]);	// row 2
		QR(x[10], x[11], x[ 8], x[ 9]);	// row 3
		QR(x[15], x[12], x[13], x[14]);	// row 4
		QR(x[ 0], x[ 4], x[ 8], x[12]);	// column 1
		QR(x[ 5], x[ 9], x[13], x[ 1]);	// column 2
		QR(x[10], x[14], x[ 2], x[ 6]);	// column 3
		QR(x[15], x[ 3], x[ 7], x[11]);	// column 4
		// Even round
		QR(x[ 0], x[ 1], x[ 2], x[ 3]);	// row 1
		QR(x[ 5], x[ 6], x[ 7], x[ 4]);	// row 2
		QR(x[10], x[11], x[ 8], x[ 9]);	// row 3
		QR(x[15], x[12], x[13], x[14]);	// row 4
		QR(x[ 0], x[ 4], x[ 8], x[12]);	// column 1
		QR(x[ 5], x[ 9], x[13], x[ 1]);	// column 2
		QR(x[10], x[14], x[ 2], x[ 6]);	// column 3
		QR(x[15], x[ 3], x[ 7], x[11]);	// column 4
		// Even round
		QR(x[ 0], x[ 1], x[ 2], x[ 3]);	// row 1
		QR(x[ 5], x[ 6], x[ 7], x[ 4]);	// row 2
		QR(x[10], x[11], x[ 8], x[ 9]);	// row 3
		QR(x[15], x[12], x[13], x[14]);	// row 4
		// Odd round
		QR(x[ 0], x[ 4], x[ 8], x[12]);	// column 1
		QR(x[ 5], x[ 9], x[13], x[ 1]);	// column 2
		QR(x[10], x[14], x[ 2], x[ 6]);	// column 3
		QR(x[15], x[ 3], x[ 7], x[11]);	// column 4
		// Even round
		QR(x[ 0], x[ 1], x[ 2], x[ 3]);	// row 1
		QR(x[ 5], x[ 6], x[ 7], x[ 4]);	// row 2
		uint32x4x4_t *one = (uint32x4x4_t *) &V[(B[0] + x[ 0]) & 1048575];
		__builtin_prefetch(one++);
		__builtin_prefetch(one);
		asm("":::"memory");
		QR(x[10], x[11], x[ 8], x[ 9]);	// row 3
		QR(x[15], x[12], x[13], x[14]);	// row 4
#undef ROTL
#undef QR
	salsa8addsave64(B,x);
}*/

/* 
 Loop is unrolled for slightly better performance on aarch64.
 64-bit logical operatations. #obsolete
*//*
static void inline xor_salsa8(uint32_t *B, const uint32_t *Bx)
{
	uint32_t x15,x14,x13,x12,x11,x10,x09,x08,x07,x06,x05,x04,x03,x02,x01,x00;
	register int i;

	salsa8eqxorload64(B,Bx);

	x00 = B[ 0];
	x01 = B[ 1];
	x02 = B[ 2];
	x03 = B[ 3];
	x04 = B[ 4];
	x05 = B[ 5];
	x06 = B[ 6];
	x07 = B[ 7];
	x08 = B[ 8];
	x09 = B[ 9];
	x10 = B[10];
	x11 = B[11];
	x12 = B[12];
	x13 = B[13];
	x14 = B[14];
	x15 = B[15];

#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
	for (i = 0; i < 3; i++) {

		// Operate on columns. 
		x04 ^= R(x00+x12, 7);	x09 ^= R(x05+x01, 7);
		x14 ^= R(x10+x06, 7);	x03 ^= R(x15+x11, 7);
		
		x08 ^= R(x04+x00, 9);	x13 ^= R(x09+x05, 9);
		x02 ^= R(x14+x10, 9);	x07 ^= R(x03+x15, 9);
		
		x12 ^= R(x08+x04,13);	x01 ^= R(x13+x09,13);
		x06 ^= R(x02+x14,13);	x11 ^= R(x07+x03,13);
		
		x00 ^= R(x12+x08,18);	x05 ^= R(x01+x13,18);
		x10 ^= R(x06+x02,18);	x15 ^= R(x11+x07,18);
		
		// Operate on rows. 
		x01 ^= R(x00+x03, 7);	x06 ^= R(x05+x04, 7);
		x11 ^= R(x10+x09, 7);	x12 ^= R(x15+x14, 7);
		
		x02 ^= R(x01+x00, 9);	x07 ^= R(x06+x05, 9);
		x08 ^= R(x11+x10, 9);	x13 ^= R(x12+x15, 9);
		
		x03 ^= R(x02+x01,13);	x04 ^= R(x07+x06,13);
		x09 ^= R(x08+x11,13);	x14 ^= R(x13+x12,13);
		
		x00 ^= R(x03+x02,18);	x05 ^= R(x04+x07,18);
		x10 ^= R(x09+x08,18);	x15 ^= R(x14+x13,18);
}
		// Operate on columns. 
		x04 ^= R(x00+x12, 7);	x09 ^= R(x05+x01, 7);
		x14 ^= R(x10+x06, 7);	x03 ^= R(x15+x11, 7);
		
		x08 ^= R(x04+x00, 9);	x13 ^= R(x09+x05, 9);
		x02 ^= R(x14+x10, 9);	x07 ^= R(x03+x15, 9);
		
		x12 ^= R(x08+x04,13);	x01 ^= R(x13+x09,13);
		x06 ^= R(x02+x14,13);	x11 ^= R(x07+x03,13);
		
		x00 ^= R(x12+x08,18);	x05 ^= R(x01+x13,18);
		x10 ^= R(x06+x02,18);	x15 ^= R(x11+x07,18);
		
		// Operate on rows. 
		x01 ^= R(x00+x03, 7);	x06 ^= R(x05+x04, 7);
		x11 ^= R(x10+x09, 7);	x12 ^= R(x15+x14, 7);
		
		x02 ^= R(x01+x00, 9);	x07 ^= R(x06+x05, 9);
		x08 ^= R(x11+x10, 9);	x13 ^= R(x12+x15, 9);
		
		x03 ^= R(x02+x01,13);	x04 ^= R(x07+x06,13);
		x09 ^= R(x08+x11,13);	x14 ^= R(x13+x12,13);
		
		x00 ^= R(x03+x02,18);	x05 ^= R(x04+x07,18);
		x10 ^= R(x09+x08,18);	x15 ^= R(x14+x13,18);
#undef R

	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}*/

// Enforces instruction ordering allowing dual issue;
/*static inline void xor_salsa8_add_asm(uint32_t resulta, uint32_t resultb, uint32_t resultc, uint32_t resultd, uint32_t input_a, uint32_t input_b, uint32_t input_c, uint32_t input_d, uint32_t input_e, uint32_t input_f, uint32_t input_g, uint32_t input_h, uint32_t tmp1, uint32_t tmp2, uint32_t tmp3, uint32_t tmp4) {

 	 __asm volatile (
	"ADD %[resulta], %[input_a], %[input_b]"	"\n\t"
	"ADD %[resultb], %[input_c], %[input_d]"	"\n\t"
	"ADD %[resultc], %[input_e], %[input_f]"	"\n\t"
	"ADD %[resultd], %[input_g], %[input_h]"	"\n\t"
: [resulta] "=r" (tmp1), [resultb] "=r" (tmp2), [resultc] "=r" (tmp3), [resultd] "=r" (tmp4)
: [input_a] "r" (input_a), [input_b] "r" (input_b), [input_c] "r" (input_c), [input_d] "r" (input_d), [input_e] "r" (input_e), [input_f] "r" (input_f), [input_g] "r" (input_g), [input_h] "r" (input_h)
 	 );
}

static inline void xor_salsa8_asm(uint32_t X1, uint32_t X2, uint32_t input_a, uint32_t input_b, 
				uint32_t input_c, uint32_t input_d)
{
	register uint32_t tmp1, tmp2;

 	 __asm volatile (
	"ADD %[tmp1], %[input_a], %[input_b]"	"\n\t"
	"ADD %[tmp2], %[input_c], %[input_d]"	"\n\t"
	"ror %[tmp1], %[tmp1], #7"	"\n\t"
	"ror %[tmp2], %[tmp2], #7"	"\n\t"
	"eor %[X1], %[X1], %[tmp1]"	"\n\t"
	"eor %[X2], %[X2], %[tmp2]"	"\n\t"
: [tmp1] "=r" (tmp1), [tmp2] "=r" (tmp2), [X1] "=r" (X1), [X2] "=r" (X2)
: [input_a] "r" (input_a), [input_b] "r" (input_b), [input_c] "r" (input_c), [input_d] "r" (input_d)
 	 );
}
static inline void xor_salsa8_asm2(uint32_t X1, uint32_t X2, uint32_t input_a, uint32_t input_b, 
				uint32_t input_c, uint32_t input_d)
{
	register uint32_t tmp1, tmp2;

 	 __asm volatile (
	"ADD %[tmp1], %[input_a], %[input_b]"	"\n\t"
	"ADD %[tmp2], %[input_c], %[input_d]"	"\n\t"
	"ror %[tmp1], %[tmp1], #9"	"\n\t"
	"ror %[tmp2], %[tmp2], #9"	"\n\t"
	"eor %[X1], %[X1], %[tmp1]"	"\n\t"
	"eor %[X2], %[X2], %[tmp2]"	"\n\t"
: [tmp1] "=r" (tmp1), [tmp2] "=r" (tmp2), [X1] "=r" (X1), [X2] "=r" (X2)
: [input_a] "r" (input_a), [input_b] "r" (input_b), [input_c] "r" (input_c), [input_d] "r" (input_d)
 	 );
}
static inline void xor_salsa8_asm3(uint32_t X1, uint32_t X2, uint32_t input_a, uint32_t input_b, 
				uint32_t input_c, uint32_t input_d)
{
	register uint32_t tmp1, tmp2;

 	 __asm volatile (
	"ADD %[tmp1], %[input_a], %[input_b]"	"\n\t"
	"ADD %[tmp2], %[input_c], %[input_d]"	"\n\t"
	"ror %[tmp1], %[tmp1], #13"	"\n\t"
	"ror %[tmp2], %[tmp2], #13"	"\n\t"
	"eor %[X1], %[X1], %[tmp1]"	"\n\t"
	"eor %[X2], %[X2], %[tmp2]"	"\n\t"
: [tmp1] "=r" (tmp1), [tmp2] "=r" (tmp2), [X1] "=r" (X1), [X2] "=r" (X2)
: [input_a] "r" (input_a), [input_b] "r" (input_b), [input_c] "r" (input_c), [input_d] "r" (input_d)
 	 );
}
static inline void xor_salsa8_asm4(uint32_t X1, uint32_t X2, uint32_t input_a, uint32_t input_b, 
				uint32_t input_c, uint32_t input_d)
{
	register uint32_t tmp1, tmp2;

 	 __asm volatile (
	"ADD %[tmp1], %[input_a], %[input_b]"	"\n\t"
	"ADD %[tmp2], %[input_c], %[input_d]"	"\n\t"
	"ror %[tmp1], %[tmp1], #18"	"\n\t"
	"ror %[tmp2], %[tmp2], #18"	"\n\t"
	"eor %[X1], %[X1], %[tmp1]"	"\n\t"
	"eor %[X2], %[X2], %[tmp2]"	"\n\t"
: [tmp1] "=r" (tmp1), [tmp2] "=r" (tmp2), [X1] "=r" (X1), [X2] "=r" (X2)
: [input_a] "r" (input_a), [input_b] "r" (input_b), [input_c] "r" (input_c), [input_d] "r" (input_d)
 	 );
}*/
/*
  Split loop and struct offers better performance for some reason. Using both processing macros here improves dual issue.
*/
static inline void xor_salsa8_prefetch(uint32_t *B, const uint32_t *Bx, uint32x4x8_t *V)
{
	register int i;
	uint32_t x[16];

	salsa8eqxorload64(B,Bx);

	salsa8load64(x,B);

	/*x[0] = B[ 0];
	x[1] = B[ 1];
	x[2] = B[ 2];
	x[3] = B[ 3];
	x[4] = B[ 4];
	x[5] = B[ 5];
	x[6] = B[ 6];
	x[7] = B[ 7];
	x[8] = B[ 8];
	x[9] = B[ 9];
	x[10] = B[10];
	x[11] = B[11];
	x[12] = B[12];
	x[13] = B[13];
	x[14] = B[14];
	x[15] = B[15];*/

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d)(		\
	b ^= ROTL(a + d, 7),	\
	c ^= ROTL(b + a, 9),	\
	d ^= ROTL(c + b,13),	\
	a ^= ROTL(d + c,18))
for (i = 0; i < 2; i++) {
		// Odd round
		QR(x[0], x[4], x[8], x[12]);	// column 1
		QR(x[5], x[9], x[13], x[1]);	// column 2
		QR(x[10], x[14], x[2], x[6]);	// column 3
		QR(x[15], x[3], x[7], x[11]);	// column 4
		// Even round
		QR(x[0], x[1], x[2], x[3]);	// row 1
		QR(x[5], x[6], x[7], x[4]);	// row 2
		QR(x[10], x[11], x[8], x[9]);	// row 3
		QR(x[15], x[12], x[13], x[14]);	// row 4
}
for (; i < 4; i++) { 
		// Odd round
		QR(x[0], x[4], x[8], x[12]);	// column 1
		QR(x[5], x[9], x[13], x[1]);	// column 2
		QR(x[10], x[14], x[2], x[6]);	// column 3
		QR(x[15], x[3], x[7], x[11]);	// column 4
		
		/* Operate on rows. */
		x[1] ^= ROTL(x[0]+x[3], 7);	x[6] ^= ROTL(x[5]+x[4], 7);
		x[11] ^= ROTL(x[10]+x[9], 7);	x[12] ^= ROTL(x[15]+x[14], 7);
		
		x[2] ^= ROTL(x[1]+x[0], 9);	x[7] ^= ROTL(x[6]+x[5], 9);
		x[8] ^= ROTL(x[11]+x[10], 9);	x[13] ^= ROTL(x[12]+x[15], 9);
		
		x[3] ^= ROTL(x[2]+x[1],13);	x[4] ^= ROTL(x[7]+x[6],13);
		x[9] ^= ROTL(x[8]+x[11],13);	x[14] ^= ROTL(x[13]+x[12],13);
		
		x[0] ^= ROTL(x[3]+x[2],18);	x[5] ^= ROTL(x[4]+x[7],18);
		x[10] ^= ROTL(x[9]+x[8],18);	x[15] ^= ROTL(x[14]+x[13],18);
 }
#undef ROTL
#undef QR
	B[ 0] += x[0];
	B[ 1] += x[1];
	x[0] = B[0] & 1048575;
 	/*__asm ("AND %[result]], %[input_i]], #0xFFFFF"
   	 : [result] "=r" (x[0)
   	 : [input_i] "r" (B[0])
 	 ]);*/
	asm("":::"memory");
	// cast pointer suitable for incrementing and cache line size of 64 bytes
	uint32x4x4_t *ptr = (uint32x4x4_t *) &V[x[0]];
	__builtin_prefetch(ptr++);
	__builtin_prefetch(ptr);
	asm("":::"memory");
	//xor_salsa_prefetch_addsave(&B[2]], &x[2]);
	B[ 2] += x[2];
	B[ 3] += x[3];
	B[ 4] += x[4];
	B[ 5] += x[5];
	B[ 6] += x[6];
	B[ 7] += x[7];
	B[ 8] += x[8];
	B[ 9] += x[9];
	B[10] += x[10];
	B[11] += x[11];
	B[12] += x[12];
	B[13] += x[13];
	B[14] += x[14];
	B[15] += x[15];
}

/*
  Replacing uint64_t with uint32x4_t for pointer causes gcc8 to implement neon logical & arm "mov" instructions.
  Halve the incremented pointer operations to account for "128-bit".
*/
//Neon based eqxor load for scrypt_core(). X must be uint32_t[32] *experimented with vector array loads
static inline void eqxorload64(uint32_t *X, uint32x4x8_t *V)
{
	uint32_t j = X[16] & 1048575;
	uint32x4_t *dst = (uint32x4_t *) X;
	uint32x4_t one, two, three, four;
	uint32_t *src = (uint32_t *) &V[j];

	// Using non-temporal load pair. Might help expire L1keep prefetch.
	asm volatile(
		"ldnp %q[DST1], %q[DST2], [%[SRC]]" "\n"
		: [DST1] "=w" (one), [DST2] "=w" (two)
		: [SRC] "X" (src)
	);
	asm volatile(
		"ldnp %q[DST1], %q[DST2], [%[SRC],#32]" "\n"
		: [DST1] "=w" (three), [DST2] "=w" (four)
		: [SRC] "X" (src)
	);
	*dst++ ^= one;*dst++ ^= two; 
	asm volatile(
		"ldnp %q[DST1], %q[DST2], [%[SRC],#64]" "\n"
		: [DST1] "=w" (one), [DST2] "=w" (two)  
		: [SRC] "X" (src)
	);
	*dst++ ^= three;*dst++ ^= four;
	asm volatile(
		"ldnp %q[DST1], %q[DST2], [%[SRC],#96]" "\n"
		: [DST1] "=w" (three), [DST2] "=w" (four)
		: [SRC] "X" (src)
	);
	*dst++ ^= one;*dst++ ^= two;*dst++ ^= three;*dst ^= four;
}

// separating the second loop as an inline function boosts & stabilizes hashrate for some reason.
static inline void scrypt_core_loop2(uint32_t *X, uint32x4x8_t *V)
{
	int i;
	for (i = 0; i < 1048576; i++) {
		// Address is resolved in eqxorload64
		eqxorload64(X, V);
		salsa20_block(&X[0], &X[16]);
		xor_salsa8_prefetch(&X[16], &X[0], V);
	}
}

//Neon based memcpy alternative for scrypt_core(). a & b must be uint32_t[32]
static inline void memcpy64(uint32x4x8_t *V, uint32_t *X)
{
    	uint32x4_t *src = (uint32x4_t *) X;

	// Using store pair
	asm(
		"stp %q[DST1], %q[DST2], [%[SRC]]" "\n"
		:  
		: [DST1] "w" (*src++), [DST2] "w" (*src++), [SRC] "X" (V)
	);
	asm(
		"stp %q[DST1], %q[DST2], [%[SRC],#32]" "\n"
		:  
		: [DST1] "w" (*src++), [DST2] "w" (*src++), [SRC] "X" (V)
	);
	asm(
		"stp %q[DST1], %q[DST2], [%[SRC],#64]" "\n"
		:  
		: [DST1] "w" (*src++), [DST2] "w" (*src++), [SRC] "X" (V)
	);
	asm(
		"stp %q[DST1], %q[DST2], [%[SRC],#96]" "\n"
		:
		: [DST1] "w" (*src++), [DST2] "w" (*src), [SRC] "X" (V)
	);
}

// gcc8 does not order instructions for dual issue in xor_salsa8_prefetch.
static inline void scrypt_core(uint32_t *X, uint32x4x8_t *V/*, int N*/)
{
	//int i; * integrate scratchpad 1024-bit pointer into loop as iterator & eliminate index calculator
	{
	    	uint32x4x8_t *Vstr = V;

		for (; Vstr < &V[1048576]; Vstr++) {
			memcpy64(Vstr, X);
			salsa20_block(&X[0], &X[16]);
			salsa20_block(&X[16], &X[0]);
		}
	}

	/*for (Vstr = V; Vstr < &V[1048576]; Vstr++) {
		// Address is resolved in eqxorload64
		eqxorload64(X, V);
		salsa20_block(&X[0], &X[16]);
		xor_salsa8_prefetch(&X[16], &X[0], V);
	}*/
	scrypt_core_loop2(X, V);
}

/* Removed unnecessary steps */
static inline void scrypt_shuffle(uint32_t B[16])
{
	uint32_t tmp = B[1];	
	B[1] = B[5];
	B[5] = tmp;
	tmp = B[2];
	B[2] = B[10];
	B[10] = tmp;
	tmp = B[3];
	B[3] = B[15];
	B[15] = tmp;
	tmp = B[4];
	B[4] = B[12];
	B[12] = tmp;
	tmp = B[7];
	B[7] = B[11];
	B[11] = tmp;
	tmp = B[9];
	B[9] = B[13];
	B[13] = tmp;
}

/* Stripped down implementation of scrypt_core_3way for aarch64/armv8.
scrypt_core() outperforms this. May aswell remove scrypt_core_1way().
Not tested for producing valid work nor any likelyhood of performance
tuning as far I can see. Lacks possibility of dual issue. */
static inline void scrypt_core_1way(uint32_t B[32 * 1], uint32_t *V, uint32_t N)
{
	uint32_t* W = V;

	scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);

	uint32x4x4_t q_tmp;
  	uint32x4x4_t q_a;
	uint32x4x4_t ba_a, ba_b;

	ba_a.val[0] = vld1q_u32(&B[( 0) / 4]);
	ba_a.val[1] = vld1q_u32(&B[(16) / 4]);
	ba_a.val[2] = vld1q_u32(&B[(32) / 4]);
	ba_a.val[3] = vld1q_u32(&B[(48) / 4]);

	ba_b.val[0] = vld1q_u32(&B[(0 + 64 + 0) / 4]);
	ba_b.val[1] = vld1q_u32(&B[(0 + 64 + 16) / 4]);
	ba_b.val[2] = vld1q_u32(&B[(0 + 64 + 32) / 4]);
	ba_b.val[3] = vld1q_u32(&B[(0 + 64 + 48) / 4]);

	// prep

	vst1q_u32(&V[( 0) / 4], ba_a.val[0]);
	vst1q_u32(&V[(16) / 4], ba_a.val[1]);
	vst1q_u32(&V[(32) / 4], ba_a.val[2]);
	vst1q_u32(&V[(48) / 4], ba_a.val[3]);

	vst1q_u32(&V[(64) / 4],  ba_b.val[0]);
	vst1q_u32(&V[(80) / 4],  ba_b.val[1]);
	vst1q_u32(&V[(96) / 4],  ba_b.val[2]);
	vst1q_u32(&V[(112) / 4], ba_b.val[3]);

	for (register int n = 0; n < N; n++)
	{
		// loop 1 part a
			vst1q_u32(&V[(     16 + (0 * 4))], ba_b.val[0]);
		q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
			vst1q_u32(&V[(     16 + (1 * 4))], ba_b.val[1]);
		q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
			vst1q_u32(&V[(     16 + (2 * 4))], ba_b.val[2]);
		q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
			vst1q_u32(&V[(     16 + (3 * 4))], ba_b.val[3]);
		q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);

		V += 32;
		ba_a = q_a;

		for (register int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			
			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);

			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);
		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		q_a = ba_a;

		// loop 1 part b
			vst1q_u32(&V[      (0 * 4) ], ba_a.val[0]);
		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
			vst1q_u32(&V[      (1 * 4) ], ba_a.val[1]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
			vst1q_u32(&V[      (2 * 4) ], ba_a.val[2]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
			vst1q_u32(&V[      (3 * 4) ], ba_a.val[3]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
		ba_b = q_a;

		for (register int i = 0; i < 4; i ++)
		{

			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			
			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);

			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);
		}

		ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]); 
	}
	V = W;

    // loop 2

	uint32_t one =   32 * (1 * (ba_b.val[0][0] & (N - 1)) + 0);
	q_tmp.val[0] = vld1q_u32(&W[one +  0]);
	q_tmp.val[1] = vld1q_u32(&W[one +  4]);
	q_tmp.val[2] = vld1q_u32(&W[one +  8]);
	q_tmp.val[3] = vld1q_u32(&W[one + 12]);

	for (register int n = 0; n < N; n++)
	{
		// loop 2 part a

		ba_a.val[0] = veorq_u32(ba_a.val[0], q_tmp.val[0]);
			q_tmp.val[0] = vld1q_u32(&W[one + 16 +  0]);
		ba_a.val[1] = veorq_u32(ba_a.val[1], q_tmp.val[1]);
			q_tmp.val[1] = vld1q_u32(&W[one + 16 +  4]);
		ba_a.val[2] = veorq_u32(ba_a.val[2], q_tmp.val[2]);
			q_tmp.val[2] = vld1q_u32(&W[one + 16 +  8]);
		ba_a.val[3] = veorq_u32(ba_a.val[3], q_tmp.val[3]);
		q_tmp.val[3] = vld1q_u32(&W[one + 16 + 12]);

			ba_b.val[0] = veorq_u32(ba_b.val[0], q_tmp.val[0]);
			ba_b.val[1] = veorq_u32(ba_b.val[1], q_tmp.val[1]);
			ba_b.val[2] = veorq_u32(ba_b.val[2], q_tmp.val[2]);
			ba_b.val[3] = veorq_u32(ba_b.val[3], q_tmp.val[3]);

				q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
				q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
				q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
				q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);
		ba_a = q_a;

		for (register int i = 0; i < 4; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			
			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);

			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);

		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		q_a = ba_a;

		// loop 2 b

		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
		ba_b = q_a;

		for (register int i = 0; i < 3; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			
			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);

			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);

			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
		}
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			
			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);

			q_tmp.val[2] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[3], q_a.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);

			q_tmp.val[2] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[3], q_a.val[0]);
				ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
					one =	32 * (1 * (ba_b.val[0][0] & (N - 1)) + 0);
					__builtin_prefetch(&W[one + 0]);
					__builtin_prefetch(&W[one + 8]);
					__builtin_prefetch(&W[one + 16]);
					__builtin_prefetch(&W[one + 24]);

			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);

		}

		q_tmp.val[0] = vld1q_u32(&W[one +  0]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		q_tmp.val[1] = vld1q_u32(&W[one +  4]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		q_tmp.val[2] = vld1q_u32(&W[one +  8]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);
		q_tmp.val[3] = vld1q_u32(&W[one + 12]);
	}

	vst1q_u32(&B[0],       ba_a.val[0]);
	vst1q_u32(&B[4],       ba_a.val[1]);
	vst1q_u32(&B[8],       ba_a.val[2]);
	vst1q_u32(&B[12],      ba_a.val[3]);
	vst1q_u32(&B[16 + 0],  ba_b.val[0]);
	vst1q_u32(&B[16 + 4],  ba_b.val[1]);
	vst1q_u32(&B[16 + 8],  ba_b.val[2]);
	vst1q_u32(&B[16 + 12], ba_b.val[3]);

	scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);
}

// Used with vld4/str4 to compensate for their interleaved load/stores.
static inline void scrypt_deinterleaved_shuffle(uint32_t B[16])
{
	uint32_t x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	
	x01 = B[ 1];
	x02 = B[ 2];
	x03 = B[ 3];
	x04 = B[ 4];
	x05 = B[ 5];
	x06 = B[ 6];
	x07 = B[ 7];
	x08 = B[ 8];
	x09 = B[ 9];
	x10 = B[10];
	x11 = B[11];
	x12 = B[12];
	x13 = B[13];
	x14 = B[14];
	x15 = B[15];

	B[ 1] = x12;
	B[ 2] = x08;
	B[ 3] = x04;
	B[ 4] = x05;
	B[ 5] = x01;
	B[ 6] = x13;
	B[ 7] = x09;
	B[ 8] = x10;
	B[ 9] = x06;
	B[10] = x02;
	B[11] = x14;
	B[12] = x15;
	B[13] = x11;
	B[14] = x07;
	B[15] = x03;
}

/*
Stripped down implementation of scrypt_core_3way for aarch64/armv8.
Usually outperforms original while consuming 1/3rd less memory.
This is a better tuned approach for limited memory capacity and bandwidth
typical of armv8 sbc's while maximizing dual issue. 1gb can run 2x or 3x 2ways (-t 3 --oneways=1).
Experimented using vld1q_u32/vst1q_u32 (interleaves/deinterleaves) in conjunction with scrypt_deinterleaved_shuffle
reduced asm code by 10% however performance degraded 15% since it maybe causing misdirected cache prefetching,
or some other overheads I am not aware about. Other small improvements including inlineable memcpy & sha256 alternatives, 
yielding 1-2% improvement over initial 2ways fork released June 2018. Hints at data alignment seem to have no effect.
asm code lacks indication of said hints and sparse cortex-a53 documentation suggests alignment is handled transparently instead
using checks. fireworm71 believes peak performance has been reached - cache and memory cannot keep up with code.
UPDATE. scrypt_core() now approaches performance of 2/3 ways while consuming 20% less power.
*/
// try prohibit loop unrolling loops for 2ways
#pragma GCC push_options
#pragma GCC optimize ("unroll-all-loops")
static inline void scrypt_core_2way(uint32_t B[32 * 2], uint32_t *V/*, int N*/)
{
	//uint32_t* W = V;
	uint32x4_t *W = (uint32x4_t *) V;//__attribute__((__aligned__(64))) = (uint32x4_t *) V __builtin_assume_aligned(V, 64);

	uint32x4x4_t q_tmp __attribute__((__aligned__(16)));
 	uint32x4x4_t q_a __attribute__((__aligned__(16))), q_b __attribute__((__aligned__(16)));
	uint32x4x4_t ba_a __attribute__((__aligned__(16))), bb_a __attribute__((__aligned__(16))), ba_b __attribute__((__aligned__(16))), bb_b __attribute__((__aligned__(16)));

	scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);
	scrypt_shuffle(&B[0 + 32]);
	scrypt_shuffle(&B[16 + 32]);

	ba_a.val[0] = vld1q_u32(&B[( 0) / 4]);
	ba_a.val[1] = vld1q_u32(&B[(16) / 4]);
	ba_a.val[2] = vld1q_u32(&B[(32) / 4]);
	ba_a.val[3] = vld1q_u32(&B[(48) / 4]);

	ba_b.val[0] = vld1q_u32(&B[(0 + 64 + 0) / 4]);
	ba_b.val[1] = vld1q_u32(&B[(0 + 64 + 16) / 4]);
	ba_b.val[2] = vld1q_u32(&B[(0 + 64 + 32) / 4]);
	ba_b.val[3] = vld1q_u32(&B[(0 + 64 + 48) / 4]);

	bb_a.val[0] = vld1q_u32(&B[(128 +  0) / 4]);
	W[0] = ba_a.val[0];
	bb_a.val[1] = vld1q_u32(&B[(128 + 16) / 4]);
	W[1] = ba_a.val[1];
	bb_a.val[2] = vld1q_u32(&B[(128 + 32) / 4]);
	W[2] = ba_a.val[2];
	bb_a.val[3] = vld1q_u32(&B[(128 + 48) / 4]);
	W[3] = ba_a.val[3];

	bb_b.val[0] = vld1q_u32(&B[(128 + 64 + 0) / 4]);
	W[8] = bb_a.val[0];
	bb_b.val[1] = vld1q_u32(&B[(128 + 64 + 16) / 4]);
	W[9] = bb_a.val[1];
	bb_b.val[2] = vld1q_u32(&B[(128 + 64 + 32) / 4]);
	W[10] = bb_a.val[2];
	bb_b.val[3] = vld1q_u32(&B[(128 + 64 + 48) / 4]);
	W[11] = bb_a.val[3];
 

	for (register int n = 0; n < 1048576; n++)
	{
		// loop 1 part a
		W[4] = ba_b.val[0];
		q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
		W[5] = ba_b.val[1];
		q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
 		W[6] = ba_b.val[2];
		q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
 		W[7] = ba_b.val[3];
		q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);
 		W[12] = bb_b.val[0];
		q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
 		W[13] = bb_b.val[1];
		q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
 		W[14] = bb_b.val[2];	
		q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);
		W[15] = bb_b.val[3];
		q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);
 
		ba_a = q_a;
		bb_a = q_b;
		//increments scratchpad pointer
		W += 16;

		for (register int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);
 
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);;
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);

			// gcc8 mixes ext with add instructions. Dual issue should still be preserved.
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		bb_a.val[0] = vaddq_u32(bb_a.val[0], q_b.val[0]);
		bb_a.val[1] = vaddq_u32(bb_a.val[1], q_b.val[1]);
		bb_a.val[2] = vaddq_u32(bb_a.val[2], q_b.val[2]);
		bb_a.val[3] = vaddq_u32(bb_a.val[3], q_b.val[3]);

		q_a = ba_a;
		q_b = bb_a;
		
		/*for (int i = 0; i < 4; i++) // code unrolled and moved below to perhaps encourage dual issue
		{
			vst1q_u32(&W[      (i * 4) ], ba_a.val[i]);
			vst1q_u32(&W[(32 + (i * 4))], bb_a.val[i]);
		}*/
			//vst4q_u32(&W[      (0 * 4) ], ba_a); //experimented with alternative store
			//vst4q_u32(&W[(32 + (0 * 4))], bb_a); //experimented with alternative store

		// loop 1 part b
 			W[0] = ba_a.val[0];
		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
 			W[1] = ba_a.val[1];
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
 			W[2] = ba_a.val[2];
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
			W[3] = ba_a.val[3];
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
 
			W[8] = bb_a.val[0];
		q_b.val[0] = veorq_u32(bb_b.val[0], q_b.val[0]);
 			W[9] = bb_a.val[1];
		q_b.val[1] = veorq_u32(bb_b.val[1], q_b.val[1]);
 			W[10] = bb_a.val[2];
		q_b.val[2] = veorq_u32(bb_b.val[2], q_b.val[2]);
 			W[11] = bb_a.val[3];
		q_b.val[3] = veorq_u32(bb_b.val[3], q_b.val[3]);
		
		ba_b = q_a;		
		bb_b = q_b;

		for (register int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);	
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);

			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
		}

		ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);
		bb_b.val[0] = vaddq_u32(q_b.val[0], bb_b.val[0]);
		bb_b.val[1] = vaddq_u32(q_b.val[1], bb_b.val[1]);
		bb_b.val[2] = vaddq_u32(q_b.val[2], bb_b.val[2]);
		bb_b.val[3] = vaddq_u32(q_b.val[3], bb_b.val[3]);

		/*for (int i = 0; i < 4; i++) // stores unrolled moved to start of loop 1
		{
			vst1q_u32(&V[(     16 + (i * 4))], ba_b.val[i]);
			vst1q_u32(&V[(32 + 16 + (i * 4))], bb_b.val[i]);
		}*/
	}

 	for (register int n = 0; n < 1048576; n++)
	{
		register int one = 32 * (2 * (ba_b.val[0][0] & 1048575));
		register int two = 32 * (2 * (bb_b.val[0][0] & 1048575) + 1);
		uint32x4_t *oneneon __attribute__((__aligned__(64))) = (uint32x4_t *) __builtin_assume_aligned(&V[one], 64);
		uint32x4_t *twoneon __attribute__((__aligned__(64))) = (uint32x4_t *) __builtin_assume_aligned(&V[two], 64);
		// loop 2 part a
		ba_a.val[0] ^= *oneneon++;
		ba_a.val[1] ^= *oneneon++;
		ba_a.val[2] ^= *oneneon++;
		ba_a.val[3] ^= *oneneon++;

		ba_b.val[0] ^= *oneneon++;
		ba_b.val[1] ^= *oneneon++;
		ba_b.val[2] ^= *oneneon++;
		ba_b.val[3] ^= *oneneon++;
		 
		bb_a.val[0] ^= *twoneon++;
		bb_a.val[1] ^= *twoneon++;
		bb_a.val[2] ^= *twoneon++;
		bb_a.val[3] ^= *twoneon++;

		bb_b.val[0] ^= *twoneon++;
		bb_b.val[1] ^= *twoneon++;
		bb_b.val[2] ^= *twoneon++;
		bb_b.val[3] ^= *twoneon++;

		q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);

		q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
		q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
		q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);
		q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);

		ba_a = q_a;
		bb_a = q_b;

		for (register int i = 0; i < 4; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);	
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);

			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		bb_a.val[0] = vaddq_u32(bb_a.val[0], q_b.val[0]);
		bb_a.val[1] = vaddq_u32(bb_a.val[1], q_b.val[1]);
		bb_a.val[2] = vaddq_u32(bb_a.val[2], q_b.val[2]);
		bb_a.val[3] = vaddq_u32(bb_a.val[3], q_b.val[3]);

		q_a = ba_a;
		q_b = bb_a;

		// loop 2 b
		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);

		q_b.val[0] = veorq_u32(bb_b.val[0], q_b.val[0]);
		q_b.val[1] = veorq_u32(bb_b.val[1], q_b.val[1]);
		q_b.val[2] = veorq_u32(bb_b.val[2], q_b.val[2]);
		q_b.val[3] = veorq_u32(bb_b.val[3], q_b.val[3]);

		ba_b = q_a;
		bb_b = q_b;

		for (register int i = 0; i < 3; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);;

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);

			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
		}
		{
			//1
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);
			//2
			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);
			//3
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			//4
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			//5
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			//6
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);
			//7
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);
			//8
			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);
				bb_b.val[0] = vaddq_u32(q_b.val[0], bb_b.val[0]);
				ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
					one =	32 * (2 * (ba_b.val[0][0] & 1048575));	
					two =	32 * (2 * (bb_b.val[0][0] & 1048575) + 1);
					// Cast pointer suitable for 64 byte cache line size
					__builtin_prefetch((uint32x4x4_t *) &V[one]);
					__builtin_prefetch((uint32x4x4_t *) &V[one + 16]);
					__builtin_prefetch((uint32x4x4_t *) &V[two]);
					__builtin_prefetch((uint32x4x4_t *) &V[two + 16]);

			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
		}

		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);
		bb_b.val[1] = vaddq_u32(q_b.val[1], bb_b.val[1]);
		bb_b.val[2] = vaddq_u32(q_b.val[2], bb_b.val[2]);
		bb_b.val[3] = vaddq_u32(q_b.val[3], bb_b.val[3]);
	}

	vst1q_u32(&B[0],	ba_a.val[0]);
	vst1q_u32(&B[4],	ba_a.val[1]);
	vst1q_u32(&B[8],	ba_a.val[2]);
	vst1q_u32(&B[12],	ba_a.val[3]);

	vst1q_u32(&B[16 + 0],	ba_b.val[0]);
	vst1q_u32(&B[16 + 4],	ba_b.val[1]);
	vst1q_u32(&B[16 + 8],	ba_b.val[2]);
	vst1q_u32(&B[16 + 12],	ba_b.val[3]);

	vst1q_u32(&B[32 + 0],	bb_a.val[0]);
	vst1q_u32(&B[32 + 4],	bb_a.val[1]);
	vst1q_u32(&B[32 + 8],	bb_a.val[2]);
	vst1q_u32(&B[32 + 12],	bb_a.val[3]);

	vst1q_u32(&B[32 + 16 + 0],  bb_b.val[0]);
	vst1q_u32(&B[32 + 16 + 4],  bb_b.val[1]);
	vst1q_u32(&B[32 + 16 + 8],  bb_b.val[2]);
	vst1q_u32(&B[32 + 16 + 12], bb_b.val[3]);

	scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);
	scrypt_shuffle(&B[0 + 32]);
	scrypt_shuffle(&B[16 + 32]);
}
// restore normal gcc options
#pragma GCC pop_options

/* 
* scrypt_core_3way disabled for aarch64/armv8. Refer to scrypt_core_2way for notes as to why. 
* Code left in as comment for reference purposes
*/
/*
static inline void scrypt_core_3way(uint32_t B[32 * 3], uint32_t *V, uint32_t N)
{
	uint32_t* W = V;

	scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);
	scrypt_shuffle(&B[0 + 32]);
	scrypt_shuffle(&B[16 + 32]);
	scrypt_shuffle(&B[0 + 64]);
	scrypt_shuffle(&B[16 + 64]);

	uint32x4x4_t q_a, q_b, q_c, q_tmp;
	uint32x4x4_t ba_a, bb_a, bc_a, ba_b, bb_b, bc_b;

	ba_a.val[0] = vld1q_u32(&B[( 0) / 4]);
	ba_a.val[1] = vld1q_u32(&B[(16) / 4]);
	ba_a.val[2] = vld1q_u32(&B[(32) / 4]);
	ba_a.val[3] = vld1q_u32(&B[(48) / 4]);
	ba_b.val[0] = vld1q_u32(&B[(0 + 64 + 0) / 4]);
	ba_b.val[1] = vld1q_u32(&B[(0 + 64 + 16) / 4]);
	ba_b.val[2] = vld1q_u32(&B[(0 + 64 + 32) / 4]);
	ba_b.val[3] = vld1q_u32(&B[(0 + 64 + 48) / 4]);

	bb_a.val[0] = vld1q_u32(&B[(128 +  0) / 4]);
	bb_a.val[1] = vld1q_u32(&B[(128 + 16) / 4]);
	bb_a.val[2] = vld1q_u32(&B[(128 + 32) / 4]);
	bb_a.val[3] = vld1q_u32(&B[(128 + 48) / 4]);
	bb_b.val[0] = vld1q_u32(&B[(128 + 64 + 0) / 4]);
	bb_b.val[1] = vld1q_u32(&B[(128 + 64 + 16) / 4]);
	bb_b.val[2] = vld1q_u32(&B[(128 + 64 + 32) / 4]);
	bb_b.val[3] = vld1q_u32(&B[(128 + 64 + 48) / 4]);
	
	bc_a.val[0] = vld1q_u32(&B[(256 + 0) / 4]);
	bc_a.val[1] = vld1q_u32(&B[(256 + 16) / 4]);
	bc_a.val[2] = vld1q_u32(&B[(256 + 32) / 4]);
	bc_a.val[3] = vld1q_u32(&B[(256 + 48) / 4]);
	bc_b.val[0] = vld1q_u32(&B[(256 + 64 + 0) / 4]);
	bc_b.val[1] = vld1q_u32(&B[(256 + 64 + 16) / 4]);
	bc_b.val[2] = vld1q_u32(&B[(256 + 64 + 32) / 4]);
	bc_b.val[3] = vld1q_u32(&B[(256 + 64 + 48) / 4]);

	// prep

	vst1q_u32(&V[( 0) / 4], ba_a.val[0]);
	vst1q_u32(&V[(16) / 4], ba_a.val[1]);
	vst1q_u32(&V[(32) / 4], ba_a.val[2]);
	vst1q_u32(&V[(48) / 4], ba_a.val[3]);
	vst1q_u32(&V[(64) / 4],  ba_b.val[0]);
	vst1q_u32(&V[(80) / 4],  ba_b.val[1]);
	vst1q_u32(&V[(96) / 4],  ba_b.val[2]);
	vst1q_u32(&V[(112) / 4], ba_b.val[3]);

	vst1q_u32(&V[(128 +  0) / 4], bb_a.val[0]);
	vst1q_u32(&V[(128 + 16) / 4], bb_a.val[1]);
	vst1q_u32(&V[(128 + 32) / 4], bb_a.val[2]);
	vst1q_u32(&V[(128 + 48) / 4], bb_a.val[3]);
	vst1q_u32(&V[(128 + 64) / 4],  bb_b.val[0]);
	vst1q_u32(&V[(128 + 80) / 4],  bb_b.val[1]);
	vst1q_u32(&V[(128 + 96) / 4],  bb_b.val[2]);
	vst1q_u32(&V[(128 + 112) / 4], bb_b.val[3]);

	vst1q_u32(&V[(256 +  0) / 4], bc_a.val[0]);
	vst1q_u32(&V[(256 + 16) / 4], bc_a.val[1]);
	vst1q_u32(&V[(256 + 32) / 4], bc_a.val[2]);
	vst1q_u32(&V[(256 + 48) / 4], bc_a.val[3]);
	vst1q_u32(&V[(256 + 64) / 4], bc_b.val[0]);
	vst1q_u32(&V[(256 + 80) / 4], bc_b.val[1]);
	vst1q_u32(&V[(256 + 96) / 4], bc_b.val[2]);
	vst1q_u32(&V[(256 + 112) / 4],bc_b.val[3]);

	V += 96;

	for (int n = 0; n < N; n++)
	{
		// loop 1 part a
		q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);

		q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
		q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
		q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);
		q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);

		q_c.val[0] = veorq_u32(bc_b.val[0], bc_a.val[0]);
		q_c.val[1] = veorq_u32(bc_b.val[1], bc_a.val[1]);
		q_c.val[2] = veorq_u32(bc_b.val[2], bc_a.val[2]);
		q_c.val[3] = veorq_u32(bc_b.val[3], bc_a.val[3]);

		ba_a = q_a;
		bb_a = q_b;
		bc_a = q_c;

		for (int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		q_a = ba_a;

		bb_a.val[0] = vaddq_u32(bb_a.val[0], q_b.val[0]);
		bb_a.val[1] = vaddq_u32(bb_a.val[1], q_b.val[1]);
		bb_a.val[2] = vaddq_u32(bb_a.val[2], q_b.val[2]);
		bb_a.val[3] = vaddq_u32(bb_a.val[3], q_b.val[3]);

		q_b = bb_a;

		bc_a.val[0] = vaddq_u32(bc_a.val[0], q_c.val[0]);
		bc_a.val[1] = vaddq_u32(bc_a.val[1], q_c.val[1]);
		bc_a.val[2] = vaddq_u32(bc_a.val[2], q_c.val[2]);
		bc_a.val[3] = vaddq_u32(bc_a.val[3], q_c.val[3]);

		q_c = bc_a;
		
		for (int i = 0; i < 4; i++)
		{
			vst1q_u32(&V[      (i * 4) ], ba_a.val[i]);
			vst1q_u32(&V[(32 + (i * 4))], bb_a.val[i]);
			vst1q_u32(&V[(64 + (i * 4))], bc_a.val[i]);
		}

		// loop 1 part b

		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
		ba_b = q_a;

		q_b.val[0] = veorq_u32(bb_b.val[0], q_b.val[0]);
		q_b.val[1] = veorq_u32(bb_b.val[1], q_b.val[1]);
		q_b.val[2] = veorq_u32(bb_b.val[2], q_b.val[2]);
		q_b.val[3] = veorq_u32(bb_b.val[3], q_b.val[3]);
		bb_b = q_b;

		q_c.val[0] = veorq_u32(bc_b.val[0], q_c.val[0]);
		q_c.val[1] = veorq_u32(bc_b.val[1], q_c.val[1]);
		q_c.val[2] = veorq_u32(bc_b.val[2], q_c.val[2]);
		q_c.val[3] = veorq_u32(bc_b.val[3], q_c.val[3]);
		bc_b = q_c;


		for (int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}

		ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);
		bb_b.val[0] = vaddq_u32(q_b.val[0], bb_b.val[0]);
		bb_b.val[1] = vaddq_u32(q_b.val[1], bb_b.val[1]);
		bb_b.val[2] = vaddq_u32(q_b.val[2], bb_b.val[2]);
		bb_b.val[3] = vaddq_u32(q_b.val[3], bb_b.val[3]);
		bc_b.val[0] = vaddq_u32(q_c.val[0], bc_b.val[0]);
		bc_b.val[1] = vaddq_u32(q_c.val[1], bc_b.val[1]);
		bc_b.val[2] = vaddq_u32(q_c.val[2], bc_b.val[2]);
		bc_b.val[3] = vaddq_u32(q_c.val[3], bc_b.val[3]);
		for (int i = 0; i < 4; i++)
		{
			vst1q_u32(&V[(     16 + (i * 4))], ba_b.val[i]);
			vst1q_u32(&V[(32 + 16 + (i * 4))], bb_b.val[i]);
			vst1q_u32(&V[(64 + 16 + (i * 4))], bc_b.val[i]);
		}
		V += 96;
	}
	V = W;

    // loop 2

	uint32x4x4_t x;

	uint32_t one =   32 * (3 * (ba_b.val[0][0] & (N - 1)) + 0);
	uint32_t two =   32 * (3 * (bb_b.val[0][0] & (N - 1)) + 1);
	uint32_t three = 32 * (3 * (bc_b.val[0][0] & (N - 1)) + 2);
	q_tmp.val[0] = vld1q_u32(&W[one +  0]);
	q_tmp.val[1] = vld1q_u32(&W[one +  4]);
	q_tmp.val[2] = vld1q_u32(&W[one +  8]);
	q_tmp.val[3] = vld1q_u32(&W[one + 12]);

	for (int n = 0; n < N; n++)
	{
		// loop 2 part a

		ba_a.val[0] = veorq_u32(ba_a.val[0], q_tmp.val[0]);
			q_tmp.val[0] = vld1q_u32(&W[one + 16 +  0]);
		ba_a.val[1] = veorq_u32(ba_a.val[1], q_tmp.val[1]);
			q_tmp.val[1] = vld1q_u32(&W[one + 16 +  4]);
		ba_a.val[2] = veorq_u32(ba_a.val[2], q_tmp.val[2]);
			q_tmp.val[2] = vld1q_u32(&W[one + 16 +  8]);
		ba_a.val[3] = veorq_u32(ba_a.val[3], q_tmp.val[3]);

			ba_b.val[0] = veorq_u32(ba_b.val[0], q_tmp.val[0]);
			ba_b.val[1] = veorq_u32(ba_b.val[1], q_tmp.val[1]);
			q_tmp.val[3] = vld1q_u32(&W[one + 16 + 12]);
			ba_b.val[2] = veorq_u32(ba_b.val[2], q_tmp.val[2]);
			ba_b.val[3] = veorq_u32(ba_b.val[3], q_tmp.val[3]);
		q_tmp.val[0] = vld1q_u32(&W[two +  0]);
				q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
				q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
		q_tmp.val[1] = vld1q_u32(&W[two +  4]);
				q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
				q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);
		q_tmp.val[2] = vld1q_u32(&W[two +  8]);
		ba_a = q_a;

		q_tmp.val[3] = vld1q_u32(&W[two + 12]);

		bb_a.val[0] = veorq_u32(bb_a.val[0], q_tmp.val[0]);
			q_tmp.val[0] = vld1q_u32(&W[two + 16 +  0]);
		bb_a.val[1] = veorq_u32(bb_a.val[1], q_tmp.val[1]);
			q_tmp.val[1] = vld1q_u32(&W[two + 16 +  4]);
		bb_a.val[2] = veorq_u32(bb_a.val[2], q_tmp.val[2]);
			q_tmp.val[2] = vld1q_u32(&W[two + 16 +  8]);
		bb_a.val[3] = veorq_u32(bb_a.val[3], q_tmp.val[3]);
			bb_b.val[0] = veorq_u32(bb_b.val[0], q_tmp.val[0]);
			q_tmp.val[3] = vld1q_u32(&W[two + 16 + 12]);
			bb_b.val[1] = veorq_u32(bb_b.val[1], q_tmp.val[1]);
		q_tmp.val[0] = vld1q_u32(&W[three +  0]);
			bb_b.val[2] = veorq_u32(bb_b.val[2], q_tmp.val[2]);
			bb_b.val[3] = veorq_u32(bb_b.val[3], q_tmp.val[3]);
		q_tmp.val[1] = vld1q_u32(&W[three +  4]);
				q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
				q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
		q_tmp.val[2] = vld1q_u32(&W[three +  8]);
				q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);
				q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);
		q_tmp.val[3] = vld1q_u32(&W[three + 12]);
		bb_a = q_b;

		bc_a.val[0] = veorq_u32(bc_a.val[0], q_tmp.val[0]);
			q_tmp.val[0] = vld1q_u32(&W[three + 16 +  0]);
		bc_a.val[1] = veorq_u32(bc_a.val[1], q_tmp.val[1]);
			q_tmp.val[1] = vld1q_u32(&W[three + 16 +  4]);
		bc_a.val[2] = veorq_u32(bc_a.val[2], q_tmp.val[2]);
			q_tmp.val[2] = vld1q_u32(&W[three + 16 +  8]);
		bc_a.val[3] = veorq_u32(bc_a.val[3], q_tmp.val[3]);
			bc_b.val[0] = veorq_u32(bc_b.val[0], q_tmp.val[0]);
			q_tmp.val[3] = vld1q_u32(&W[three + 16 + 12]);
			bc_b.val[1] = veorq_u32(bc_b.val[1], q_tmp.val[1]);
			bc_b.val[2] = veorq_u32(bc_b.val[2], q_tmp.val[2]);
			bc_b.val[3] = veorq_u32(bc_b.val[3], q_tmp.val[3]);
				q_c.val[0] = veorq_u32(bc_b.val[0], bc_a.val[0]);
				q_c.val[1] = veorq_u32(bc_b.val[1], bc_a.val[1]);
				q_c.val[2] = veorq_u32(bc_b.val[2], bc_a.val[2]);
				q_c.val[3] = veorq_u32(bc_b.val[3], bc_a.val[3]);
		bc_a = q_c;

		for (int i = 0; i < 4; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		q_a = ba_a;

		bb_a.val[0] = vaddq_u32(bb_a.val[0], q_b.val[0]);
		bb_a.val[1] = vaddq_u32(bb_a.val[1], q_b.val[1]);
		bb_a.val[2] = vaddq_u32(bb_a.val[2], q_b.val[2]);
		bb_a.val[3] = vaddq_u32(bb_a.val[3], q_b.val[3]);
		q_b = bb_a;

		bc_a.val[0] = vaddq_u32(bc_a.val[0], q_c.val[0]);
		bc_a.val[1] = vaddq_u32(bc_a.val[1], q_c.val[1]);
		bc_a.val[2] = vaddq_u32(bc_a.val[2], q_c.val[2]);
		bc_a.val[3] = vaddq_u32(bc_a.val[3], q_c.val[3]);
		q_c = bc_a;

		// loop 2 b

		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
		ba_b = q_a;

		q_b.val[0] = veorq_u32(bb_b.val[0], q_b.val[0]);
		q_b.val[1] = veorq_u32(bb_b.val[1], q_b.val[1]);
		q_b.val[2] = veorq_u32(bb_b.val[2], q_b.val[2]);
		q_b.val[3] = veorq_u32(bb_b.val[3], q_b.val[3]);
		bb_b = q_b;

		q_c.val[0] = veorq_u32(bc_b.val[0], q_c.val[0]);
		q_c.val[1] = veorq_u32(bc_b.val[1], q_c.val[1]);
		q_c.val[2] = veorq_u32(bc_b.val[2], q_c.val[2]);
		q_c.val[3] = veorq_u32(bc_b.val[3], q_c.val[3]);
		bc_b = q_c;


		for (int i = 0; i < 3; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}
		{
			//1
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			//2
			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);
			//3
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			//4
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			//5
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			//6
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);
			//7
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
				q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			//8
			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
				ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
					one =	32 * (3 * (ba_b.val[0][0] & (N - 1)) + 0);
					__builtin_prefetch(&W[one + 0]);
					__builtin_prefetch(&W[one + 8]);
					__builtin_prefetch(&W[one + 16]);
					__builtin_prefetch(&W[one + 24]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
				bb_b.val[0] = vaddq_u32(q_b.val[0], bb_b.val[0]);
					two =	32 * (3 * (bb_b.val[0][0] & (N - 1)) + 1);
					__builtin_prefetch(&W[two + 0]);
					__builtin_prefetch(&W[two + 8]);
					__builtin_prefetch(&W[two + 16]);
					__builtin_prefetch(&W[two + 24]);

			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
				bc_b.val[0] = vaddq_u32(q_c.val[0], bc_b.val[0]);
					three = 32 * (3 * (bc_b.val[0][0] & (N - 1)) + 2);
					__builtin_prefetch(&W[three + 0]);
					__builtin_prefetch(&W[three + 8]);
					__builtin_prefetch(&W[three + 16]);
					__builtin_prefetch(&W[three + 24]);
		}

		q_tmp.val[0] = vld1q_u32(&W[one +  0]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);
		q_tmp.val[1] = vld1q_u32(&W[one +  4]);
		bb_b.val[1] = vaddq_u32(q_b.val[1], bb_b.val[1]);
		bb_b.val[2] = vaddq_u32(q_b.val[2], bb_b.val[2]);
		bb_b.val[3] = vaddq_u32(q_b.val[3], bb_b.val[3]);
		q_tmp.val[2] = vld1q_u32(&W[one +  8]);
		bc_b.val[1] = vaddq_u32(q_c.val[1], bc_b.val[1]);
		bc_b.val[2] = vaddq_u32(q_c.val[2], bc_b.val[2]);
		bc_b.val[3] = vaddq_u32(q_c.val[3], bc_b.val[3]);
		q_tmp.val[3] = vld1q_u32(&W[one + 12]);
	}

	vst1q_u32(&B[0],       ba_a.val[0]);
	vst1q_u32(&B[4],       ba_a.val[1]);
	vst1q_u32(&B[8],       ba_a.val[2]);
	vst1q_u32(&B[12],      ba_a.val[3]);
	vst1q_u32(&B[16 + 0],  ba_b.val[0]);
	vst1q_u32(&B[16 + 4],  ba_b.val[1]);
	vst1q_u32(&B[16 + 8],  ba_b.val[2]);
	vst1q_u32(&B[16 + 12], ba_b.val[3]);

	vst1q_u32(&B[32 + 0],  		bb_a.val[0]);
	vst1q_u32(&B[32 + 4],  		bb_a.val[1]);
	vst1q_u32(&B[32 + 8],  		bb_a.val[2]);
	vst1q_u32(&B[32 + 12], 		bb_a.val[3]);
	vst1q_u32(&B[32 + 16 + 0],  bb_b.val[0]);
	vst1q_u32(&B[32 + 16 + 4],  bb_b.val[1]);
	vst1q_u32(&B[32 + 16 + 8],  bb_b.val[2]);
	vst1q_u32(&B[32 + 16 + 12], bb_b.val[3]);

	vst1q_u32(&B[64 + 0],  		bc_a.val[0]);
	vst1q_u32(&B[64 + 4],  		bc_a.val[1]);
	vst1q_u32(&B[64 + 8],  		bc_a.val[2]);
	vst1q_u32(&B[64 + 12], 		bc_a.val[3]);
	vst1q_u32(&B[64 + 16 + 0],  bc_b.val[0]);
	vst1q_u32(&B[64 + 16 + 4],  bc_b.val[1]);
	vst1q_u32(&B[64 + 16 + 8],  bc_b.val[2]);
	vst1q_u32(&B[64 + 16 + 12], bc_b.val[3]);

        scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);
	scrypt_shuffle(&B[0 + 32]);
	scrypt_shuffle(&B[16 + 32]);
	scrypt_shuffle(&B[0 + 64]);
	scrypt_shuffle(&B[16 + 64]);
}*/

#else

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16], uint32_t*V, uint32_t N)
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
		#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x04 ^= R(x00+x12, 7);	x09 ^= R(x05+x01, 7);
		x14 ^= R(x10+x06, 7);	x03 ^= R(x15+x11, 7);
		
		x08 ^= R(x04+x00, 9);	x13 ^= R(x09+x05, 9);
		x02 ^= R(x14+x10, 9);	x07 ^= R(x03+x15, 9);
		
		x12 ^= R(x08+x04,13);	x01 ^= R(x13+x09,13);
		x06 ^= R(x02+x14,13);	x11 ^= R(x07+x03,13);
		
		x00 ^= R(x12+x08,18);	x05 ^= R(x01+x13,18);
		x10 ^= R(x06+x02,18);	x15 ^= R(x11+x07,18);
		
		/* Operate on rows. */
		x01 ^= R(x00+x03, 7);	x06 ^= R(x05+x04, 7);
		x11 ^= R(x10+x09, 7);	x12 ^= R(x15+x14, 7);
		
		x02 ^= R(x01+x00, 9);	x07 ^= R(x06+x05, 9);
		x08 ^= R(x11+x10, 9);	x13 ^= R(x12+x15, 9);
		
		x03 ^= R(x02+x01,13);	x04 ^= R(x07+x06,13);
		x09 ^= R(x08+x11,13);	x14 ^= R(x13+x12,13);
		
		x00 ^= R(x03+x02,18);	x05 ^= R(x04+x07,18);
		x10 ^= R(x09+x08,18);	x15 ^= R(x14+x13,18);
		#undef R
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}
static inline void xor_salsa8_prefetch(uint32_t B[16], const uint32_t Bx[16], uint32_t*V, uint32_t N)
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
		#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x04 ^= R(x00+x12, 7);	x09 ^= R(x05+x01, 7);
		x14 ^= R(x10+x06, 7);	x03 ^= R(x15+x11, 7);
		
		x08 ^= R(x04+x00, 9);	x13 ^= R(x09+x05, 9);
		x02 ^= R(x14+x10, 9);	x07 ^= R(x03+x15, 9);
		
		x12 ^= R(x08+x04,13);	x01 ^= R(x13+x09,13);
		x06 ^= R(x02+x14,13);	x11 ^= R(x07+x03,13);
		
		x00 ^= R(x12+x08,18);	x05 ^= R(x01+x13,18);
		x10 ^= R(x06+x02,18);	x15 ^= R(x11+x07,18);
		
		/* Operate on rows. */
		x01 ^= R(x00+x03, 7);	x06 ^= R(x05+x04, 7);
		x11 ^= R(x10+x09, 7);	x12 ^= R(x15+x14, 7);
		
		x02 ^= R(x01+x00, 9);	x07 ^= R(x06+x05, 9);
		x08 ^= R(x11+x10, 9);	x13 ^= R(x12+x15, 9);
		
		x03 ^= R(x02+x01,13);	x04 ^= R(x07+x06,13);
		x09 ^= R(x08+x11,13);	x14 ^= R(x13+x12,13);
		
		x00 ^= R(x03+x02,18);	x05 ^= R(x04+x07,18);
		x10 ^= R(x09+x08,18);	x15 ^= R(x14+x13,18);
		#undef R
	}
	B[ 0] += x00;
	uint32_t one = 32 * (B[0] & (N - 1));
	__builtin_prefetch(&V[one]);
	__builtin_prefetch(&V[one + 8]);
	__builtin_prefetch(&V[one + 16]);
	__builtin_prefetch(&V[one + 24]);
	asm("":::"memory");
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

static inline void scrypt_core(uint32_t *X, uint32_t *V, int N)
{
	int i;

	for (i = 0; i < N; i++) {
		memcpy(&V[i * 32], X, 128);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < N; i++) {
		uint32_t j = 32 * (X[16] & (N - 1));
		for (uint8_t k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8_prefetch(&X[16], &X[0], V, N);
	}
}

#endif

#ifndef SCRYPT_MAX_WAYS
#define SCRYPT_MAX_WAYS 1
#define scrypt_best_throughput() 1
#endif

pthread_mutex_t alloc_mutex = PTHREAD_MUTEX_INITIALIZER;
bool printed = false;
bool tested_hugepages = false;
bool disable_hugepages = false;
int hugepages_successes = 0;
int hugepages_fails = 0;
int hugepages_size_failed = 0;
unsigned char *scrypt_buffer_alloc(int N, int forceThroughput)
{
	uint32_t throughput = forceThroughput == -1 ? scrypt_best_throughput() : forceThroughput;
	#ifndef __aarch64__
	if (opt_ryzen_1x) {
		// force throughput to be 3 (aka AVX) instead of AVX2.
		throughput = 3;
	}
	#endif
	size_t size = throughput * 32 * (N + 1) * sizeof(uint32_t);

#ifdef __linux__
	pthread_mutex_lock(&alloc_mutex);
	if (!tested_hugepages)
	{
		FILE* f = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
		if (f)
		{
			char buff[32];
			fread(buff, 32, 1, f);
			fclose(f);
			if (strstr(buff, "[always]") != NULL)
			{
				applog(LOG_DEBUG, "HugePages type: transparent_hugepages\n");
				disable_hugepages = true;
			}
		}
		else
		{
		}
		tested_hugepages = true;
	}
	pthread_mutex_unlock(&alloc_mutex);

	if (!disable_hugepages)
	{
		unsigned char* m_memory = (unsigned char*)(mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE | MAP_NONBLOCK | MAP_NORESERVE, 0, 0));
		if (m_memory == MAP_FAILED)
		{
			pthread_mutex_lock(&alloc_mutex);
			hugepages_fails++;
			hugepages_size_failed += ((size / (2 * 1024 * 1024)) + 1);
			if( hugepages_successes == 0)
			{
				if (!printed)
				{
					applog(LOG_DEBUG, "HugePages unavailable (%d)\n", errno);
					printed = true;
				}
			}
			else
			{
				applog(LOG_INFO, "HugePages too small! (%d success, %d fail)\n\tNeed at most %d more hugepages\n", hugepages_successes, hugepages_fails, hugepages_size_failed);
			}
			pthread_mutex_unlock(&alloc_mutex);
			m_memory = (unsigned char*)malloc(size);
		}
		else
		{
			pthread_mutex_lock(&alloc_mutex);
			if (!printed)
			{
				printed = true;
				applog(LOG_DEBUG, "HugePages type: preallocated\n");
			}
			hugepages_successes++;
			pthread_mutex_unlock(&alloc_mutex);
		}	
		return m_memory;
	}
	else
	{
		// pointer aligned to cache line size 64 bytes
		return (unsigned char*)aligned_alloc(64,size);
	}
#elif defined(WIN32)

	pthread_mutex_lock(&alloc_mutex);
	if (!tested_hugepages)
	{
		tested_hugepages = true;
		
		HANDLE           hToken;
		TOKEN_PRIVILEGES tp;
		BOOL             status;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
			disable_hugepages = true;

		if (!disable_hugepages && !LookupPrivilegeValue(NULL, TEXT("SeLockMemoryPrivilege"), &tp.Privileges[0].Luid))
			disable_hugepages = true;

		if (!disable_hugepages)
		{
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			status = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
		}

		if (disable_hugepages || (!status || (GetLastError() != ERROR_SUCCESS)))
		{
			applog(LOG_DEBUG, "HugePages: not enabled, view readme for more info!");
			disable_hugepages = true;
		}

		CloseHandle(hToken);
	}
	pthread_mutex_unlock(&alloc_mutex);

	if (tested_hugepages && !disable_hugepages)
	{   
		int size = N * scrypt_best_throughput() * 128;
		SIZE_T iLargePageMin = GetLargePageMinimum();
		if (size < iLargePageMin)
			size = iLargePageMin;

		unsigned char *scratchpad = VirtualAllocEx(GetCurrentProcess(), NULL, size, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
		if (!scratchpad)
		{
			applog(LOG_ERR, "Large page allocation failed.");
			scratchpad = VirtualAllocEx(GetCurrentProcess(), NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}

		return scratchpad;
	}
	else
	{
		return (unsigned char*)malloc(size);
	}

#else
	return (unsigned char*)malloc(size);
#endif
}

#define UNION_CAST(x, destType) \
   (((union {__typeof__(x) a; destType b;})x).b)

static void scrypt_1024_1_1_256(const uint32_t *input, uint32_t *output,
	uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t tstate[8] __attribute__((__aligned__(16))), ostate[8] __attribute__((__aligned__(16)));
	uint32_t X[32] __attribute__((__aligned__(16)));
	//uint32_t *V __attribute__((__aligned__(64)));

	// Cast custom typedef 1024 bit scratchpad pointer aligned to cache line size of 64 bytes on armv8
	#ifdef __aarch64__
	uint32x4x8_t *V __attribute__((__aligned__(64))) = (uint32x4x8_t *)(((uintptr_t)(UNION_CAST(__builtin_assume_aligned(scratchpad, 64), uint32x4x8_t *)) + 63) & ~ (uintptr_t)(63));
	#else
	uint32_t *V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));
	#endif

	newmemcpy(tstate, midstate, 32);
	HMAC_SHA256_80_init_armv8(input, tstate, ostate, 1);

	PBKDF2_SHA256_80_128_armv8(tstate, ostate, input, X);

	scrypt_core(X, V/*, N*/); // Hardcode N into function instead

	PBKDF2_SHA256_128_32_armv8(tstate, ostate, X, output, 1);
}

#ifdef HAVE_SHA256_4WAY
static void scrypt_1024_1_1_256_4way(const uint32_t *input,
	uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t _ALIGN(128) tstate[4 * 8];
	uint32_t _ALIGN(128) ostate[4 * 8];
	uint32_t _ALIGN(128) W[4 * 32];
	uint32_t _ALIGN(128) X[4 * 32];
	uint32_t *V;
	int i, k;
	
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	for (i = 0; i < 20; i++)
		for (k = 0; k < 4; k++)
			W[4 * i + k] = input[k * 20 + i];
	for (i = 0; i < 8; i++)
		for (k = 0; k < 4; k++)
			tstate[4 * i + k] = midstate[i];
	HMAC_SHA256_80_init_4way(W, tstate, ostate);
	PBKDF2_SHA256_80_128_4way(tstate, ostate, W, W);
	for (i = 0; i < 32; i++)
		for (k = 0; k < 4; k++)
			X[k * 32 + i] = W[4 * i + k];
	scrypt_core(X + 0 * 32, V, N);
	scrypt_core(X + 1 * 32, V, N);
	scrypt_core(X + 2 * 32, V, N);
	scrypt_core(X + 3 * 32, V, N);
	for (i = 0; i < 32; i++)
		for (k = 0; k < 4; k++)
			W[4 * i + k] = X[k * 32 + i];
	PBKDF2_SHA256_128_32_4way(tstate, ostate, W, W);
	for (i = 0; i < 8; i++)
		for (k = 0; k < 4; k++)
			output[k * 8 + i] = W[4 * i + k];
}
#endif /* HAVE_SHA256_4WAY */

#ifdef HAVE_SCRYPT_2WAY

static void scrypt_1024_1_1_256_2way(const uint32_t *input,
	uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t tstate[2 * 8] __attribute__((__aligned__(16))), ostate[2 * 8] __attribute__((__aligned__(16)));
	uint32_t X[2 * 32] __attribute__((__aligned__(16)));
	uint32_t *V __attribute__((__aligned__(16)));
	
	V = (uint32_t *)(((uintptr_t)(UNION_CAST(__builtin_assume_aligned(scratchpad, 64), uint32_t *)) + 63) & ~ (uintptr_t)(63));

	newmemcpy(tstate +  0, midstate, 32);
	newmemcpy(tstate +  8, midstate, 32);
	HMAC_SHA256_80_init_armv8(input, tstate, ostate, 2);
	//HMAC_SHA256_80_init_armv8(input + 20, tstate +  8, ostate +  8);
	PBKDF2_SHA256_80_128_armv8(tstate +  0, ostate +  0, input +  0, X +  0);
	PBKDF2_SHA256_80_128_armv8(tstate +  8, ostate +  8, input + 20, X + 32);

	scrypt_core_2way(X, V/*, N*/); // Hardcode N into function instead

	PBKDF2_SHA256_128_32_armv8(tstate +  0, ostate +  0, X +  0, output +  0, 2);
	//PBKDF2_SHA256_128_32_armv8(tstate +  8, ostate +  8, X + 32, output +  8);
}

#endif /* HAVE_SCRYPT_2WAY */

#ifdef HAVE_SCRYPT_3WAY

static void scrypt_1024_1_1_256_3way(const uint32_t *input,
	uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t _ALIGN(64) tstate[3 * 8], ostate[3 * 8];
	uint32_t _ALIGN(64) X[3 * 32];
	uint32_t *V;
	
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	newmemcpy(tstate +  0, midstate, 32);
	newmemcpy(tstate +  8, midstate, 32);
	newmemcpy(tstate + 16, midstate, 32);
	HMAC_SHA256_80_init(input +  0, tstate +  0, ostate +  0);
	HMAC_SHA256_80_init(input + 20, tstate +  8, ostate +  8);
	HMAC_SHA256_80_init(input + 40, tstate + 16, ostate + 16);
	PBKDF2_SHA256_80_128(tstate +  0, ostate +  0, input +  0, X +  0);
	PBKDF2_SHA256_80_128(tstate +  8, ostate +  8, input + 20, X + 32);
	PBKDF2_SHA256_80_128(tstate + 16, ostate + 16, input + 40, X + 64);

	scrypt_core_3way(X, V, N);

	PBKDF2_SHA256_128_32(tstate +  0, ostate +  0, X +  0, output +  0);
	PBKDF2_SHA256_128_32(tstate +  8, ostate +  8, X + 32, output +  8);
	PBKDF2_SHA256_128_32(tstate + 16, ostate + 16, X + 64, output + 16);
}

#ifdef HAVE_SHA256_4WAY
static void scrypt_1024_1_1_256_12way(const uint32_t *input,
	uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t _ALIGN(128) tstate[12 * 8];
	uint32_t _ALIGN(128) ostate[12 * 8];
	uint32_t _ALIGN(128) W[12 * 32];
	uint32_t _ALIGN(128) X[12 * 32];
	uint32_t *V;
	int i, j, k;
	
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	for (j = 0; j < 3; j++)
		for (i = 0; i < 20; i++)
			for (k = 0; k < 4; k++)
				W[128 * j + 4 * i + k] = input[80 * j + k * 20 + i];
	for (j = 0; j < 3; j++)
		for (i = 0; i < 8; i++)
			for (k = 0; k < 4; k++)
				tstate[32 * j + 4 * i + k] = midstate[i];
	HMAC_SHA256_80_init_4way(W +   0, tstate +  0, ostate +  0);
	HMAC_SHA256_80_init_4way(W + 128, tstate + 32, ostate + 32);
	HMAC_SHA256_80_init_4way(W + 256, tstate + 64, ostate + 64);
	PBKDF2_SHA256_80_128_4way(tstate +  0, ostate +  0, W +   0, W +   0);
	PBKDF2_SHA256_80_128_4way(tstate + 32, ostate + 32, W + 128, W + 128);
	PBKDF2_SHA256_80_128_4way(tstate + 64, ostate + 64, W + 256, W + 256);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 32; i++)
			for (k = 0; k < 4; k++)
				X[128 * j + k * 32 + i] = W[128 * j + 4 * i + k];
	scrypt_core_3way(X + 0 * 96, V, N);
	scrypt_core_3way(X + 1 * 96, V, N);
	scrypt_core_3way(X + 2 * 96, V, N);
	scrypt_core_3way(X + 3 * 96, V, N);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 32; i++)
			for (k = 0; k < 4; k++)
				W[128 * j + 4 * i + k] = X[128 * j + k * 32 + i];
	PBKDF2_SHA256_128_32_4way(tstate +  0, ostate +  0, W +   0, W +   0);
	PBKDF2_SHA256_128_32_4way(tstate + 32, ostate + 32, W + 128, W + 128);
	PBKDF2_SHA256_128_32_4way(tstate + 64, ostate + 64, W + 256, W + 256);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 8; i++)
			for (k = 0; k < 4; k++)
				output[32 * j + k * 8 + i] = W[128 * j + 4 * i + k];
}
#endif /* HAVE_SHA256_4WAY */

#endif /* HAVE_SCRYPT_3WAY */

#ifdef HAVE_SCRYPT_6WAY
static void scrypt_1024_1_1_256_24way(const uint32_t *input,
	uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t _ALIGN(128) tstate[24 * 8];
	uint32_t _ALIGN(128) ostate[24 * 8];
	uint32_t _ALIGN(128) W[24 * 32];
	uint32_t _ALIGN(128) X[24 * 32];
	uint32_t *V;
	int i, j, k;
	
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));
	
	for (j = 0; j < 3; j++) 
		for (i = 0; i < 20; i++)
			for (k = 0; k < 8; k++)
				W[8 * 32 * j + 8 * i + k] = input[8 * 20 * j + k * 20 + i];
	for (j = 0; j < 3; j++)
		for (i = 0; i < 8; i++)
			for (k = 0; k < 8; k++)
				tstate[8 * 8 * j + 8 * i + k] = midstate[i];
	HMAC_SHA256_80_init_8way(W +   0, tstate +   0, ostate +   0);
	HMAC_SHA256_80_init_8way(W + 256, tstate +  64, ostate +  64);
	HMAC_SHA256_80_init_8way(W + 512, tstate + 128, ostate + 128);
	PBKDF2_SHA256_80_128_8way(tstate +   0, ostate +   0, W +   0, W +   0);
	PBKDF2_SHA256_80_128_8way(tstate +  64, ostate +  64, W + 256, W + 256);
	PBKDF2_SHA256_80_128_8way(tstate + 128, ostate + 128, W + 512, W + 512);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 32; i++)
			for (k = 0; k < 8; k++)
				X[8 * 32 * j + k * 32 + i] = W[8 * 32 * j + 8 * i + k];
	scrypt_core_6way(X + 0 * 32, V, N);
	scrypt_core_6way(X + 6 * 32, V, N);
	scrypt_core_6way(X + 12 * 32, V, N);
	scrypt_core_6way(X + 18 * 32, V, N);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 32; i++)
			for (k = 0; k < 8; k++)
				W[8 * 32 * j + 8 * i + k] = X[8 * 32 * j + k * 32 + i];
	PBKDF2_SHA256_128_32_8way(tstate +   0, ostate +   0, W +   0, W +   0);
	PBKDF2_SHA256_128_32_8way(tstate +  64, ostate +  64, W + 256, W + 256);
	PBKDF2_SHA256_128_32_8way(tstate + 128, ostate + 128, W + 512, W + 512);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 8; i++)
			for (k = 0; k < 8; k++)
				output[8 * 8 * j + k * 8 + i] = W[8 * 32 * j + 8 * i + k];
}
#endif /* HAVE_SCRYPT_6WAY */

extern int scanhash_scrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
	unsigned char *scratchbuf, uint32_t N, int forceThroughput)
{
	int throughput = (forceThroughput != -1) ? forceThroughput : scrypt_best_throughput();
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	// create arrays based on exact size requirements
	uint32_t data[throughput * 20], hash[throughput * 8];
	uint32_t midstate[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[7];
 

#ifndef __aarch64__
	if (opt_ryzen_1x) {
		// force throughput to be 3 (aka AVX) instead of AVX2.
		throughput = 3;
	}
#endif
	int i;
	
#ifdef HAVE_SHA256_4WAY
	if (sha256_use_4way())
		throughput *= 4;
#endif	

	/*if (forceThroughput != -1)
	{
		throughput = forceThroughput;
	}*/

	for (i = 0; i < throughput; i++)
		newmemcpy(data + i * 20, pdata, 80);
	
	//sha256_init_armv8(midstate);
	sha256_transform_armv8_init(midstate, data);
	
	do {
		for (i = 0; i < throughput; i++)
			data[i * 20 + 19] = ++n;
		
#if defined(HAVE_SHA256_4WAY)
		if (throughput == 4)
			scrypt_1024_1_1_256_4way(data, hash, midstate, scratchbuf, N);
		else
#endif
#if defined(HAVE_SCRYPT_3WAY) && defined(HAVE_SHA256_4WAY)
		if (throughput == 12)
			scrypt_1024_1_1_256_12way(data, hash, midstate, scratchbuf, N);
		else
#endif
#if defined(HAVE_SCRYPT_6WAY)
		if (throughput == 24)
			scrypt_1024_1_1_256_24way(data, hash, midstate, scratchbuf, N);
		else
#endif
#if defined(HAVE_SCRYPT_2WAY)
		if (throughput == 2)
			scrypt_1024_1_1_256_2way(data, hash, midstate, scratchbuf, N);
		else
#endif
#if defined(HAVE_SCRYPT_3WAY)
		if (throughput == 3)
			scrypt_1024_1_1_256_3way(data, hash, midstate, scratchbuf, N);
		else
#endif
			scrypt_1024_1_1_256(data, hash, midstate, scratchbuf, N);

		for (i = 0; i < throughput; i++) {
			if (unlikely(hash[i * 8 + 7] <= Htarg && fulltest(hash + i * 8, ptarget))) {
				work_set_target_ratio(work, hash + i * 8);
				*hashes_done = n - pdata[19] + 1;
				pdata[19] = data[i * 20 + 19];
				return 1;
			}
		}
	} while (likely(n < max_nonce && !work_restart[thr_id].restart));
	
	*hashes_done = n - pdata[19] + 1;
	pdata[19] = n;
	return 0;
}

/* simple cpu test (util.c) */
void scrypthash(void *output, const void *input, uint32_t N)
{
	uint32_t midstate[8];
	char *scratchbuf = scrypt_buffer_alloc(N, -1);

	memset(output, 0, 32);
	if (!scratchbuf)
		return;

	//sha256_init_armv8(midstate);
	sha256_transform_armv8_init(midstate, input);

	scrypt_1024_1_1_256((uint32_t*)input, (uint32_t*)output, midstate, scratchbuf, N);

	free(scratchbuf);
}
