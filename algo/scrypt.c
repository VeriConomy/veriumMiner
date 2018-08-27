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
 *			Might add support for it (Odroid XU4 users) in future.
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

#ifndef __aarch64__

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

//simplified & inlinable version of memcpy.
static inline void newmemcpy(uint32_t *__restrict__ dstp, const uint32_t *__restrict__ srcp, uint len)
{
	ulong *dst = (ulong *) dstp;
	ulong *src = (ulong *) srcp;
	uint i;

	for(i = 0; i < (len / sizeof(ulong)); i++)
		*dst++ = *src++;
}

//simplified & inlinable version of memcpy with "tail" handling.
static inline void newmemcpytail(uint32_t *__restrict__ dstp, const uint32_t *__restrict__ srcp, uint len)
{
	ulong *dst = (ulong *) dstp;
	ulong *src = (ulong *) srcp;
	uint i, tail;

	for(i = 0; i < (len / sizeof(ulong)); i++)
		*dst++ = *src++;

	tail = len & (sizeof(ulong) - 1);
	//if(tail) { //one instance requires this
		uchar *dstb = (uchar *) dstp;
		uchar *srcb = (uchar *) srcp;

		for(i = len - tail; i < len; i++)
			dstb[i] = srcb[i];
	//}
}

//simplified & inlinable version of memcpy.
static inline void scrypt_core_copy(uint32_t *__restrict__ dstp, uint32_t *__restrict__ srcp)
{
	ulong *dst = (ulong *) dstp;
	ulong *src = (ulong *) srcp;
	uint i;

	for(i = 0; i < 16; i++)
		*dst++ = *src++;
}

//functions inspired by newmemcopy used in salsa20_block which itself was not as performant as original xorsalsa.
static inline void salsa_postloop_copyadd(uint32_t *__restrict__ dstp, uint32_t *__restrict__ srcp)
{
	uint i;
	for(i = 0; i < 16; i++)
		*dstp++ += *srcp++;
}

static inline void salsaprefetch_postloop_add(uint32_t *__restrict__ dstp, uint32_t *__restrict__ srcp)
{
	uint i;
	for(i = 0; i < 15; i++)
		*dstp++ += *srcp++;
}

static inline void salsa20_block_xoreq_preloop(uint32_t *__restrict__ x, uint32_t *__restrict__ B, const uint32_t *__restrict__ Bx)
{
	uint i;
	for(i = 0; i < 16; i++)
		*x++ = (*B++ ^= *Bx++);
}

//does not work
static inline uint32x4_t neon_bswap32_uint32x4_t(uint32x4_t val)
{
    val = vorrq_u32(vandq_u32(vshlq_n_u32(val, 8), vdupq_n_u32(4278255360)), vandq_u32(vsriq_n_u32(val,val, 8), vdupq_n_u32(16711935))); 
    return vorrq_u32(vshlq_n_u32(val, 16), vsriq_n_u32(val,val, 16));
}

static const uint32_t sha256_h[8] = {
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

static uint32x4_t w0, w1, w2, w3, ddtmp;
static uint32x4x2_t dd, sta;
static uint32x4_t t0, t1;

static inline void sha256_init_armv8(uint32_t *__restrict__ state)
{
	newmemcpy(state, sha256_h, 32);
}

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

//based on sha2armv8.c in new vrm wallet. Minor performance gain from inlineable shrunken code.
static inline void sha256_transform_armv8(uint32_t state[8], const uint32_t data[16], int swap)
{

	/* load state */
	sta.val[0] = vld1q_u32(&state[0]);
	sta.val[1] = vld1q_u32(&state[4]);

	/* load message */
	w0 = vld1q_u32(data);
	w1 = vld1q_u32(data + 4);
	w2 = vld1q_u32(data + 8);
	w3 = vld1q_u32(data + 12);

	if (__builtin_expect(swap, 0)) {
		w0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w0)));
		w1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w1)));
		w2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w2)));
		w3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(w3)));
	}

	/* initialize t0, dd.val[0], dd.val[1] */
	t0 = vaddq_u32(w0, k0.val[0]);
	dd = sta;
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

// scrypt_core prefers this
static void HMAC_SHA256_80_init_armv8_noinline(const uint32_t *__restrict__ key,
	uint32_t *__restrict__ tstate, uint32_t *__restrict__ ostate)
{
	uint32_t ihash[8];
	uint32_t pad[16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	newmemcpy(pad, key + 16, 16);
	newmemcpy(pad + 4, keypad, 48);
	sha256_transform_armv8(tstate, pad, 0);
	newmemcpy(ihash, tstate, 32);

	sha256_init_armv8(ostate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform_armv8(ostate, pad, 0);

	sha256_init_armv8(tstate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	sha256_transform_armv8(tstate, pad, 0);
}

static inline void HMAC_SHA256_80_init_armv8(const uint32_t *__restrict__ key,
	uint32_t *__restrict__ tstate, uint32_t *__restrict__ ostate)
{
	uint32_t ihash[8];
	uint32_t pad[16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	newmemcpy(pad, key + 16, 16);
	newmemcpy(pad + 4, keypad, 48);
	sha256_transform_armv8(tstate, pad, 0);
	newmemcpy(ihash, tstate, 32);

	sha256_init_armv8(ostate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform_armv8(ostate, pad, 0);

	sha256_init_armv8(tstate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	sha256_transform_armv8(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128_armv8(const uint32_t *__restrict__ tstate,
	const uint32_t *__restrict__ ostate, const uint32_t *__restrict__ salt, uint32_t *__restrict__ output)
{
	uint32_t istate[8], ostate2[8];
	uint32_t ibuf[16], obuf[16];
	int i, j;

	newmemcpy(istate, tstate, 32);
	sha256_transform_armv8(istate, salt, 0);
	
	newmemcpy(ibuf, salt + 16, 16);
	newmemcpytail(ibuf + 5, innerpad, 44);
	newmemcpy(obuf + 8, outerpad, 32);

	for (i = 0; i < 4; i++) {
		newmemcpy(obuf, istate, 32);
		ibuf[4] = i + 1;
		sha256_transform_armv8(obuf, ibuf, 0);

		newmemcpy(ostate2, ostate, 32);
		sha256_transform_armv8(ostate2, obuf, 0);
		for (j = 0; j < 8; j++)
			output[8 * i + j] = __builtin_bswap32(ostate2[j]);
	}
}

static void PBKDF2_SHA256_128_32_armv8(uint32_t *__restrict__ tstate, uint32_t *__restrict__ ostate,
	const uint32_t *__restrict__ salt, uint32_t *__restrict__ output)
{
	uint32_t buf[16];
	int i;
	
	sha256_transform_armv8(tstate, salt, 1);
	sha256_transform_armv8(tstate, salt + 16, 1);
	sha256_transform_armv8(tstate, finalblk, 0);
	newmemcpy(buf, tstate, 32);
	newmemcpy(buf + 8, outerpad, 32);

	sha256_transform_armv8(ostate, buf, 0);
	for (i = 0; i < 8; i++)
		output[i] = __builtin_bswap32(ostate[i]);
}
/*
static inline uint32_t ROTL(uint32_t *__restrict__ value, unsigned int count) {
    return *value<<count | *value>>(32-count);
}*/


#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d)(		\
	b ^= ROTL(a + d, 7),	\
	c ^= ROTL(b + a, 9),	\
	d ^= ROTL(c + b,13),	\
	a ^= ROTL(d + c,18))
/*
static inline void QR(uint32_t *__restrict__ a, uint32_t *__restrict__ b, uint32_t *__restrict__ c, uint32_t *__restrict__ d) {
	*b ^= ROTL(*a + *d, 7);
	*c ^= ROTL(*b + *a, 9);
	*d ^= ROTL(*c + *b,13);
	*a ^= ROTL(*d + *c,18);
}*/

//Wikipedia based xorsalsa. Slight performance regression.
static inline void salsa20_block(uint32_t B[16], uint32_t const Bx[16])
{
	int i;
	uint32_t x[16];

salsa20_block_xoreq_preloop(x,B,Bx);

	// 10 loops × 2 rounds/loop = 20 rounds
	for (int i = 0; i < 2; i ++) {
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
	salsa_postloop_copyadd(&B[ 0],&x[ 0]);
}

//Wikipedia based xorsalsa. Slight performance regression.
static void salsa20_block_prefetch(uint32_t B[16], uint32_t const Bx[16], uint32_t *__restrict__ V, uint32_t N)
{
	int i;
	uint32_t x[16];

	salsa20_block_xoreq_preloop(x,B,Bx);

	// 10 loops × 2 rounds/loop = 20 rounds
	for (int i = 0; i < 2; i ++) {
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
	B[ 0] += x[ 0];
	uint32_t one = 32 * (B[0] & (N - 1));
	__builtin_prefetch(&V[one + 0]);
	__builtin_prefetch(&V[one + 8]);
	__builtin_prefetch(&V[one + 16]);
	__builtin_prefetch(&V[one + 24]);
	asm("":::"memory");
	salsaprefetch_postloop_add(&B[1], &x[1]);
}

static inline uint32_t myXOR(uint32_t x, uint32_t y)
{
   return (x | y) & (~x | ~y);
}

/* Loop is unrolled from 4 iterations to 2 for slightly better performance on aarch64*/
static void inline xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
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
	for (i = 0; i < 2; i ++) {
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

/*		// Operate on columns. *attempted to encourange dual issue. gcc8 does not order enough asm instructions for xorsalsa
		tmp = x00 + x12;
		tmp2 = x05 + x01;
		x04 ^= R(tmp, 7);
		x09 ^= R(tmp2, 7);
		tmp = x10 + x06;
		tmp2 = x15 + x11;
		x14 ^= R(tmp, 7);	
		x03 ^= R(tmp2, 7);
		
		tmp = x04 + x00;
		tmp2 = x09 + x05;
		x08 ^= R(tmp, 9);	
		x13 ^= R(tmp2, 9);
		tmp = x14 + x10;
		tmp2 = x03 + x15;
		x02 ^= R(tmp, 9);	
		x07 ^= R(tmp2, 9);
		
		tmp = x08 + x04;
		tmp2 = x13 + x09;
		x12 ^= R(tmp,13);	
		x01 ^= R(tmp2,13);
		tmp = x02 + x14;
		tmp2 = x07 + x03;
		x06 ^= R(tmp,13);	
		x11 ^= R(tmp2,13);
		
		tmp = x12 + x08;
		tmp2 = x01 + x13;
		x00 ^= R(tmp,18);	
		x05 ^= R(tmp2,18);
		tmp = x06 + x02;
		tmp2 = x11 + x07;
		x10 ^= R(tmp,18);	
		x15 ^= R(tmp2,18);
		
		// Operate on rows. 
		tmp = x00 + x03;
		tmp2 = x05 + x04;
		x01 ^= R(tmp, 7);	
		x06 ^= R(tmp2, 7);
		tmp = x10 + x09;
		tmp2 = x15 + x14;
		x11 ^= R(tmp, 7);	
		x12 ^= R(tmp2, 7);
		
		tmp = x01 + x00;
		tmp2 = x06 + x05;
		x02 ^= R(tmp, 9);	
		x07 ^= R(tmp2, 9);
		tmp = x11 + x10;
		tmp2 = x12 + x15;
		x08 ^= R(tmp, 9);	
		x13 ^= R(tmp2, 9);
		
		tmp = x02 + x01;
		tmp2 = x07 + x06;
		x03 ^= R(tmp,13);	
		x04 ^= R(tmp2,13);
		tmp = x08 + x11;
		tmp2 = x13 + x12;
		x09 ^= R(tmp,13);	
		x14 ^= R(tmp2,13);
		
		tmp = x03 + x02;
		tmp2 = x04 + x07;
		x00 ^= R(tmp,18);	
		x05 ^= R(tmp2,18);
		tmp = x09 + x08;
		tmp2 = x14 + x13;
		x10 ^= R(tmp,18);	
		x15 ^= R(tmp2,18);

		// Operate on columns. 
		tmp = x00 + x12;
		tmp2 = x05 + x01;
		x04 ^= R(tmp, 7);
		x09 ^= R(tmp2, 7);
		tmp = x10 + x06;
		tmp2 = x15 + x11;
		x14 ^= R(tmp, 7);	
		x03 ^= R(tmp2, 7);
		
		tmp = x04 + x00;
		tmp2 = x09 + x05;
		x08 ^= R(tmp, 9);	
		x13 ^= R(tmp2, 9);
		tmp = x14 + x10;
		tmp2 = x03 + x15;
		x02 ^= R(tmp, 9);	
		x07 ^= R(tmp2, 9);
		
		tmp = x08 + x04;
		tmp2 = x13 + x09;
		x12 ^= R(tmp,13);	
		x01 ^= R(tmp2,13);
		tmp = x02 + x14;
		tmp2 = x07 + x03;
		x06 ^= R(tmp,13);	
		x11 ^= R(tmp2,13);
		
		tmp = x12 + x08;
		tmp2 = x01 + x13;
		x00 ^= R(tmp,18);	
		x05 ^= R(tmp2,18);
		tmp = x06 + x02;
		tmp2 = x11 + x07;
		x10 ^= R(tmp,18);	
		x15 ^= R(tmp2,18);
		
		// Operate on rows. 
		tmp = x00 + x03;
		tmp2 = x05 + x04;
		x01 ^= R(tmp, 7);	
		x06 ^= R(tmp2, 7);
		tmp = x10 + x09;
		tmp2 = x15 + x14;
		x11 ^= R(tmp, 7);	
		x12 ^= R(tmp2, 7);
		
		tmp = x01 + x00;
		tmp2 = x06 + x05;
		x02 ^= R(tmp, 9);	
		x07 ^= R(tmp2, 9);
		tmp = x11 + x10;
		tmp2 = x12 + x15;
		x08 ^= R(tmp, 9);	
		x13 ^= R(tmp2, 9);
		
		tmp = x02 + x01;
		tmp2 = x07 + x06;
		x03 ^= R(tmp,13);	
		x04 ^= R(tmp2,13);
		tmp = x08 + x11;
		tmp2 = x13 + x12;
		x09 ^= R(tmp,13);	
		x14 ^= R(tmp2,13);
		
		tmp = x03 + x02;
		tmp2 = x04 + x07;
		x00 ^= R(tmp,18);	
		x05 ^= R(tmp2,18);
		tmp = x09 + x08;
		tmp2 = x14 + x13;
		x10 ^= R(tmp,18);	
		x15 ^= R(tmp2,18);
*/
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

/* Loop is unrolled from 4 iterations to 2 for slightly better performance on aarch64 */
static void inline xor_salsa8_prefetch(uint32_t B[16], const uint32_t Bx[16], uint32_t *__restrict__ V, uint32_t N)
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
	for (i = 0; i < 2; i ++) {
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

/* attempted to encourange dual issue. gcc8 does not order instructions enough for xorsalsa
		// Operate on columns. 
		tmp = x00 + x12;
		tmp2 = x05 + x01;
		x04 ^= R(tmp, 7);
		x09 ^= R(tmp2, 7);
		tmp = x10 + x06;
		tmp2 = x15 + x11;
		x14 ^= R(tmp, 7);	
		x03 ^= R(tmp2, 7);
		
		tmp = x04 + x00;
		tmp2 = x09 + x05;
		x08 ^= R(tmp, 9);	
		x13 ^= R(tmp2, 9);
		tmp = x14 + x10;
		tmp2 = x03 + x15;
		x02 ^= R(tmp, 9);	
		x07 ^= R(tmp2, 9);
		
		tmp = x08 + x04;
		tmp2 = x13 + x09;
		x12 ^= R(tmp,13);	
		x01 ^= R(tmp2,13);
		tmp = x02 + x14;
		tmp2 = x07 + x03;
		x06 ^= R(tmp,13);	
		x11 ^= R(tmp2,13);
		
		tmp = x12 + x08;
		tmp2 = x01 + x13;
		x00 ^= R(tmp,18);	
		x05 ^= R(tmp2,18);
		tmp = x06 + x02;
		tmp2 = x11 + x07;
		x10 ^= R(tmp,18);	
		x15 ^= R(tmp2,18);
		
		// Operate on rows. 
		tmp = x00 + x03;
		tmp2 = x05 + x04;
		x01 ^= R(tmp, 7);	
		x06 ^= R(tmp2, 7);
		tmp = x10 + x09;
		tmp2 = x15 + x14;
		x11 ^= R(tmp, 7);	
		x12 ^= R(tmp2, 7);
		
		tmp = x01 + x00;
		tmp2 = x06 + x05;
		x02 ^= R(tmp, 9);	
		x07 ^= R(tmp2, 9);
		tmp = x11 + x10;
		tmp2 = x12 + x15;
		x08 ^= R(tmp, 9);	
		x13 ^= R(tmp2, 9);
		
		tmp = x02 + x01;
		tmp2 = x07 + x06;
		x03 ^= R(tmp,13);	
		x04 ^= R(tmp2,13);
		tmp = x08 + x11;
		tmp2 = x13 + x12;
		x09 ^= R(tmp,13);	
		x14 ^= R(tmp2,13);
		
		tmp = x03 + x02;
		tmp2 = x04 + x07;
		x00 ^= R(tmp,18);	
		x05 ^= R(tmp2,18);
		tmp = x09 + x08;
		tmp2 = x14 + x13;
		x10 ^= R(tmp,18);	
		x15 ^= R(tmp2,18);
}


		// Operate on columns. 
		tmp = x00 + x12;
		tmp2 = x05 + x01;
		x04 ^= R(tmp, 7);
		x09 ^= R(tmp2, 7);
		tmp = x10 + x06;
		tmp2 = x15 + x11;
		x14 ^= R(tmp, 7);	
		x03 ^= R(tmp2, 7);
		
		tmp = x04 + x00;
		tmp2 = x09 + x05;
		x08 ^= R(tmp, 9);	
		x13 ^= R(tmp2, 9);
		tmp = x14 + x10;
		tmp2 = x03 + x15;
		x02 ^= R(tmp, 9);	
		x07 ^= R(tmp2, 9);
		
		tmp = x08 + x04;
		tmp2 = x13 + x09;
		x12 ^= R(tmp,13);	
		x01 ^= R(tmp2,13);
		tmp = x02 + x14;
		tmp2 = x07 + x03;
		x06 ^= R(tmp,13);	
		x11 ^= R(tmp2,13);
		
		tmp = x12 + x08;
		tmp2 = x01 + x13;
		x00 ^= R(tmp,18);	
		x05 ^= R(tmp2,18);
		tmp = x06 + x02;
		tmp2 = x11 + x07;
		x10 ^= R(tmp,18);	
		x15 ^= R(tmp2,18);
		
		// Operate on rows. 
		tmp = x00 + x03;
		tmp2 = x05 + x04;
		x01 ^= R(tmp, 7);	
		x06 ^= R(tmp2, 7);
		tmp = x10 + x09;
		tmp2 = x15 + x14;
		x11 ^= R(tmp, 7);	
		x12 ^= R(tmp2, 7);
		
		tmp = x01 + x00;
		tmp2 = x06 + x05;
		x02 ^= R(tmp, 9);	
		x07 ^= R(tmp2, 9);
		tmp = x11 + x10;
		tmp2 = x12 + x15;
		x08 ^= R(tmp, 9);	
		x13 ^= R(tmp2, 9);
		
		tmp = x02 + x01;
		tmp2 = x07 + x06;
		x03 ^= R(tmp,13);	
		x04 ^= R(tmp2,13);
		tmp = x08 + x11;
		tmp2 = x13 + x12;
		x09 ^= R(tmp,13);	
		x14 ^= R(tmp2,13);
		
		tmp = x03 + x02;
		tmp2 = x04 + x07;
		x00 ^= R(tmp,18);	
		x05 ^= R(tmp2,18);
		tmp = x09 + x08;
		tmp2 = x14 + x13;
		x10 ^= R(tmp,18);	
		x15 ^= R(tmp2,18);*/

/*		// Operate on columns. 

		tmp = x00 + x12;	tmp2 = x05 + x01;
		tmp3 = x10 + x06;	tmp4 = x15 + x11;
		x14 ^= R(tmp, 7);	x03 ^= R(tmp2, 7);
		x04 ^= R(tmp3, 7);	x09 ^= R(tmp4, 7);
		
		tmp = x04 + x00;	tmp2 = x09 + x05;
		tmp3 = x14 + x10;	tmp4 = x03 + x15;
		x08 ^= R(tmp, 9);	x13 ^= R(tmp2, 9);
		x02 ^= R(tmp3, 9);	x07 ^= R(tmp4, 9);
		
		tmp = x08 + x04;	tmp2 = x13 + x09;
		tmp3 = x02 + x14;	tmp4 = x07 + x03;
		x12 ^= R(tmp,13);	x01 ^= R(tmp2,13);
		x06 ^= R(tmp3,13);	x11 ^= R(tmp4,13);
		
		tmp = x12 + x08;	tmp2 = x01 + x13;
		tmp3 = x06 + x02;	tmp4 = x11 + x07;
		x00 ^= R(tmp,18);	x05 ^= R(tmp2,18);
		x10 ^= R(tmp3,18);	x15 ^= R(tmp4,18);
		
		// Operate on rows. 

		tmp = x00 + x03;	tmp2 = x05 + x04;
		tmp3 = x10 + x09;	tmp4 = x15 + x14;
		x01 ^= R(tmp, 7);	x06 ^= R(tmp2, 7);
		x11 ^= R(tmp3, 7);	x12 ^= R(tmp4, 7);
		
		tmp = x01 + x00;	tmp2 = x06 + x05;
		tmp3 = x11 + x10;	tmp4 = x12 + x15;
		x02 ^= R(tmp, 9);	x07 ^= R(tmp2, 9);
		x08 ^= R(tmp3, 9);	x13 ^= R(tmp4, 9);
		
		tmp = x02 + x01;	tmp2 = x07 + x06;
		tmp3 = x08 + x11;	tmp4 = x13 + x12;
		x03 ^= R(tmp,13);	x04 ^= R(tmp2,13);
		x09 ^= R(tmp3,13);	x14 ^= R(tmp4,13);
		
		tmp = x03 + x02;	tmp2 = x04 + x07;
		tmp3 = x09 + x08;	tmp4 = x14 + x13;
		x00 ^= R(tmp,18);	x05 ^= R(tmp2,18);
		x10 ^= R(tmp3,18);	x15 ^= R(tmp4,18);*/

#undef R
	}
	B[ 0] += x00;
	uint32_t one = 32 * (B[0] & (N - 1));
	__builtin_prefetch(&V[one + 0]);
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

// gcc8 does not always dual issues only 50% of loops.
static inline void scrypt_core(uint32_t *__restrict__ X, uint32_t *__restrict__ V, int N)
{
	int i;
	uint32_t j, k;

	for (i = 0; i < N; i++) {
		scrypt_core_copy(&V[i * 32], X);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < N; i++) {
		j = 32 * (X[16] & (N - 1));
		for (k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8_prefetch(&X[16], &X[0], V, N);
	}
}

//possibility of scrypt shuffle alternative? meh, who cares.
static inline void neoscrypt_blkswp(void *blkAp, void *blkBp, uint len)
{
	ulong *blkA = (ulong *) blkAp;
	ulong *blkB = (ulong *) blkBp;
	register ulong t0, t1, t2, t3;
	uint i;

	for(i = 0; i < (len / sizeof(ulong)); i += 4) {
		t0          = blkA[i];
		t1          = blkA[i + 1];
		t2          = blkA[i + 2];
		t3          = blkA[i + 3];
		blkA[i]     = blkB[i];
		blkA[i + 1] = blkB[i + 1];
		blkA[i + 2] = blkB[i + 2];
		blkA[i + 3] = blkB[i + 3];
		blkB[i]     = t0;
		blkB[i + 1] = t1;
		blkB[i + 2] = t2;
		blkB[i + 3] = t3;
	}
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

static inline uint32x4x4_t scrypt_deinterleave_shuffle(uint32x4x4_t B)
{
	uint32_t tmp = B.val[0][1];	
	B.val[0][1] = B.val[1][0];
	B.val[1][0] = tmp;
	tmp = B.val[0][2];
	B.val[0][2] = B.val[2][0];
	B.val[2][0] = tmp;
	tmp = B.val[0][3];
	B.val[0][3] = B.val[3][0];
	B.val[3][0] = tmp;
	tmp = B.val[1][2];
	B.val[1][2] = B.val[2][1];
	B.val[2][1] = tmp;
	tmp = B.val[1][3];
	B.val[1][3] = B.val[3][1];
	B.val[3][1] = tmp;
	tmp = B.val[2][3];
	B.val[2][3] = B.val[3][2];
	B.val[3][2] = tmp;
	
	return B;
}

/* Stripped down implementation of scrypt_core_3way for aarch64/armv8.
scrypt_core() outperforms this. May aswell remove scrypt_core_1way().
Not tested for producing valid work nor any likelyhood of performance
tuning as far I can see. Lacks possibility of dual issue. */
static inline void scrypt_core_1way(uint32_t B[32 * 1], uint32_t *__restrict__ V, uint32_t N)
{
	uint32_t* W = V;

	scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);
/*	scrypt_shuffle(&B[0 + 32]);
	scrypt_shuffle(&B[16 + 32]);
	scrypt_shuffle(&B[0 + 64]);
	scrypt_shuffle(&B[16 + 64]);*/

	uint32x4x2_t q_tmp;
  	uint32x4x4_t q_a/*, q_b, q_c,*/;
	uint32x4x4_t x, ba_a,/* bb_a, bc_a,*/ ba_b/*, bb_b, bc_b*/;

	ba_a.val[0] = vld1q_u32(&B[( 0) / 4]);
	ba_a.val[1] = vld1q_u32(&B[(16) / 4]);
	ba_a.val[2] = vld1q_u32(&B[(32) / 4]);
	ba_a.val[3] = vld1q_u32(&B[(48) / 4]);
	//ba_a = vld4q_u32(&B[0]);
	ba_b.val[0] = vld1q_u32(&B[(0 + 64 + 0) / 4]);
	ba_b.val[1] = vld1q_u32(&B[(0 + 64 + 16) / 4]);
	ba_b.val[2] = vld1q_u32(&B[(0 + 64 + 32) / 4]);
	ba_b.val[3] = vld1q_u32(&B[(0 + 64 + 48) / 4]);
	//ba_b = vld4q_u32(&B[16]);

// 	bb_a.val[0] = vld1q_u32(&B[(128 +  0) / 4]);
// 	bb_a.val[1] = vld1q_u32(&B[(128 + 16) / 4]);
// 	bb_a.val[2] = vld1q_u32(&B[(128 + 32) / 4]);
// 	bb_a.val[3] = vld1q_u32(&B[(128 + 48) / 4]);
// 	bb_b.val[0] = vld1q_u32(&B[(128 + 64 + 0) / 4]);
// 	bb_b.val[1] = vld1q_u32(&B[(128 + 64 + 16) / 4]);
// 	bb_b.val[2] = vld1q_u32(&B[(128 + 64 + 32) / 4]);
// 	bb_b.val[3] = vld1q_u32(&B[(128 + 64 + 48) / 4]);
	
// 	bc_a.val[0] = vld1q_u32(&B[(256 + 0) / 4]);
// 	bc_a.val[1] = vld1q_u32(&B[(256 + 16) / 4]);
// 	bc_a.val[2] = vld1q_u32(&B[(256 + 32) / 4]);
// 	bc_a.val[3] = vld1q_u32(&B[(256 + 48) / 4]);
// 	bc_b.val[0] = vld1q_u32(&B[(256 + 64 + 0) / 4]);
// 	bc_b.val[1] = vld1q_u32(&B[(256 + 64 + 16) / 4]);
// 	bc_b.val[2] = vld1q_u32(&B[(256 + 64 + 32) / 4]);
// 	bc_b.val[3] = vld1q_u32(&B[(256 + 64 + 48) / 4]);

	// prep

	vst1q_u32(&V[( 0) / 4], ba_a.val[0]);
	vst1q_u32(&V[(16) / 4], ba_a.val[1]);
	vst1q_u32(&V[(32) / 4], ba_a.val[2]);
	vst1q_u32(&V[(48) / 4], ba_a.val[3]);
	//vst4q_u32(&V[0], ba_a);
	vst1q_u32(&V[(64) / 4],  ba_b.val[0]);
	vst1q_u32(&V[(80) / 4],  ba_b.val[1]);
	vst1q_u32(&V[(96) / 4],  ba_b.val[2]);
	vst1q_u32(&V[(112) / 4], ba_b.val[3]);
	//vst4q_u32(&V[16], ba_b);

// 	vst1q_u32(&V[(128 +  0) / 4], bb_a.val[0]);
// 	vst1q_u32(&V[(128 + 16) / 4], bb_a.val[1]);
// 	vst1q_u32(&V[(128 + 32) / 4], bb_a.val[2]);
// 	vst1q_u32(&V[(128 + 48) / 4], bb_a.val[3]);
// 	vst1q_u32(&V[(128 + 64) / 4],  bb_b.val[0]);
// 	vst1q_u32(&V[(128 + 80) / 4],  bb_b.val[1]);
// 	vst1q_u32(&V[(128 + 96) / 4],  bb_b.val[2]);
// 	vst1q_u32(&V[(128 + 112) / 4], bb_b.val[3]);

// 	vst1q_u32(&V[(256 +  0) / 4], bc_a.val[0]);
// 	vst1q_u32(&V[(256 + 16) / 4], bc_a.val[1]);
// 	vst1q_u32(&V[(256 + 32) / 4], bc_a.val[2]);
// 	vst1q_u32(&V[(256 + 48) / 4], bc_a.val[3]);
// 	vst1q_u32(&V[(256 + 64) / 4], bc_b.val[0]);
// 	vst1q_u32(&V[(256 + 80) / 4], bc_b.val[1]);
// 	vst1q_u32(&V[(256 + 96) / 4], bc_b.val[2]);
// 	vst1q_u32(&V[(256 + 112) / 4],bc_b.val[3]);

//	V += 96; /* Original code for 3ways */
	V += 32;

	for (int n = 0; n < N; n++)
	{
		// loop 1 part a
		q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);

// 		q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
// 		q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
// 		q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);
// 		q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);

// 		q_c.val[0] = veorq_u32(bc_b.val[0], bc_a.val[0]);
// 		q_c.val[1] = veorq_u32(bc_b.val[1], bc_a.val[1]);
// 		q_c.val[2] = veorq_u32(bc_b.val[2], bc_a.val[2]);
// 		q_c.val[3] = veorq_u32(bc_b.val[3], bc_a.val[3]);

		ba_a = q_a;
// 		bb_a = q_b;
// 		bc_a = q_c;

		for (int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
 
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
 
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
 
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		q_a = ba_a;

// 		bb_a.val[0] = vaddq_u32(bb_a.val[0], q_b.val[0]);
// 		bb_a.val[1] = vaddq_u32(bb_a.val[1], q_b.val[1]);
// 		bb_a.val[2] = vaddq_u32(bb_a.val[2], q_b.val[2]);
// 		bb_a.val[3] = vaddq_u32(bb_a.val[3], q_b.val[3]);

// 		q_b = bb_a;

// 		bc_a.val[0] = vaddq_u32(bc_a.val[0], q_c.val[0]);
// 		bc_a.val[1] = vaddq_u32(bc_a.val[1], q_c.val[1]);
// 		bc_a.val[2] = vaddq_u32(bc_a.val[2], q_c.val[2]);
// 		bc_a.val[3] = vaddq_u32(bc_a.val[3], q_c.val[3]);

// 		q_c = bc_a;
		
		/*for (int i = 0; i < 4; i++)
		{
			vst1q_u32(&V[      (i * 4) ], ba_a.val[i]);
// 			vst1q_u32(&V[(32 + (i * 4))], bb_a.val[i]);
// 			vst1q_u32(&V[(64 + (i * 4))], bc_a.val[i]);
		}*/

			vst1q_u32(&V[      (0 * 4) ], ba_a.val[0]);
			vst1q_u32(&V[      (1 * 4) ], ba_a.val[1]);
			vst1q_u32(&V[      (2 * 4) ], ba_a.val[2]);
			vst1q_u32(&V[      (3 * 4) ], ba_a.val[3]);


		// loop 1 part b

		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
		ba_b = q_a;

// 		q_b.val[0] = veorq_u32(bb_b.val[0], q_b.val[0]);
// 		q_b.val[1] = veorq_u32(bb_b.val[1], q_b.val[1]);
// 		q_b.val[2] = veorq_u32(bb_b.val[2], q_b.val[2]);
// 		q_b.val[3] = veorq_u32(bb_b.val[3], q_b.val[3]);
// 		bb_b = q_b;

// 		q_c.val[0] = veorq_u32(bc_b.val[0], q_c.val[0]);
// 		q_c.val[1] = veorq_u32(bc_b.val[1], q_c.val[1]);
// 		q_c.val[2] = veorq_u32(bc_b.val[2], q_c.val[2]);
// 		q_c.val[3] = veorq_u32(bc_b.val[3], q_c.val[3]);
// 		bc_b = q_c;


		for (int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
 
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
 
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
 
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
 
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}

		ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);
// 		bb_b.val[0] = vaddq_u32(q_b.val[0], bb_b.val[0]);
// 		bb_b.val[1] = vaddq_u32(q_b.val[1], bb_b.val[1]);
// 		bb_b.val[2] = vaddq_u32(q_b.val[2], bb_b.val[2]);
// 		bb_b.val[3] = vaddq_u32(q_b.val[3], bb_b.val[3]);
// 		bc_b.val[0] = vaddq_u32(q_c.val[0], bc_b.val[0]);
// 		bc_b.val[1] = vaddq_u32(q_c.val[1], bc_b.val[1]);
// 		bc_b.val[2] = vaddq_u32(q_c.val[2], bc_b.val[2]);
// 		bc_b.val[3] = vaddq_u32(q_c.val[3], bc_b.val[3]);
		for (int i = 0; i < 4; i++)
		{
			vst1q_u32(&V[(     16 + (i * 4))], ba_b.val[i]);
// 			vst1q_u32(&V[(32 + 16 + (i * 4))], bb_b.val[i]);
// 			vst1q_u32(&V[(64 + 16 + (i * 4))], bc_b.val[i]);
		}
//		V += 96; /* Original code for scrypt_core_3ways() */
		V += 32;
	}
	V = W;

    // loop 2

//	uint32_t one =   32 * (3 * (ba_b.val[0][0] & (N - 1)) + 0); /* Original code for 3ways */
//	uint32_t two =   32 * (3 * (bb_b.val[0][0] & (N - 1)) + 1); /* Original code for 3ways */
// 	uint32_t three = 32 * (3 * (bc_b.val[0][0] & (N - 1)) + 2); /* Original code for 3ways */

	uint32_t one =   32 * (1 * (ba_b.val[0][0] & (N - 1)) + 0);
// 	uint32_t two =   32 * (2 * (bb_b.val[0][0] & (N - 1)) + 1);
// 	uint32_t three = 32 * (3 * (bc_b.val[0][0] & (N - 1)) + 2);
	q_tmp.val[0] = vld1q_u32(&W[one +  0]);
	q_tmp.val[1] = vld1q_u32(&W[one +  4]);
	q_tmp.val[2] = vld1q_u32(&W[one +  8]);
	q_tmp.val[3] = vld1q_u32(&W[one + 12]);

	for (int n = 0; n < N; n++)
	{
		// loop 2 part a

		ba_a.val[0] = veorq_u32(ba_a.val[0], q_tmp.val[0]);
			//q_tmp.val[0] = vld1q_u32(&W[one + 16 +  0]);
		ba_a.val[1] = veorq_u32(ba_a.val[1], q_tmp.val[1]);
			//q_tmp.val[1] = vld1q_u32(&W[one + 16 +  4]);
		ba_a.val[2] = veorq_u32(ba_a.val[2], q_tmp.val[2]);
			//q_tmp.val[2] = vld1q_u32(&W[one + 16 +  8]);
		ba_a.val[3] = veorq_u32(ba_a.val[3], q_tmp.val[3]);

		q_tmp.val[0] = vld1q_u32(&W[one + 16 +  0]);
		q_tmp.val[1] = vld1q_u32(&W[one + 16 +  4]);
		q_tmp.val[2] = vld1q_u32(&W[one + 16 +  8]);
		q_tmp.val[3] = vld1q_u32(&W[one + 16 + 12]);

			ba_b.val[0] = veorq_u32(ba_b.val[0], q_tmp.val[0]);
			ba_b.val[1] = veorq_u32(ba_b.val[1], q_tmp.val[1]);
			//q_tmp.val[3] = vld1q_u32(&W[one + 16 + 12]);
			ba_b.val[2] = veorq_u32(ba_b.val[2], q_tmp.val[2]);
			ba_b.val[3] = veorq_u32(ba_b.val[3], q_tmp.val[3]);
// 		q_tmp.val[0] = vld1q_u32(&W[two +  0]);
				q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
				q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
// 		q_tmp.val[1] = vld1q_u32(&W[two +  4]);
				q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
				q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);
// 		q_tmp.val[2] = vld1q_u32(&W[two +  8]);
		ba_a = q_a;

// 		q_tmp.val[3] = vld1q_u32(&W[two + 12]);

// 		bb_a.val[0] = veorq_u32(bb_a.val[0], q_tmp.val[0]);
// 			q_tmp.val[0] = vld1q_u32(&W[two + 16 +  0]);
// 		bb_a.val[1] = veorq_u32(bb_a.val[1], q_tmp.val[1]);
// 			q_tmp.val[1] = vld1q_u32(&W[two + 16 +  4]);
// 		bb_a.val[2] = veorq_u32(bb_a.val[2], q_tmp.val[2]);
// 			q_tmp.val[2] = vld1q_u32(&W[two + 16 +  8]);
// 		bb_a.val[3] = veorq_u32(bb_a.val[3], q_tmp.val[3]);
// 			bb_b.val[0] = veorq_u32(bb_b.val[0], q_tmp.val[0]);
// 			q_tmp.val[3] = vld1q_u32(&W[two + 16 + 12]);
// 			bb_b.val[1] = veorq_u32(bb_b.val[1], q_tmp.val[1]);
// 		q_tmp.val[0] = vld1q_u32(&W[three +  0]);
// 			bb_b.val[2] = veorq_u32(bb_b.val[2], q_tmp.val[2]);
// 			bb_b.val[3] = veorq_u32(bb_b.val[3], q_tmp.val[3]);
// 		q_tmp.val[1] = vld1q_u32(&W[three +  4]);
// 				q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
// 				q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
// 		q_tmp.val[2] = vld1q_u32(&W[three +  8]);
// 				q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);
// 				q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);
// 		q_tmp.val[3] = vld1q_u32(&W[three + 12]);
// 		bb_a = q_b;

// 		bc_a.val[0] = veorq_u32(bc_a.val[0], q_tmp.val[0]);
// 			q_tmp.val[0] = vld1q_u32(&W[three + 16 +  0]);
// 		bc_a.val[1] = veorq_u32(bc_a.val[1], q_tmp.val[1]);
// 			q_tmp.val[1] = vld1q_u32(&W[three + 16 +  4]);
// 		bc_a.val[2] = veorq_u32(bc_a.val[2], q_tmp.val[2]);
// 			q_tmp.val[2] = vld1q_u32(&W[three + 16 +  8]);
// 		bc_a.val[3] = veorq_u32(bc_a.val[3], q_tmp.val[3]);
// 			bc_b.val[0] = veorq_u32(bc_b.val[0], q_tmp.val[0]);
// 			q_tmp.val[3] = vld1q_u32(&W[three + 16 + 12]);
// 			bc_b.val[1] = veorq_u32(bc_b.val[1], q_tmp.val[1]);
// 			bc_b.val[2] = veorq_u32(bc_b.val[2], q_tmp.val[2]);
// 			bc_b.val[3] = veorq_u32(bc_b.val[3], q_tmp.val[3]);
// 				q_c.val[0] = veorq_u32(bc_b.val[0], bc_a.val[0]);
// 				q_c.val[1] = veorq_u32(bc_b.val[1], bc_a.val[1]);
// 				q_c.val[2] = veorq_u32(bc_b.val[2], bc_a.val[2]);
// 				q_c.val[3] = veorq_u32(bc_b.val[3], bc_a.val[3]);
// 		bc_a = q_c;

		for (int i = 0; i < 4; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
 
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		q_a = ba_a;

// 		bb_a.val[0] = vaddq_u32(bb_a.val[0], q_b.val[0]);
// 		bb_a.val[1] = vaddq_u32(bb_a.val[1], q_b.val[1]);
// 		bb_a.val[2] = vaddq_u32(bb_a.val[2], q_b.val[2]);
// 		bb_a.val[3] = vaddq_u32(bb_a.val[3], q_b.val[3]);
// 		q_b = bb_a;

// 		bc_a.val[0] = vaddq_u32(bc_a.val[0], q_c.val[0]);
// 		bc_a.val[1] = vaddq_u32(bc_a.val[1], q_c.val[1]);
// 		bc_a.val[2] = vaddq_u32(bc_a.val[2], q_c.val[2]);
// 		bc_a.val[3] = vaddq_u32(bc_a.val[3], q_c.val[3]);
// 		q_c = bc_a;

		// loop 2 b

		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
		ba_b = q_a;

// 		q_b.val[0] = veorq_u32(bb_b.val[0], q_b.val[0]);
// 		q_b.val[1] = veorq_u32(bb_b.val[1], q_b.val[1]);
// 		q_b.val[2] = veorq_u32(bb_b.val[2], q_b.val[2]);
// 		q_b.val[3] = veorq_u32(bb_b.val[3], q_b.val[3]);
// 		bb_b = q_b;

// 		q_c.val[0] = veorq_u32(bc_b.val[0], q_c.val[0]);
// 		q_c.val[1] = veorq_u32(bc_b.val[1], q_c.val[1]);
// 		q_c.val[2] = veorq_u32(bc_b.val[2], q_c.val[2]);
// 		q_c.val[3] = veorq_u32(bc_b.val[3], q_c.val[3]);
// 		bc_b = q_c;

		for (int i = 0; i < 3; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}
		{
			//1
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			//2
			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);
			//3
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			//4
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			//5
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
// 			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
// 			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			//6
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
// 			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
// 			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);
			//7
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
// 			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
// 			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
// 			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
// 			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			//8
			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
// 			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
				ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
//					one =	32 * (3 * (ba_b.val[0][0] & (N - 1)) + 0); /* original code for 3ways*/
					one =	32 * (1 * (ba_b.val[0][0] & (N - 1)) + 0);
					__builtin_prefetch(&W[one + 0]);
					__builtin_prefetch(&W[one + 8]);
					__builtin_prefetch(&W[one + 16]);
					__builtin_prefetch(&W[one + 24]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
// 			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			
// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
// 			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
// 			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
// 			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
// 			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
// 				bb_b.val[0] = vaddq_u32(q_b.val[0], bb_b.val[0]);
//					two =	32 * (3 * (bb_b.val[0][0] & (N - 1)) + 1); /* original code for 3ways*/
// 					two =	32 * (2 * (bb_b.val[0][0] & (N - 1)) + 1);
// 					__builtin_prefetch(&W[two + 0]);
// 					__builtin_prefetch(&W[two + 8]);
// 					__builtin_prefetch(&W[two + 16]);
// 					__builtin_prefetch(&W[two + 24]);

// 			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
// 			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
// 			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
// 			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
// 				bc_b.val[0] = vaddq_u32(q_c.val[0], bc_b.val[0]);
// 					three = 32 * (3 * (bc_b.val[0][0] & (N - 1)) + 2);
// 					__builtin_prefetch(&W[three + 0]);
// 					__builtin_prefetch(&W[three + 8]);
// 					__builtin_prefetch(&W[three + 16]);
// 					__builtin_prefetch(&W[three + 24]);
		}

		q_tmp.val[0] = vld1q_u32(&W[one +  0]);
		q_tmp.val[1] = vld1q_u32(&W[one +  4]);
		q_tmp.val[2] = vld1q_u32(&W[one +  8]);
		q_tmp.val[3] = vld1q_u32(&W[one + 12]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);

// 		bb_b.val[1] = vaddq_u32(q_b.val[1], bb_b.val[1]);
// 		bb_b.val[2] = vaddq_u32(q_b.val[2], bb_b.val[2]);
// 		bb_b.val[3] = vaddq_u32(q_b.val[3], bb_b.val[3]);

// 		bc_b.val[1] = vaddq_u32(q_c.val[1], bc_b.val[1]);
// 		bc_b.val[2] = vaddq_u32(q_c.val[2], bc_b.val[2]);
// 		bc_b.val[3] = vaddq_u32(q_c.val[3], bc_b.val[3]);

	}

	vst1q_u32(&B[0],       ba_a.val[0]);
	vst1q_u32(&B[4],       ba_a.val[1]);
	vst1q_u32(&B[8],       ba_a.val[2]);
	vst1q_u32(&B[12],      ba_a.val[3]);
	vst1q_u32(&B[16 + 0],  ba_b.val[0]);
	vst1q_u32(&B[16 + 4],  ba_b.val[1]);
	vst1q_u32(&B[16 + 8],  ba_b.val[2]);
	vst1q_u32(&B[16 + 12], ba_b.val[3]);

// 	vst1q_u32(&B[32 + 0],  		bb_a.val[0]);
// 	vst1q_u32(&B[32 + 4],  		bb_a.val[1]);
// 	vst1q_u32(&B[32 + 8],  		bb_a.val[2]);
// 	vst1q_u32(&B[32 + 12], 		bb_a.val[3]);
// 	vst1q_u32(&B[32 + 16 + 0],  bb_b.val[0]);
// 	vst1q_u32(&B[32 + 16 + 4],  bb_b.val[1]);
// 	vst1q_u32(&B[32 + 16 + 8],  bb_b.val[2]);
// 	vst1q_u32(&B[32 + 16 + 12], bb_b.val[3]);

// 	vst1q_u32(&B[64 + 0],  		bc_a.val[0]);
// 	vst1q_u32(&B[64 + 4],  		bc_a.val[1]);
// 	vst1q_u32(&B[64 + 8],  		bc_a.val[2]);
// 	vst1q_u32(&B[64 + 12], 		bc_a.val[3]);
// 	vst1q_u32(&B[64 + 16 + 0],  bc_b.val[0]);
// 	vst1q_u32(&B[64 + 16 + 4],  bc_b.val[1]);
// 	vst1q_u32(&B[64 + 16 + 8],  bc_b.val[2]);
// 	vst1q_u32(&B[64 + 16 + 12], bc_b.val[3]);

	scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);
//	scrypt_shuffle(&B[0 + 32]);
//	scrypt_shuffle(&B[16 + 32]);
//	scrypt_shuffle(&B[0 + 64]);
//	scrypt_shuffle(&B[16 + 64]);
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
*/
// try prohibit loop unrolling loops for 2ways
#pragma GCC push_options
#pragma GCC optimize ("no-unroll-loops")
static inline void scrypt_core_2way(uint32_t B[32 * 2], uint32_t *__restrict__ V, uint32_t N)
{
	uint32_t* W __attribute__((__aligned__(16))) = __builtin_assume_aligned (V, 16);
/*
	scrypt_deinterleaved_shuffle(&B[0  + 0]);
	scrypt_deinterleaved_shuffle(&B[16 + 0]);
	scrypt_deinterleaved_shuffle(&B[0 + 32]);
	scrypt_deinterleaved_shuffle(&B[16 + 32]);
	//Used with vld4 to compensate for its interleave. See above.
*/
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

/*	printf("vld1q_u32\n"); // used to reverse engineer vld4/str4 interleaved load/stores
	printf("%d, %d, %d, %d,\n", ba_a.val[0][0], ba_a.val[0][1], ba_a.val[0][2], ba_a.val[0][3]);
	printf("%d, %d, %d, %d,\n", ba_a.val[1][0], ba_a.val[1][1], ba_a.val[1][2], ba_a.val[1][3]);
	printf("%d, %d, %d, %d,\n", ba_a.val[2][0], ba_a.val[2][1], ba_a.val[2][2], ba_a.val[2][3]);
	printf("%d, %d, %d, %d,\n\n", ba_a.val[3][0], ba_a.val[3][1], ba_a.val[3][2], ba_a.val[3][3]);
	printf("vld4q_u32\n");
	printf("%d, %d, %d, %d,\n", dd_a.val[0][0], dd_a.val[0][1], dd_a.val[0][2], dd_a.val[0][3]);
	printf("%d, %d, %d, %d,\n", dd_a.val[1][0], dd_a.val[1][1], dd_a.val[1][2], dd_a.val[1][3]);
	printf("%d, %d, %d, %d,\n", dd_a.val[2][0], dd_a.val[2][1], dd_a.val[2][2], dd_a.val[2][3]);
	printf("%d, %d, %d, %d,\n\n", dd_a.val[3][0], dd_a.val[3][1], dd_a.val[3][2], dd_a.val[3][3]);*/

	ba_b.val[0] = vld1q_u32(&B[(0 + 64 + 0) / 4]);
	ba_b.val[1] = vld1q_u32(&B[(0 + 64 + 16) / 4]);
	ba_b.val[2] = vld1q_u32(&B[(0 + 64 + 32) / 4]);
	ba_b.val[3] = vld1q_u32(&B[(0 + 64 + 48) / 4]);

	bb_a.val[0] = vld1q_u32(&B[(128 +  0) / 4]);
	bb_a.val[1] = vld1q_u32(&B[(128 + 16) / 4]);
	bb_a.val[2] = vld1q_u32(&B[(128 + 32) / 4]);
	bb_a.val[3] = vld1q_u32(&B[(128 + 48) / 4]);

	//ba_a = vld4q_u32(&B[( 0) / 4]); //experimented with alternative load
	//ba_b = vld4q_u32(&B[(0 + 64 + 0) / 4]); //experimented with alternative load
	//bb_a = vld4q_u32(&B[(128 +  0) / 4]); //experimented with alternative load
	//bb_b = vld4q_u32(&B[(128 + 64 + 0) / 4]); //experimented with alternative load

	bb_b.val[0] = vld1q_u32(&B[(128 + 64 + 0) / 4]);
	bb_b.val[1] = vld1q_u32(&B[(128 + 64 + 16) / 4]);
	bb_b.val[2] = vld1q_u32(&B[(128 + 64 + 32) / 4]);
	bb_b.val[3] = vld1q_u32(&B[(128 + 64 + 48) / 4]);
 
	//vst4q_u32(&V[( 0) / 4], ba_a); //experimented with alternative store
	//vst4q_u32(&V[(64) / 4], ba_b); //experimented with alternative store
	//vst4q_u32(&V[(128 +  0) / 4], bb_a); //experimented with alternative store
	//vst4q_u32(&V[(128 + 64) / 4], bb_b); //experimented with alternative store

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

	for (int n = 0; n < N; n++)
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
		vst1q_u32(&V[(32 + 16 + (0 * 4))], bb_b.val[0]);
		q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
		vst1q_u32(&V[(32 + 16 + (1 * 4))], bb_b.val[1]);
		q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
		vst1q_u32(&V[(32 + 16 + (2 * 4))], bb_b.val[2]);
		q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);	
		vst1q_u32(&V[(32 + 16 + (3 * 4))], bb_b.val[3]);
		q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);

		ba_a = q_a;
		bb_a = q_b;
		//increments scratchpad pointer
		V += 64;

		for (int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);	
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
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
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);;
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
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
			vst1q_u32(&V[      (i * 4) ], ba_a.val[i]);
			vst1q_u32(&V[(32 + (i * 4))], bb_a.val[i]);
		}*/
			//vst4q_u32(&V[      (0 * 4) ], ba_a); //experimented with alternative store
			//vst4q_u32(&V[(32 + (0 * 4))], bb_a); //experimented with alternative store

		// loop 1 part b
			vst1q_u32(&V[      (0 * 4) ], ba_a.val[0]);
		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
			vst1q_u32(&V[      (1 * 4) ], ba_a.val[1]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
			vst1q_u32(&V[      (2 * 4) ], ba_a.val[2]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
			vst1q_u32(&V[      (3 * 4) ], ba_a.val[3]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
			
			vst1q_u32(&V[(32 + (0 * 4))], bb_a.val[0]);
		q_b.val[0] = veorq_u32(bb_b.val[0], q_b.val[0]);
			vst1q_u32(&V[(32 + (1 * 4))], bb_a.val[1]);
		q_b.val[1] = veorq_u32(bb_b.val[1], q_b.val[1]);
			vst1q_u32(&V[(32 + (2 * 4))], bb_a.val[2]);
		q_b.val[2] = veorq_u32(bb_b.val[2], q_b.val[2]);
			vst1q_u32(&V[(32 + (3 * 4))], bb_a.val[3]);
		q_b.val[3] = veorq_u32(bb_b.val[3], q_b.val[3]);
		
		ba_b = q_a;		
		bb_b = q_b;

		for (int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);	
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
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
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
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
			//vst4q_u32(&V[(     16 + (0 * 4))], ba_b); //experimented with alternative store
			//vst4q_u32(&V[(32 + 16 + (0 * 4))], bb_b); //experimented with alternative store
	}

    // loop 2 *mix code to perhaps encourage dual issue
	uint32_t one =   32 * (2 * (ba_b.val[0][0] & (N - 1)) + 0);
	q_tmp.val[0] = vld1q_u32(&W[one +  0]);
	uint32_t two = bb_b.val[0][0];
	q_tmp.val[1] = vld1q_u32(&W[one +  4]);
	two = 32 * (2 * (bb_b.val[0][0] & (N - 1)) + 1);
	q_tmp.val[2] = vld1q_u32(&W[one +  8]);
	V = W;
	q_tmp.val[3] = vld1q_u32(&W[one + 12]);
	// q_tmp = vld4q_u32(&W[one +  0]); //experimented with alternative load

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
			q_tmp.val[3] = vld1q_u32(&W[one + 16 + 12]);
			// q_tmp = vld4q_u32(&W[one + 16 +  0]); //experimented with alternative load

			ba_b.val[0] = veorq_u32(ba_b.val[0], q_tmp.val[0]);
			ba_b.val[1] = veorq_u32(ba_b.val[1], q_tmp.val[1]);
			ba_b.val[2] = veorq_u32(ba_b.val[2], q_tmp.val[2]);
			ba_b.val[3] = veorq_u32(ba_b.val[3], q_tmp.val[3]);

		q_tmp.val[0] = vld1q_u32(&W[two +  0]);
				q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
				q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
		q_tmp.val[1] = vld1q_u32(&W[two +  4]);
				q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
				q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);
		q_tmp.val[2] = vld1q_u32(&W[two +  8]);

		q_tmp.val[3] = vld1q_u32(&W[two + 12]);
		// q_tmp = vld4q_u32(&W[two +  0]); //experimented with alternative load
		bb_a.val[0] = veorq_u32(bb_a.val[0], q_tmp.val[0]);
			q_tmp.val[0] = vld1q_u32(&W[two + 16 +  0]);
		bb_a.val[1] = veorq_u32(bb_a.val[1], q_tmp.val[1]);
			q_tmp.val[1] = vld1q_u32(&W[two + 16 +  4]);
		bb_a.val[2] = veorq_u32(bb_a.val[2], q_tmp.val[2]);
			q_tmp.val[2] = vld1q_u32(&W[two + 16 +  8]);
		bb_a.val[3] = veorq_u32(bb_a.val[3], q_tmp.val[3]);
			q_tmp.val[3] = vld1q_u32(&W[two + 16 + 12]);
			// q_tmp = vld4q_u32(&W[two + 16 +  4]); //experimented with alternative load

			bb_b.val[0] = veorq_u32(bb_b.val[0], q_tmp.val[0]);
			bb_b.val[1] = veorq_u32(bb_b.val[1], q_tmp.val[1]);
			bb_b.val[2] = veorq_u32(bb_b.val[2], q_tmp.val[2]);
			bb_b.val[3] = veorq_u32(bb_b.val[3], q_tmp.val[3]);
			q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
			q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
			q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);
			q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);

		ba_a = q_a;
		bb_a = q_b;

		for (int i = 0; i < 4; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
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
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
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

		for (int i = 0; i < 3; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_b.val[0] = veorq_u32(q_tmp.val[3], q_b.val[0]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);;

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
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
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_b.val[3] = veorq_u32(q_tmp.val[3], q_b.val[3]);
			//2
			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);
			//3
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			//4
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 14);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
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
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 25);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_b.val[1] = veorq_u32(q_tmp.val[3], q_b.val[1]);
			//6
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 23);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_b.val[2] = veorq_u32(q_tmp.val[3], q_b.val[2]);
			//7
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[3] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vsriq_n_u32(q_tmp.val[3], q_tmp.val[2], 19);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
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
					one =	32 * (2 * (ba_b.val[0][0] & (N - 1)) + 0);	
					two =	32 * (2 * (bb_b.val[0][0] & (N - 1)) + 1);
					__builtin_prefetch(&W[one + 0]);
					__builtin_prefetch(&W[one + 8]);
					__builtin_prefetch(&W[one + 16]);
					__builtin_prefetch(&W[one + 24]);
					__builtin_prefetch(&W[two + 0]);
					__builtin_prefetch(&W[two + 8]);
					__builtin_prefetch(&W[two + 16]);
					__builtin_prefetch(&W[two + 24]);

			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
		}

		//q_tmp = vld4q_u32(&W[one +  0]); //experimented with alternative load
		q_tmp.val[0] = vld1q_u32(&W[one +  0]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		q_tmp.val[1] = vld1q_u32(&W[one +  4]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);
		bb_b.val[1] = vaddq_u32(q_b.val[1], bb_b.val[1]);
		q_tmp.val[2] = vld1q_u32(&W[one +  8]);
		bb_b.val[2] = vaddq_u32(q_b.val[2], bb_b.val[2]);
		bb_b.val[3] = vaddq_u32(q_b.val[3], bb_b.val[3]);
		q_tmp.val[3] = vld1q_u32(&W[one + 12]);
	}

	vst1q_u32(&B[0],       ba_a.val[0]);
	vst1q_u32(&B[4],       ba_a.val[1]);
	vst1q_u32(&B[8],       ba_a.val[2]);
	vst1q_u32(&B[12],      ba_a.val[3]);
	// vst4q_u32(&B[0],       ba_a); //experimented with alternative store

	vst1q_u32(&B[16 + 0],  ba_b.val[0]);
	vst1q_u32(&B[16 + 4],  ba_b.val[1]);
	vst1q_u32(&B[16 + 8],  ba_b.val[2]);
	vst1q_u32(&B[16 + 12], ba_b.val[3]);
	// vst4q_u32(&B[16 + 0],  ba_b); //experimented with alternative store

	vst1q_u32(&B[32 + 0],  		bb_a.val[0]);
	vst1q_u32(&B[32 + 4],  		bb_a.val[1]);
	vst1q_u32(&B[32 + 8],  		bb_a.val[2]);
	vst1q_u32(&B[32 + 12], 		bb_a.val[3]);
	// vst4q_u32(&B[32 + 0],  bb_a); //experimented with alternative store

	vst1q_u32(&B[32 + 16 + 0],  bb_b.val[0]);
	vst1q_u32(&B[32 + 16 + 4],  bb_b.val[1]);
	vst1q_u32(&B[32 + 16 + 8],  bb_b.val[2]);
	vst1q_u32(&B[32 + 16 + 12], bb_b.val[3]);
	// vst4q_u32(&B[32 + 16 + 0],  bb_b); //experimented with alternative store

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

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16], uint32_t* V, uint32_t N)
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
static inline void xor_salsa8_prefetch(uint32_t B[16], const uint32_t Bx[16], uint32_t* V, uint32_t N)
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

static inline void scrypt_core(uint32_t *__restrict__ X, uint32_t *__restrict__ V, int N)
{
	int i;

	for (i = 0; i < N; i++) {
		newmemcpy(&V[i * 32], X, 128);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8_prefetch(&X[16], &X[0], V, N);
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
	uint32_t throughput = (forceThroughput == -1 ? scrypt_best_throughput() : forceThroughput);

	if (opt_ryzen_1x) {
		// force throughput to be 3 (aka AVX) instead of AVX2.
		throughput = 3;
	}

	uint32_t size = throughput * 32 * (N + 1) * sizeof(uint32_t);

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
		unsigned char* m_memory = (unsigned char*)(mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, 0, 0));
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
		return (unsigned char*)aligned_alloc(16,size); // malloc already seems to align pointer
		//return (unsigned char*)aligned_malloc(size, 16);
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

static void scrypt_1024_1_1_256(const uint32_t *__restrict__ input, uint32_t *__restrict__ output,
	uint32_t *__restrict__ midstate, unsigned char *__restrict__ scratchpad, int N)
{
	uint32_t tstate[8] __attribute__((__aligned__(16))), ostate[8] __attribute__((__aligned__(16)));
	uint32_t X[32] __attribute__((__aligned__(16)));
	uint32_t *V __attribute__((__aligned__(16)));
	
	V = (uint32_t *)(((uintptr_t)(__builtin_assume_aligned (scratchpad, 16)) + 63) & ~ (uintptr_t)(63));

	newmemcpy(tstate, midstate, 32);
	HMAC_SHA256_80_init_armv8_noinline(input, tstate, ostate);
	PBKDF2_SHA256_80_128_armv8(tstate, ostate, input, X);

	scrypt_core(X, V, N);

	PBKDF2_SHA256_128_32_armv8(tstate, ostate, X, output);
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

static void scrypt_1024_1_1_256_2way(const uint32_t *__restrict__ input,
	uint32_t *__restrict__ output, uint32_t *__restrict__ midstate, unsigned char *__restrict__ scratchpad, int N)
{
	uint32_t tstate[2 * 8] __attribute__((__aligned__(16))), ostate[2 * 8] __attribute__((__aligned__(16)));
	uint32_t X[2 * 32] __attribute__((__aligned__(16)));
	uint32_t *V __attribute__((__aligned__(16)));
	
	V = (uint32_t *)(((uintptr_t)(__builtin_assume_aligned (scratchpad, 16)) + 63) & ~ (uintptr_t)(63));

	newmemcpy(tstate +  0, midstate, 32);
	newmemcpy(tstate +  8, midstate, 32);
	HMAC_SHA256_80_init_armv8(input +  0, tstate +  0, ostate +  0);
	HMAC_SHA256_80_init_armv8(input + 20, tstate +  8, ostate +  8);
	PBKDF2_SHA256_80_128_armv8(tstate +  0, ostate +  0, input +  0, X +  0);
	PBKDF2_SHA256_80_128_armv8(tstate +  8, ostate +  8, input + 20, X + 32);

	scrypt_core_2way(X, V, N);

	PBKDF2_SHA256_128_32_armv8(tstate +  0, ostate +  0, X +  0, output +  0);
	PBKDF2_SHA256_128_32_armv8(tstate +  8, ostate +  8, X + 32, output +  8);
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
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t data[SCRYPT_MAX_WAYS * 20], hash[SCRYPT_MAX_WAYS * 8];
	uint32_t midstate[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[7];
	int throughput = scrypt_best_throughput();

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

	if (forceThroughput != -1)
	{
		throughput = forceThroughput;
	}

	for (i = 0; i < throughput; i++)
		newmemcpy(data + i * 20, pdata, 80);
	
	sha256_init_armv8(midstate);
	sha256_transform_armv8(midstate, data, 0);
	
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

	sha256_init_armv8(midstate);
	sha256_transform_armv8(midstate, input, 0);

	scrypt_1024_1_1_256((uint32_t*)input, (uint32_t*)output, midstate, scratchbuf, N);

	free(scratchbuf);
}
