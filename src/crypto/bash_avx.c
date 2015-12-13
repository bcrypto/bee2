/*
*******************************************************************************
\file bash_avx.c
\brief STB 34.101.77 (bash): hashing algorithms, AVX implementation
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2015.12.13
\version 2015.12.13
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/u64.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bash.h"

#if defined(_MSC_VER)
#include <intrin.h>
#include <immintrin.h>

#define u256 __m256i

#define LOADW(s) _mm256_loadu_si256( (__m256i const *)(s) )
#define STOREW(s,w) _mm256_storeu_si256( (__m256i *)(s), (w) )

#define I(W,n) W.m256i_u64[n]

#define S4(w0,w1,w2,w3) _mm256_set_epi64x(w3,w2,w1,w0)
#define X4(w1,w2) _mm256_xor_si256(w1,w2)
#define O4(w1,w2) _mm256_or_si256(w1,w2)
#define A4(w1,w2) _mm256_and_si256(w1,w2)

#define ROLV(a, i0, i1, i2, i3) \
	X4(_mm256_sllv_epi64(a, S4(i0, i1, i2, i3)), \
		_mm256_srlv_epi64(a, S4(64-i0, 64-i1, 64-i2, 64-i3)))

#define PERM4X64(w,i) _mm256_permute4x64_epi64(w,i)
#define PERM2X128(w0,w1,i) _mm256_permute2x128_si256(w0,w1,i)

#define R4(m0,m1,m2,m3, W) ROLV(W, m0,m1,m2,m3)

#define ONE _mm256_set1_epi64x( 0xffffffffffffffffull )

#endif


/* S0,S1,S2,S3 S4,S5,S6,S7 -> S6,S3,S0,S5 S2,S7,S4,S1
    w0=S0,S1,S2,S3 w1=S4,S5,S6,S7
 -> u0=S0,S3,S2,S1 u1=S4,S7,S6,S5
 -> t0=S0,S3,S6,S5 t1=S4,S7,S2,S1
 -> s0=S6,S3,S0,S5 s1=S2,S7,S4,S1
*/
#define P01_1(W0,W1, U0,U1,T0,T1) \
    do { \
        U0 = PERM4X64( W0, 0x6c ); \
        U1 = PERM4X64( W1, 0x6c ); \
        T0 = PERM2X128( U0, U1, 0x30 ); \
        T1 = PERM2X128( U0, U1, 0x12 ); \
    } while (0)
#define P01_2(T0,T1, S0,S1) \
    do { \
        S0 = PERM4X64( T0, 0xc6 ); \
        S1 = PERM4X64( T1, 0xc6 ); \
    } while (0)

/* S8,S9,S10,S11 S12,S13,S14,S15 -> S15,S10,S9,S12 S11,S14,S13,S8
    w2=S8,S9,S10,S11 w3=S12,S13,S14,S15
 -> u2=S8,S11,S10,S9 u3=S12,S15,S14,S13
 -> t2=S8,S11,S14,S13 t3=S12,S15,S10,S9
 -> s2=S15,S10,S9,S12 s3=S11,S14,S13,S8
*/
#define P23_1(W2,W3, U2,U3,T2,T3) \
    do { \
        U2 = PERM4X64( W2, 0x6c ); \
        U3 = PERM4X64( W3, 0x6c ); \
        T2 = PERM2X128( U2, U3, 0x30 ); \
        T3 = PERM2X128( U2, U3, 0x12 ); \
    } while (0)
#define P23_2(T2,T3, S2,S3) \
    do { \
        S2 = PERM4X64( T3, 0x39 ); \
        S3 = PERM4X64( T2, 0x39 ); \
    } while (0)

/* S16,S17,S18,S19 S20,S21,S22,S23 -> S17,S16,S19,S18 S21,S20,S23,S22
    w4=S16,S17,S18,S19 w5=S20,S21,S22,S23
 -> s4=S17,S16,S19,S18 s5=S21,S20,S23,S22
*/
#define P45(W4,W5, S4,S5) \
    do { \
        S4 = PERM4X64( W4, 0xb1 ); \
        S5 = PERM4X64( W5, 0xb1 ); \
    } while (0)

#define bashP(W0,W1,W2,W3,W4,W5 ,T0,T1,T2,T3, U0,U1,U2,U3) \
    do { \
        P23_1(W2,W3, U2,U3,T2,T3); \
        P45(W4,W5, W2,W3); \
        P01_1(W0,W1, U0,U1,T0,T1); \
        P23_2(T2,T3, W0,W1); \
        P01_2(T0,T1, W4,W5); \
    } while(0)



#define bashS(m10,m11,m12,m13, n10,n11,n12,n13, m20,m21,m22,m23, n20,n21,n22,n23, W0,W1,W2 ,S0,S1,S2,T0,T1,T2,U0,U1,U2) \
    do { \
        S2 = R4(m10,m11,m12,m13, W0); \
        U0 = X4(W0, X4(W1, W2)); \
        S1 = X4(W1, R4(n10,n11,n12,n13, U0)); \
        U2 = X4(X4(W2, R4(m20,m21,m22,m23, W2)), R4(n20,n21,n22,n23, S1)); \
        U1 = X4(S1, S2); \
        S0 = X4(U2, ONE); \
        T1 = O4(U0, U2); \
        T2 = A4(U0, U1); \
        T0 = O4(S0, U1); \
        W1 = X4(U1, T1); \
        W2 = X4(U2, T2); \
        W0 = X4(U0, T0); \
    } while (0)


#define f(x) ((x*7) % 64)
#define m1 8
#define n1 53
#define m2 14
#define n2 1

#define m10 m1
#define m11 f(m10)
#define m12 f(m11)
#define m13 f(m12)
#define m14 f(m13)
#define m15 f(m14)
#define m16 f(m15)
#define m17 f(m16)

#define n10 n1
#define n11 f(n10)
#define n12 f(n11)
#define n13 f(n12)
#define n14 f(n13)
#define n15 f(n14)
#define n16 f(n15)
#define n17 f(n16)

#define m20 m2
#define m21 f(m20)
#define m22 f(m21)
#define m23 f(m22)
#define m24 f(m23)
#define m25 f(m24)
#define m26 f(m25)
#define m27 f(m26)

#define n20 n2
#define n21 f(n20)
#define n22 f(n21)
#define n23 f(n22)
#define n24 f(n23)
#define n25 f(n24)
#define n26 f(n25)
#define n27 f(n26)

#define bashR(W0,W1,W2,W3,W4,W5,C ,S0,S1,S2,T0,T1,T2,U0,U1,U2) \
    do { \
        bashS(m10,m11,m12,m13, n10,n11,n12,n13, m20,m21,m22,m23, n20,n21,n22,n23, W0,W2,W4 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashS(m14,m15,m16,m17, n14,n15,n16,n17, m24,m25,m26,m27, n24,n25,n26,n27, W1,W3,W5 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashP(W0,W1,W2,W3,W4,W5 ,T0,T1,U0,U1, W4,W5,T0,T1); \
        I( W5, 3 ) ^= C; \
    } while (0)

#define C0 0x3bf5080ac8ba94b1ull
#define C1 0xc1d1659c1bbd92f6ull
#define C2 0x60e8b2ce0ddec97bull
#define C3 0xec5fb8fe790fbc13ull
#define C4 0xaa043de6436706a7ull
#define C5 0x8929ff6a5e535bfdull
#define C6 0x98bf1e2c50c97550ull
#define C7 0x4c5f8f162864baa8ull
#define C8 0x262fc78b14325d54ull
#define C9 0x1317e3c58a192eaaull
#define C10 0x98bf1e2c50c9755ull
#define C11 0xd8ee19681d669304ull
#define C12 0x6c770cb40eb34982ull
#define C13 0x363b865a0759a4c1ull
#define C14 0xc73622b47c4c0aceull
#define C15 0x639b115a3e260567ull
#define C16 0xede6693460f3da1dull
#define C17 0xaad8d5034f9935a0ull
#define C18 0x556c6a81a7cc9ad0ull
#define C19 0x2ab63540d3e64d68ull
#define C20 0x155b1aa069f326b4ull
#define C21 0xaad8d5034f9935aull
#define C22 0x556c6a81a7cc9adull
#define C23 0xde8082cd72debc78ull

#define bashF(W0,W1,W2,W3,W4,W5 ,S0,S1,S2,T0,T1,T2,U0,U1,U2) \
    do { \
        bashR(W0,W1,W2,W3,W4,W5,C0 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C1 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C2 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C3 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C4 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C5 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C6 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C7 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C8 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C9 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C10 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C11 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C12 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C13 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C14 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C15 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C16 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C17 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C18 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C19 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C20 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C21 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C22 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
        bashR(W0,W1,W2,W3,W4,W5,C23 ,S0,S1,S2,T0,T1,T2,U0,U1,U2); \
    } while (0)

void bashF0_AVX( u64 S[24] )
{
    u256 S0,S1,S2,T0,T1,T2,U0,U1,U2;
    u256 W0 = LOADW( S + 0 );
    u256 W1 = LOADW( S + 4 );
    u256 W2 = LOADW( S + 8 );
    u256 W3 = LOADW( S + 12 );
    u256 W4 = LOADW( S + 16 );
    u256 W5 = LOADW( S + 20 );

    bashF(W0,W1,W2,W3,W4,W5 ,S0,S1,S2,T0,T1,T2,U0,U1,U2);

    STOREW( S + 0, W0 );
    STOREW( S + 4, W1 );
    STOREW( S + 8, W2 );
    STOREW( S + 12, W3 );
    STOREW( S + 16, W4 );
    STOREW( S + 20, W5 );
}

