/*
*******************************************************************************
\file be-test.c
\brief Tests for broadcast encryption (be)
\project bee2/test
\author 
\created 2016.03.20
\version 2016.03.20
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/crypto/be.h>

#include <assert.h>
//#define BREAK break
#define BREAK assert(0)

/*
*******************************************************************************
Самотестирование

-#    .
*******************************************************************************
*/

bool_t beTest()
{
    bool_t ok = FALSE;
    u8 const h = 4; // 2^h = user count
    u32 const H = (u32)1 << h;
    u16 const m = 256;

    // server's key
    u8 S[32]; // m/8
    // server's precomputed users keys
    beUserKey *akeys = NULL;
    u32 count;

    // all users keys
    beUserKey **ukeys = NULL;
    u32 *ucount = NULL;
    u32 u;

    // revoked set - just int
    u32 R; // max h=5: 2^5=32
    u32 r;

    // X_1
    u8 *BX;
    u32 bxsize;
    // Х_2, X_3, …, X_{d+2}
    u8 *EX;
    u32 exsize;

    // session key
    u8 K[32]; // m/8
    // initialization vector
    u8 T[16];
    // sensitive data
    u8 M[5];
    u32 msize = sizeof(M);
    // encrypted data
    u8 *AY;
    u32 aysize;

    // decryption objects
    // some internal parameters: d, E, DK
    u32 d;
    u32 E;
    u8 DK[32]; // m/8
    err_t err;
    // session data decryption key
    u8 KK[32];
    // header mac
    u8 mac[8];
    // decrypted message
    u8 *MM;
    u32 mmsize;

    do
    {
        // gen server key
        memSet( S, 0xaa, sizeof( S ) );

        // gen users keys
        if( ERR_OK != beGenUsersKeys( h, m, S, NULL, &count ) )
            BREAK;
        if( NULL == (akeys = (beUserKey *) memAlloc( count * sizeof(beUserKey) ) ) )
            BREAK;
        if( ERR_OK != beGenUsersKeys( h, m, S, akeys, &count ) )
            BREAK;

        if( NULL == (ukeys = (beUserKey **)memAlloc( H * sizeof( beUserKey * ) )) )
            BREAK;
        if( NULL == (ucount = (u32 *)memAlloc( H * sizeof( u32 ) )) )
            BREAK;
        // get user keys for each user
        for( u = 1; u <= H; ++u )
        {
            if( ERR_OK != beGetUserKeys( h, m, u, akeys, NULL, &ucount[u-1] ) )
                BREAK;
            if( NULL == (ukeys[u-1] = (beUserKey *)memAlloc( ucount[u-1] * sizeof( beUserKey ) )) )
                BREAK;
            if( ERR_OK != beGetUserKeys( h, m, u, akeys, ukeys[u-1], &ucount[u-1] ) )
                BREAK;
        }
        if( !(H < u) )
            BREAK;

        // for each possible revocation; all users can't be revoked, so (H - 1)
        for( R = 0; R < (H - 1); ++R )
        {
            // encryption step
            {
                // set of revoked users -> begin of the header
                if( ERR_OK != beFormBMsgX( h, (u8 *)&R, &r, NULL, &bxsize ) )
                    BREAK;
                if( NULL == (BX = (u8 *)memAlloc( bxsize )) )
                    BREAK;
                if( ERR_OK != beFormBMsgX( h, (u8 *)&R, &r, BX, &bxsize ) )
                    BREAK;

                // gen session key
                memSet( K, 0xbb, sizeof( K ) );

                // for session key -> the rest of the header
                if( ERR_OK != beFormEMsgX( h, m, S, K, r, BX, NULL, &exsize ) )
                    BREAK;
                if( NULL == (EX = (u8 *)memAlloc( exsize )) )
                    BREAK;
                if( ERR_OK != beFormEMsgX( h, m, S, K, r, BX, EX, &exsize ) )
                    BREAK;

                // gen iv
                memSet( T, 0xdd, sizeof( T ) );
                // get data
                memSet( M, 0xee, sizeof( M ) );

                // encrypt data
                if( ERR_OK != beFormAMsgY( m, K, T, M, msize, NULL, &aysize ) )
                    BREAK;
                if( NULL == (AY = (u8 *)memAlloc( aysize )) )
                    BREAK;
                if( ERR_OK != beFormAMsgY( m, K, T, M, msize, AY, &aysize ) )
                    BREAK;
            }

            // transmit BX[bxsize], EX[exsize], AY[aysize]

            // decryption step
            {
                // for each user
                for( u = 1; u <= H; ++u )
                {
                    if( ERR_OK != (err = beAnalyzBMsgX( h, m, u, ukeys[u-1], BX, bxsize, &d, &E, DK )) )
                    {
                        if( ERR_REVOKED != err )
                            BREAK;
                        // user revoked from header
                        if( ((u8 *) &R)[ (u-1)/8 ] & (1 << ((u-1) % 8)) )
                            // ok, user's actually revoked
                            ;
                        else
                            // user's not revoked
                            BREAK;
                    }
                    else
                    {
                        // user not revoked from header
                        if( ((u8 *)&R)[(u - 1) / 8] & (1 << ((u - 1) % 8)) )
                            // user's actually revoked
                            BREAK;
                        else
                            // ok, user's not revoked
                            ;

                        if( ERR_OK != beAnalyzEMsgX( m, EX, exsize, d, E, DK, KK, mac ) )
                            BREAK;
                        if( ERR_OK != (err = beCheckMsgX( h, m, BX, bxsize, KK, mac )) )
                            BREAK;
                        // check for err == ERR_BAD_MAC

                        if( ERR_OK != beAnalyzAMsgY( m, KK, AY, aysize, NULL, &mmsize ) )
                            BREAK;
                        if( NULL == (MM = (u8 *)memAlloc( mmsize )) )
                            BREAK;
                        if( ERR_OK != beAnalyzAMsgY( m, KK, AY, aysize, MM, &mmsize ) )
                            BREAK;

                        if( mmsize != sizeof( M )
                            || 0 != memcmp( M, MM, mmsize ) )
                            BREAK;

                        memFree( MM ); MM = NULL;
                    }
                }
                if( u <= H )
                    BREAK;
            }

            memFree( AY ); AY = NULL;
            memFree( EX ); EX = NULL;
            memFree( BX ); BX = NULL;
        }
        if( R != (H-1) )
            BREAK;

        ok = TRUE;
    } while (0);

    memFree( MM ); MM = NULL;
    memFree( AY ); AY = NULL;
    memFree( EX ); EX = NULL;
    memFree( BX ); BX = NULL;
    if( ukeys )
        for( u = 1; u <= H; ++u )
            memFree( ukeys[u-1] );
    memFree( ukeys ); ukeys = NULL;
    memFree( ucount ); ucount = NULL;
    memFree( akeys ); akeys = NULL;
    return ok;
}
