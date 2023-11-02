#include "js_gen.h"
#include "js_log.h"
#include "js_bin.h"
#include "reg_srv.h"
#include "js_db.h"
#include "js_http.h"
#include "js_json.h"
#include "js_pki.h"

int regUser( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    JRegUserReq     sRegUserReq;
    JRegUserRsp     sRegUserRsp;
    JDB_User        sDBUser;
    int             nRefCode = -1;
    BIN             binRand = {0,0};
    char            *pRand = NULL;
    char            sRefCode[64];
    time_t          now_t = time(NULL);

    memset( &sRegUserReq, 0x00, sizeof(sRegUserReq));
    memset( &sRegUserRsp, 0x00, sizeof(sRegUserRsp));
    memset( &sDBUser, 0x00, sizeof(sDBUser));

    if( pReq == NULL ) return -1;

//    nRefCode = JS_DB_getSeq( db, "TB_USER" );
    nRefCode = JS_DB_getLastVal( db, "TB_USER" );
    if( nRefCode < 0 )
    {
        ret = -1;
        goto end;
    }

    sprintf( sRefCode, "%d", nRefCode );
    ret = JS_PKI_genRandom( 4, &binRand );
    ret = JS_BIN_encodeHex( &binRand, &pRand );

    ret = JS_JSON_decodeRegUserReq( pReq, &sRegUserReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to decode request[%d]\n", ret );
        ret = -1;
        goto end;
    }

    ret = JS_DB_setUser( &sDBUser,
                   -1,
                   now_t,
                   sRegUserReq.pName,
                   sRegUserReq.pSSN,
                   sRegUserReq.pEmail,
                   1,
                   sRefCode,
                   pRand );

    ret = JS_DB_addUser( db, &sDBUser );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to add user record:%d\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to add user record:%d", ret  );
        ret = -1;
        goto end;
    }

    JS_JSON_setRegUserRsp( &sRegUserRsp, "0000", "OK", sRefCode, pRand );
    JS_JSON_encodeRegUserRsp( &sRegUserRsp, ppRsp );

    JS_addAudit( db, JS_GEN_KIND_REG_SRV, JS_GEN_OP_REG_USER, NULL );

end :

    JS_JSON_resetRegUserReq( &sRegUserReq );
    JS_JSON_resetRegUserRsp( &sRegUserRsp );
    JS_DB_resetUser( &sDBUser );
    if( pRand ) JS_free( pRand );
    JS_BIN_reset( &binRand );

    return ret;
}

int certRevoke( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    JRegCertRevokeReq   sRevokeReq;
    JRegCertRevokeRsp   sRevokeRsp;
    JDB_Cert            sDBCert;
    JDB_Revoked         sDBRevoked;
    int     nReason = -1;

    memset( &sRevokeReq, 0x00, sizeof(sRevokeReq));
    memset( &sRevokeRsp, 0x00, sizeof(sRevokeRsp));
    memset( &sDBCert, 0x00, sizeof(sDBCert));
    memset( &sDBRevoked, 0x00, sizeof(sDBRevoked));

    JS_JSON_decodeRegCertRevokeReq( pReq, &sRevokeReq );

    if( strcasecmp( sRevokeReq.pTarget, "name" ) == 0 )
    {
        JDB_User    sDBUser;
        memset( &sDBUser, 0x00, sizeof(sDBUser));

        ret = JS_DB_getUserByName( db, sRevokeReq.pValue, &sDBUser );
        if( ret < 1 )
        {
            fprintf( stderr, "There is no user[%s]\n", sRevokeReq.pValue );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "There is no user[%s]", sRevokeReq.pValue );
            ret = -1;
            goto end;
        }

        ret = JS_DB_getLatestCertByUserNum( db, sDBUser.nNum, &sDBCert );
        if( ret < 1 )
        {
            fprintf( stderr, "There is no cert[%s]\n", sDBUser.pName );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "There is no cert[%s]", sDBUser.pName );
            ret = -1;
            goto end;
        }

        JS_DB_resetUser( &sDBUser );
    }
    else if( strcasecmp( sRevokeReq.pTarget, "serial" ) == 0 )
    {
        ret = JS_DB_getCertBySerial( db, sRevokeReq.pValue, &sDBCert );
        if( ret < 1 )
        {
            fprintf( stderr, "There is no cert[%s]\n", sRevokeReq.pValue );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "There is no cert[%s]", sRevokeReq.pValue );
            ret = -1;
            goto end;
        }
    }
    else
    {
        ret = -1;
        goto end;
    }

    nReason = atoi( sRevokeReq.pReason );
    JS_DB_setRevoked( &sDBRevoked, -1, sDBCert.nIssuerNum, sDBCert.nNum, sDBCert.pSerial, time(NULL), nReason, sDBCert.pCRLDP );
    JS_DB_addRevoked( db, &sDBRevoked );
    JS_DB_changeCertStatus( db, sDBCert.nNum, 2 );

    JS_JSON_setRegRsp( &sRevokeRsp, "0000", "OK" );
    JS_JSON_encodeRegRsp( &sRevokeRsp, ppRsp );

    JS_addAudit( db, JS_GEN_KIND_REG_SRV, JS_GEN_OP_REVOKE_CERT, NULL );

    ret = 0;

end :
    JS_JSON_resetRegCertRevokeReq( &sRevokeReq );
    JS_JSON_resetRegRsp( &sRevokeRsp );
    JS_DB_resetCert( &sDBCert );
    JS_DB_resetRevoked( &sDBRevoked );

    return ret;
}

int certStatus( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    JRegCertStatusReq       sStatusReq;
    JRegCertStatusRsp       sStatusRsp;
    JDB_Cert                sDBCert;
    JDB_Revoked             sDBRevoked;

    memset( &sStatusReq, 0x00, sizeof(sStatusReq));
    memset( &sStatusRsp, 0x00, sizeof(sStatusRsp));
    memset( &sDBCert, 0x00, sizeof(sDBCert));
    memset( &sDBRevoked, 0x00, sizeof(sDBRevoked));

    JS_JSON_decodeRegCertStatusReq( pReq, &sStatusReq );

    if( strcasecmp( sStatusReq.pTarget, "name" ) == 0 )
    {
        JDB_User    sDBUser;
        memset( &sDBUser, 0x00, sizeof(sDBUser));

        ret = JS_DB_getUserByName( db, sStatusReq.pValue, &sDBUser );
        if( ret < 1 )
        {
            fprintf( stderr, "There is no user[%s]\n", sStatusReq.pValue );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "There is no user[%s]", sStatusReq.pValue );
            ret = -1;
            goto end;
        }

        ret = JS_DB_getLatestCertByUserNum( db, sDBUser.nNum, &sDBCert );
        if( ret < 1 )
        {
            fprintf( stderr, "There is no cert[%s]\n", sDBUser.pName );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "There is no cert[%s]", sDBUser.pName );
            ret = -1;
            goto end;
        }

        JS_DB_resetUser( &sDBUser );
    }
    else if( strcasecmp( sStatusReq.pTarget, "serial" ) == 0 )
    {
         ret = JS_DB_getCertBySerial( db, sStatusReq.pValue, &sDBCert );
         if( ret < 1 )
         {
            fprintf( stderr, "There is no cert[%s]\n", sStatusReq.pValue );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "There is no cert[%s]", sStatusReq.pValue );
            ret = -1;
            goto end;
         }
    }

    if( sDBCert.nStatus == 0 )
    {
        JS_JSON_setRegCertStatusRsp( &sStatusRsp, "0000", "OK", "Valid", NULL, NULL, sDBCert.pSerial );
    }
    else
    {
        JS_DB_getRevokedByCertNum( db, sDBCert.nNum, &sDBRevoked );
        char sReason[128];
        char sRevokeDate[128];

        sprintf( sReason, "%d", sDBRevoked.nReason );
        sprintf( sRevokeDate, "%d", sDBRevoked.nRevokedDate );

        JS_JSON_setRegCertStatusRsp( &sStatusRsp, "0000", "OK", "Revoked", sReason, sRevokeDate, sDBCert.pSerial );
    }

    JS_JSON_encodeRegCertStatusRsp( &sStatusRsp, ppRsp );
    ret = 0;

end :
    JS_JSON_resetRegCertStatusReq( &sStatusReq );
    JS_JSON_resetRegCertStatusRsp( &sStatusRsp );
    JS_DB_resetCert( &sDBCert );
    JS_DB_resetRevoked( &sDBRevoked );

    return ret;
}

int procReg( sqlite3 *db, const char *pReq, int nType, const char *pPath, char **ppRsp )
{
    int ret = 0;

    if( strcasecmp( pPath, "/user" ) == 0 )
        ret = regUser( db, pReq, ppRsp );
    else if( strcasecmp( pPath, "/certrevoke" ) == 0 )
        ret = certRevoke( db, pReq, ppRsp );
    else if( strcasecmp( pPath, "/certstatus" ) == 0 )
        ret = certStatus( db, pReq, ppRsp );


    return ret;
}
