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

    memset( &sRegUserReq, 0x00, sizeof(sRegUserReq));
    memset( &sRegUserRsp, 0x00, sizeof(sRegUserRsp));
    memset( &sDBUser, 0x00, sizeof(sDBUser));

    if( pReq == NULL ) return -1;

    nRefCode = JS_DB_getSeq( db, "TB_USER" );
    if( nRefCode < 0 )
    {
        ret = -1;
        goto end;
    }

    sprintf( sRefCode, "%d", nRefCode );
    ret = JS_PKI_genRandom( 4, &binRand );
    ret = JS_BIN_encodeHex( &binRand, &pRand );

    ret = JS_JSON_decodeRegUserReq( pReq, &sRegUserReq );

    ret = JS_DB_setUser( &sDBUser,
                   -1,
                   sRegUserReq.pName,
                   sRegUserReq.pSSN,
                   sRegUserReq.pEmail,
                   -1,
                   0,
                   sRefCode,
                   pRand );

    ret = JS_DB_addUser( db, &sDBUser );

    JS_JSON_setRegUserRsp( &sRegUserRsp, "0000", "OK", sRefCode, pRand );
    JS_JSON_encodeRegUserRsp( &sRegUserRsp, ppRsp );


end :

    JS_JSON_resetRegUserReq( &sRegUserReq );
    JS_JSON_resetRegUserRsp( &sRegUserRsp );
    JS_DB_resetUser( &sDBUser );
    if( pRand ) JS_free( pRand );
    JS_BIN_reset( &binRand );

    return ret;
}

int revokeCert( sqlite3 *db, const char *pReq, char **ppRsp )
{
    return 0;
}

int getCertStatus( sqlite3 *db, const char *pReq, char **ppRsp )
{
    return 0;
}

int procReg( sqlite3 *db, const char *pReq, int nType, const char *pPath, char **ppRsp )
{
    int ret = 0;

    if( nType == JS_HTTP_METHOD_POST )
    {
        if( strcasecmp( pPath, "/user" ) == 0 )
            ret = regUser( db, pReq, ppRsp );
        else if( strcasecmp( pPath, "/revoke" ) == 0 )
            ret = revokeCert( db, pReq, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_GET )
    {
        if( strcasecmp( pPath, "/certstatus" ) == 0 )
            ret = getCertStatus( db, pReq, ppRsp );
    }

    return ret;
}
