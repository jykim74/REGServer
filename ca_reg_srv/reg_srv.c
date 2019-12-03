#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"

#include "reg_srv.h"

const char* g_dbPath = "/Users/jykim/work/CAMan/ca.db";

int REG_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    int nType = -1;
    char *pPath = NULL;

    char    *pReq = NULL;
    char    *pRsp = NULL;

    char    *pMethInfo = NULL;
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recv( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath );

    ret = procReg( db, pReq, nType, pPath, &pRsp );
    if( ret != 0 )
    {
        goto end;
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");

    ret = JS_HTTP_send( pThInfo->nSockFd, JS_HTTP_OK, pRspHeaderList, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        goto end;
    }
    /* send response body */
end:
    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );

    if( pPath ) JS_free( pPath );

    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    if( db ) JS_DB_close( db );

    return 0;
}

int REG_SSL_Service( JThreadInfo *pThInfo )
{
    return 0;
}

int main( int argc, char *argv[] )
{
    JS_THD_logInit( "./log", "reg", 2 );
    JS_THD_registerService( "JS_REG", NULL, 9030, 4, NULL, REG_Service );
    JS_THD_registerService( "JS_REG_SSL", NULL, 9130, 4, NULL, REG_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
