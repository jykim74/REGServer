#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"
#include "js_cfg.h"

#include "reg_srv.h"

const char* g_dbPath = NULL;
static char g_sConfigPath[1024];
static char g_sBuildInfo[1024];

SSL_CTX     *g_pSSLCTX = NULL;

int g_nVerbose = 0;
JEnvList    *g_pEnvList = NULL;

const char *getBuildInfo()
{
    sprintf( g_sBuildInfo, "Version: %s Build Date : %s %s",
             JS_REG_SRV_VERSION, __DATE__, __TIME__ );

    return g_sBuildInfo;
}

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
    JNameValList    *pParamList = NULL;

    const char *pRspMethod = NULL;

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

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {
        pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else
    {
        ret = procReg( db, pReq, nType, pPath, &pRsp );
        if( ret != 0 )
        {
            pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_INTERNAL_SERVER_ERROR );
            goto end;
        }

        pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");

    ret = JS_HTTP_send( pThInfo->nSockFd, pRspMethod, pRspHeaderList, pRsp );
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
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );

    if( db ) JS_DB_close( db );

    return 0;
}

int REG_SSL_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    int nType = -1;
    char *pPath = NULL;

    char    *pReq = NULL;
    char    *pRsp = NULL;

    char    *pMethInfo = NULL;
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    SSL *pSSL = NULL;

    const char *pRspMethod = NULL;

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to accept SSL(%d)\n", ret );
        goto end;
    }

    ret = JS_HTTPS_recv( pSSL, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {
        pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else
    {
        ret = procReg( db, pReq, nType, pPath, &pRsp );
        if( ret != 0 )
        {
            pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_INTERNAL_SERVER_ERROR );
            goto end;
        }

        pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");

    ret = JS_HTTPS_send( pSSL, pRspMethod, pRspHeaderList, pRsp );
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
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );

    if( pSSL ) JS_SSL_clear( pSSL );
    if( db ) JS_DB_close( db );

    return 0;
}

int initServer()
{
    int ret = 0;
    const char *value = NULL;

    ret = JS_CFG_readConfig( g_sConfigPath, &g_pEnvList );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_CA_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CA_CERT_PATH'\n" );
        exit(0);
    }

    BIN binSSLCA = {0,0};
    BIN binSSLCert = {0,0};
    BIN binSSLPri = {0,0};

    ret = JS_BIN_fileRead( value, &binSSLCA );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to read ssl ca cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileRead( value, &binSSLCert );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to read ssl cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_PRIKEY_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_PRIKEY_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileRead( value, &binSSLPri );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to read ssl private key(%s)\n", value );
        exit(0);
    }

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &binSSLPri, &binSSLCert );
    JS_SSL_setClientCACert( g_pSSLCTX, &binSSLCA );


    value = JS_CFG_getValue( g_pEnvList, "DB_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'DB_PATH'\n" );
        exit(0);
    }

    g_dbPath = JS_strdup( value );

    printf( "CA RegServer Init OK\n" );

    JS_BIN_reset( &binSSLCA );
    JS_BIN_reset( &binSSLCert );
    JS_BIN_reset( &binSSLPri );

    return 0;
}

void printUsage()
{
    printf( "JS OCSP Server ( %s )\n", getBuildInfo() );
    printf( "[Options]\n" );
    printf( "-v         : Verbose on(%d)\n", g_nVerbose );
    printf( "-c config : set config file(%s)\n", g_sConfigPath );
    printf( "-h         : Print this message\n" );
}

int main( int argc, char *argv[] )
{
    int nOpt = 0;

    sprintf( g_sConfigPath, "%s", "../ca_reg_srv.cfg" );

    while(( nOpt = getopt( argc, argv, "c:vh")) != -1 )
    {
        switch( nOpt ) {
        case 'h':
            printUsage();
            return 0;

        case 'v':
            g_nVerbose = 1;
            break;

        case 'c':
            sprintf( g_sConfigPath, "%s", optarg );
            break;
        }
    }

    initServer();

    JS_THD_logInit( "./log", "reg", 2 );
    JS_THD_registerService( "JS_REG", NULL, 9030, 4, NULL, REG_Service );
    JS_THD_registerService( "JS_REG_SSL", NULL, 9130, 4, NULL, REG_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
