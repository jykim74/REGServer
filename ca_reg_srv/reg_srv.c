#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "js_gen.h"
#include "js_log.h"
#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"
#include "js_cfg.h"

#include "reg_srv.h"

int     g_nConfigDB = 0;
const char* g_dbPath = NULL;
static char g_sConfigPath[1024];
static char g_sBuildInfo[1024];

SSL_CTX     *g_pSSLCTX = NULL;
int     g_nPort = JS_REG_PORT;
int     g_nSSLPort = JS_REG_SSL_PORT;
int     g_nLogLevel = JS_LOG_LEVEL_INFO;


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
        LE( "fail to open db file(%s)", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recv( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        LE( "fail to receive message(%d)", ret );
        goto end;
    }

    LV( "RecvLen : %d", pReq ? strlen(pReq) : 0 );

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
            LE( "fail procReg(%d)", ret );
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
        LE( "fail to send message(%d)", ret );
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
        LE( "fail to open db file(%s)", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );
    if( ret != 0 )
    {
        LE( "fail to accept SSL(%d)", ret );
        goto end;
    }

    ret = JS_HTTPS_recv( pSSL, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        LE( "fail to receive message(%d)", ret );
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
        LE( "fail to send message(%d)", ret );
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

int initServer( sqlite3* db)
{
    int ret = 0;
    const char *value = NULL;

    value = JS_CFG_getValue( g_pEnvList, "LOG_LEVEL" );
    if( value ) g_nLogLevel = atoi( value );

    JS_LOG_setLevel( g_nLogLevel );

    value = JS_CFG_getValue( g_pEnvList, "LOG_PATH" );
    if( value )
        JS_LOG_open( value, "REG", JS_LOG_TYPE_DAILY );
    else
        JS_LOG_open( "log", "REG", JS_LOG_TYPE_DAILY );

    BIN binSSLCA = {0,0};
    BIN binSSLCert = {0,0};
    BIN binSSLPri = {0,0};

    value = JS_CFG_getValue( g_pEnvList, "SSL_CA_CERT_PATH" );
    if( value == NULL )
    {
        LE( "You have to set 'SSL_CA_CERT_PATH'" );
        return -1;
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCA );
    if( ret <= 0 )
    {
        LE( "fail to read ssl ca cert(%s)\n", value );
        return -1;
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_CERT_PATH" );
    if( value == NULL )
    {
        LE( "You have to set 'SSL_CERT_PATH'" );
        return -1;
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCert );
    if( ret <= 0 )
    {
        LE( "fail to read ssl cert(%s)", value );
        return -1;
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_PRIKEY_PATH" );
    if( value == NULL )
    {
        LE( "You have to set 'SSL_PRIKEY_PATH'" );
        return -1;
    }

    ret = JS_BIN_fileReadBER( value, &binSSLPri );
    if( ret <= 0 )
    {
        LE( "fail to read ssl private key(%s)", value );
        return -1;
    }

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &binSSLPri, &binSSLCert );
    JS_SSL_setClientCACert( g_pSSLCTX, &binSSLCA );


    if( g_dbPath == NULL && g_nConfigDB == 0 )
    {
        value = JS_CFG_getValue( g_pEnvList, "DB_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'DB_PATH'" );
            return -1;
        }

        g_dbPath = JS_strdup( value );
        if( JS_UTIL_isFileExist( g_dbPath ) == 0 )
        {
            LE( "The data file is no exist[%s]", g_dbPath );
            return -1;
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "REG_PORT" );
    if( value ) g_nPort = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "REG_SSL_PORT" );
    if( value ) g_nSSLPort = atoi( value );

    LI( "CA RegServer Init OK [Port:%d SSL:%d]", g_nPort, g_nSSLPort );

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
    printf( "-d dbfile  : Use DB config(%d)\n", g_nConfigDB );
    printf( "-h         : Print this message\n" );
}

#if !defined WIN32 && defined USE_PRC
static int MainProcessInit()
{
    return 0;
}

static int MainProcessTerm()
{
    return 0;
}

static int ChildProcessInit()
{
    return 0;
}

static int ChildProcessTerm()
{
    return 0;
}
#endif

int main( int argc, char *argv[] )
{
    int ret = 0;
    int nOpt = 0;
    sqlite3* db = NULL;

    sprintf( g_sConfigPath, "%s", "../ca_reg_srv.cfg" );

    while(( nOpt = getopt( argc, argv, "c:d:vh")) != -1 )
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

        case 'd' :
            g_dbPath = JS_strdup( optarg );
            g_nConfigDB = 1;
            break;
        }
    }

    if( g_nConfigDB == 1 )
    {
        JDB_ConfigList *pConfigList = NULL;

        if( JS_UTIL_isFileExist( g_dbPath ) == 0 )
        {
            fprintf( stderr, "The data file is no exist[%s]\n", g_dbPath );
            exit(0);
        }

        db = JS_DB_open( g_dbPath );
        if( db == NULL )
        {
            fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
            exit(0);
        }

        ret = JS_DB_getConfigListByKind( db, JS_GEN_KIND_REG_SRV, &pConfigList );

        ret = JS_CFG_readConfigFromDB( pConfigList, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
            exit(0);
        }


        if( pConfigList ) JS_DB_resetConfigList( &pConfigList );
    }
    else
    {
        ret = JS_CFG_readConfig( g_sConfigPath, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
            exit(0);
        }
    }

    ret = initServer( db );
    if( ret != 0 )
    {
        LE( "fail to initialize server: %d", ret );
        exit( 0 );
    }

    if( g_nConfigDB == 1 )
    {
        if( db ) JS_DB_close( db );
    }

#if !defined WIN32 && defined USE_PRC
    JProcInit sProcInit;

    memset( &sProcInit, 0x00, sizeof(JProcInit));

    sProcInit.nCreateNum = 1;
    sProcInit.ParentInitFunction = MainProcessInit;
    sProcInit.ParemtTermFunction = MainProcessTerm;
    sProcInit.ChidInitFunction = ChildProcessInit;
    sProcInit.ChildTermFunction = ChildProcessTerm;

    JS_PRC_initRegister( &sProcInit );
    JS_PRC_register( "JS_REG", NULL, g_nPort, 4, REG_Service );
    JS_PRC_register( "JS_REG_SSL", NULL, g_nSSLPort, 4, REG_SSL_Service );
    JS_PRC_registerAdmin( NULL, g_nPort + 10 );

    JS_PRC_start();
    JS_PRC_detach();
#else
    JS_THD_logInit( "./log", "reg", 2 );
    JS_THD_registerService( "JS_REG", NULL, g_nPort, 4, REG_Service );
    JS_THD_registerService( "JS_REG_SSL", NULL, g_nSSLPort, 4, REG_SSL_Service );
    JS_THD_registerAdmin( NULL, g_nPort + 10 );
    JS_THD_serviceStartAll();
#endif

    return 0;
}
