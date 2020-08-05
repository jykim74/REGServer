#ifndef REG_SRV_H
#define REG_SRV_H

#include "sqlite3.h"
#include "js_bin.h"

#define     JS_REG_SRV_VERSION          "0.9.1"

int procReg( sqlite3 *db, const char *pReq, int nType, const char *pPath, char **ppRsp );

#endif // REG_SRV_H
