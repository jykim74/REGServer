TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.c \
        reg_proc.c \
        reg_srv.c

HEADERS += \
    reg_srv.h


INCLUDEPATH += "../../PKILib"

DEFINES += OPENSSL_V3
OPENSSL_NAME = "openssl3"
#OPENSSL_NAME = "cmpossl"

mac {
    INCLUDEPATH += "../../PKILib/lib/mac/debug/"$${OPENSSL_NAME}"/include"
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/debug/"$${OPENSSL_NAME}"/lib" -lcrypto -lssl
    LIBS += -L"/usr/local/lib" -lltdl
    LIBS += -lsqlite3
}

win32 {
    contains(QT_ARCH, i386) {
        message( "ca_reg_srv 32bit" )
        Debug {
            INCLUDEPATH += "../../PKILib/lib/win32/debug/"$${OPENSSL_NAME}"/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win32/debug/"$${OPENSSL_NAME}"/lib" -lcrypto -lssl
        } else {
            INCLUDEPATH += "../../PKILib/lib/win32/"$${OPENSSL_NAME}"/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win32/"$${OPENSSL_NAME}"/lib" -lcrypto -lssl
        }

        INCLUDEPATH += "C:\msys64\mingw32\include"
        LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lsqlite3
    } else {
        message( "ca_reg_srv 64bit" )
        Debug {
            INCLUDEPATH += "../../PKILib/lib/win64/debug/"$${OPENSSL_NAME}"/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug/debug" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win64/debug/"$${OPENSSL_NAME}"/lib64" -lcrypto -lssl
        } else {
            INCLUDEPATH += "../../PKILib/lib/win64/"$${OPENSSL_NAME}"/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release/release" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win64/"$${OPENSSL_NAME}"/lib64" -lcrypto -lssl
        }

        INCLUDEPATH += "C:\msys64\mingw64\include"
        LIBS += -L"C:\msys64\mingw64\lib" -lltdl -lsqlite3
    }
}

DISTFILES += \
    ../ca_reg_srv.cfg
