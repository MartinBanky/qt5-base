# OpenSSL support; compile in QSslSocket.
qtConfig(ssl) {
    HEADERS += ssl/qasn1element_p.h \
               ssl/qssl.h \
               ssl/qssl_p.h \
               ssl/qsslcertificate.h \
               ssl/qsslcertificate_p.h \
               ssl/qsslconfiguration.h \
               ssl/qsslconfiguration_p.h \
               ssl/qsslcipher.h \
               ssl/qsslcipher_p.h \
               ssl/qssldiffiehellmanparameters.h \
               ssl/qssldiffiehellmanparameters_p.h \
               ssl/qsslellipticcurve.h \
               ssl/qsslerror.h \
               ssl/qsslkey.h \
               ssl/qsslkey_p.h \
               ssl/qsslsocket.h \
               ssl/qsslsocket_p.h \
               ssl/qsslpresharedkeyauthenticator.h \
               ssl/qsslpresharedkeyauthenticator_p.h \
               ssl/qsslcertificateextension.h \
               ssl/qsslcertificateextension_p.h \
               ssl/qsslcertificaterevocationlist.h \
               ssl/qsslcertificaterevocationlist_p.h \
               ssl/qsslrevokedcertificate.h \
               ssl/qsslrevokedcertificate_p.h
    SOURCES += ssl/qasn1element.cpp \
               ssl/qssl.cpp \
               ssl/qsslcertificate.cpp \
               ssl/qsslconfiguration.cpp \
               ssl/qsslcipher.cpp \
               ssl/qssldiffiehellmanparameters.cpp \
               ssl/qsslellipticcurve.cpp \
               ssl/qsslkey_p.cpp \
               ssl/qsslerror.cpp \
               ssl/qsslsocket.cpp \
               ssl/qsslpresharedkeyauthenticator.cpp \
               ssl/qsslcertificateextension.cpp \
               ssl/qsslcertificaterevocationlist.cpp \
               ssl/qsslrevokedcertificate.cpp

    winrt {
        HEADERS += ssl/qsslsocket_winrt_p.h
        SOURCES += ssl/qsslcertificate_qt.cpp \
                   ssl/qsslcertificate_winrt.cpp \
                   ssl/qssldiffiehellmanparameters_dummy.cpp \
                   ssl/qsslkey_qt.cpp \
                   ssl/qsslkey_winrt.cpp \
                   ssl/qsslsocket_winrt.cpp \
                   ssl/qsslellipticcurve_dummy.cpp
    }

    qtConfig(securetransport) {
        HEADERS += ssl/qsslsocket_mac_p.h
        SOURCES += ssl/qsslcertificate_qt.cpp \
                   ssl/qssldiffiehellmanparameters_dummy.cpp \
                   ssl/qsslkey_qt.cpp \
                   ssl/qsslkey_mac.cpp \
                   ssl/qsslsocket_mac_shared.cpp \
                   ssl/qsslsocket_mac.cpp \
                   ssl/qsslellipticcurve_dummy.cpp
    }

    qtConfig(openssl) {
        HEADERS += ssl/qsslcontext_openssl_p.h \
                   ssl/qsslsocket_openssl_p.h \
                   ssl/qsslsocket_openssl_symbols_p.h
        SOURCES += ssl/qsslcertificate_openssl.cpp \
                   ssl/qsslcontext_openssl.cpp \
                   ssl/qssldiffiehellmanparameters_openssl.cpp \
                   ssl/qsslellipticcurve_openssl.cpp \
                   ssl/qsslkey_openssl.cpp \
                   ssl/qsslsocket_openssl.cpp \
                   ssl/qsslsocket_openssl_symbols.cpp \
                   ssl/qsslcertificaterevocationlist_openssl.cpp

        darwin:SOURCES += ssl/qsslsocket_mac_shared.cpp

        android: SOURCES += ssl/qsslsocket_openssl_android.cpp

        # Add optional SSL libs
        # Static linking of OpenSSL with msvc:
        #   - Binaries http://slproweb.com/products/Win32OpenSSL.html
        #   - also needs -lUser32 -lAdvapi32 -lGdi32 -lCrypt32
        #   - libs in <OPENSSL_DIR>\lib\VC\static
        #   - configure: -openssl -openssl-linked -I <OPENSSL_DIR>\include -L <OPENSSL_DIR>\lib\VC\static OPENSSL_LIBS="-lUser32 -lAdvapi32 -lGdi32" OPENSSL_LIBS_DEBUG="-lssleay32MDd -llibeay32MDd" OPENSSL_LIBS_RELEASE="-lssleay32MD -llibeay32MD"

        qtConfig(openssl-linked): \
            QMAKE_USE_FOR_PRIVATE += openssl
        else: \
            QMAKE_USE_FOR_PRIVATE += openssl/nolink
        win32: LIBS_PRIVATE += -lcrypt32
    }
}
