QT = core network

CONFIG += console
CONFIG -= app_bundle

TARGET = sslclient
TEMPLATE = app

HEADERS += \
    sslclient.h

SOURCES += \
    main.cpp \
    sslclient.cpp

RESOURCES += \
    sslclient.qrc

target.path = $$[QT_INSTALL_EXAMPLES]/network/sslclient
INSTALLS += target
