QT = core network

CONFIG += console
CONFIG -= app_bundle

TARGET = sslserver
TEMPLATE = app

HEADERS += \
    sniserver.h \
    sslserver.h \

SOURCES += \
    main.cpp \
    sniserver.cpp \
    sslserver.cpp \

RESOURCES += \
    sslserver.qrc

target.path = $$[QT_INSTALL_EXAMPLES]/network/sslserver
INSTALLS += target
