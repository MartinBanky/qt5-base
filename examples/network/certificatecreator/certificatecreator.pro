QT = core network

CONFIG += console
CONFIG -= app_bundle

TARGET = certificatecreator
TEMPLATE = app

HEADERS += \
    certificatecreator.h

SOURCES += \
    main.cpp \
    certificatecreator.cpp

LIBS += -lcrypto

target.path = $$[QT_INSTALL_EXAMPLES]/network/certificatecreator
INSTALLS += target
