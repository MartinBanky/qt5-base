QT = core network

CONFIG += console
CONFIG -= app_bundle

TARGET = crlcreator
TEMPLATE = app

SOURCES += \
    main.cpp

RESOURCES += \
    crlcreator.qrc

LIBS += -lcrypto

target.path = $$[QT_INSTALL_EXAMPLES]/network/certificatecreator
INSTALLS += target
