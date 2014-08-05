QT += network
QT -= gui

CONFIG   += console
CONFIG   -= app_bundle
TEMPLATE = app

TARGET = nosts
#TARGET = nosts_menu_version

SOURCES += \
    main.cpp \
    nostsclientserver.cpp \
    encdec.cpp

#open ssl library
LIBS += -lssl

# QtCrypto linkage
CONFIG += crypto
INCLUDEPATH += /usr/include/QtCrypto/
LIBS += -L$$PWD/usr/lib/x86_64-linux-gnu -lqca
#LIBS += -L$$PWD/usr/lib -lgmp
LIBS += -lcrypto
LIBS += -lssl
LIBS += -pthread

HEADERS += \
    nostsclientserver.h \
    encdec.h \
