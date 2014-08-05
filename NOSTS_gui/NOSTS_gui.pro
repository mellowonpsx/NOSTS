#-------------------------------------------------
#
# Project created by QtCreator 2014-04-24T16:31:47
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = NOSTS_gui
TEMPLATE = app

SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui

QT += network

SOURCES += \
    ../NOSTS/nostsclientserver.cpp \
    ../NOSTS/encdec.cpp

#open ssl library
LIBS += -lssl

# QtCrypto linkage
CONFIG += crypto
INCLUDEPATH += /usr/include/QtCrypto/
LIBS += -L/usr/lib/x86_64-linux-gnu -lqca
#LIBS += -L/usr/lib -lgmp #unused
LIBS += -lcrypto
LIBS += -lssl
#LIBS += -pthread
#QMAKE_CXXFLAGS += -std=c++11

HEADERS += \
    ../NOSTS/nostsclientserver.h \
    ../NOSTS/encdec.h \
