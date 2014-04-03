#-------------------------------------------------
#
# Project created by QtCreator 2014-04-03T08:32:32
#
#-------------------------------------------------

QT       += core network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = example
CONFIG   += console
CONFIG   -= app_bundle
DESTDIR = $$PWD/BIN
TEMPLATE = app


SOURCES += main.cpp \
    test.cpp

HEADERS += \
    test.h

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../lib/ -lqtreadability0
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../lib/ -lqtreadabilityd0
else:unix: LIBS += -L$$OUT_PWD/../lib/ -lqtreadability0

INCLUDEPATH += $$PWD/../src
DEPENDPATH += $$PWD/../src


