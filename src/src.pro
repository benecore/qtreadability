TARGET = qtreadability
QT += network
TEMPLATE = lib
DESTDIR = ../lib
CONFIG += create_prl
!macx: CONFIG += static_and_shared


VER_MAJ = 0
VER_MIN = 0
VER_PAT = 1

OBJECTS_DIR = tmp
MOC_DIR = tmp

INCLUDEPATH += .

SOURCES += qtreadability.cpp \
    qtreadabilityauth.cpp

HEADERS += qtreadability.h \
    qtreadability_export.h \
    qtreadabilityauth.h \
    qtreadabilityauth_p.h \
    qtreadability_p.h

DEFINES += QTREADABILITY

symbian {
    MMP_RULES += EXPORTUNFROZEN
    TARGET.UID3 = 0xE071A027
    TARGET.CAPABILITY = 
    TARGET.EPOCALLOWDLLDATA = 1
    addFiles.sources = QtReadability.dll
    addFiles.path = !:/sys/bin
    DEPLOYMENT += addFiles
}

unix:!symbian {
    maemo5 {
        target.path = /opt/usr/lib
    } else {
        target.path = /usr/lib
    }
    INSTALLS += target
}


CONFIG(debug_and_release) {
    build_pass:CONFIG(debug, debug|release) {
        unix: TARGET = $$join(TARGET,,,_debug)
        else: TARGET = $$join(TARGET,,,d)
    }
}
