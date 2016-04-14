TARGET = eme2
TEMPLATE = lib
CONFIG -= qt
CONFIG += staticlib

DEFINES += __KERNEL__

ARCH=x86
SRC_PROJECT_PATH = $$PWD
LINUX_HEADERS_PATH = /usr/src/linux-headers-$$system(uname -r)

INCLUDEPATH += $$SRC_PROJECT_PATH/include
INCLUDEPATH += $$LINUX_HEADERS_PATH/include
INCLUDEPATH += $$LINUX_HEADERS_PATH/arch/$$ARCH/include

buildmod.commands = make -C $$LINUX_HEADERS_PATH M=$$SRC_PROJECT_PATH modules
cleanmod.commands = make -C $$LINUX_HEADERS_PATH M=$$SRC_PROJECT_PATH clean
QMAKE_EXTRA_TARGETS += buildmod cleanmod

SOURCES += \
    eme2.c \
    eme2_test.c

DISTFILES += \
    Makefile \
    README.md \
    LICENSE

HEADERS += \
    eme2_tv.h \
    eme2.h \
    eme2_test.h \
    bufwalk.h

