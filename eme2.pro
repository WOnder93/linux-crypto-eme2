TARGET = eme2
TEMPLATE = lib
CONFIG -= qt
CONFIG += staticlib

DEFINES += __KERNEL__

ARCH=x86
SRC_PROJECT_PATH = $$PWD
LINUX_VERSION = $$system(uname -r)
LINUX_HEADERS_PATH = /lib/modules/$$LINUX_VERSION/build

INCLUDEPATH += $$SRC_PROJECT_PATH/include
INCLUDEPATH += $$LINUX_HEADERS_PATH/include
INCLUDEPATH += $$LINUX_HEADERS_PATH/arch/$$ARCH/include

buildmod.commands = make -C $$LINUX_HEADERS_PATH M=$$SRC_PROJECT_PATH modules
cleanmod.commands = make -C $$LINUX_HEADERS_PATH M=$$SRC_PROJECT_PATH clean
QMAKE_EXTRA_TARGETS += buildmod cleanmod

SOURCES += \
    blockwalk.c \
    eme2.c \
    eme2_test.c

DISTFILES += \
    Makefile \
    README.md \
    LICENSE

HEADERS += \
    blockwalk.h \
    eme2_tv.h \
    eme2.h

