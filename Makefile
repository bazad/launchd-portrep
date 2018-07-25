TARGET = launchd-portrep

DEBUG      ?= 0
ARCH       ?= x86_64
SDK        ?= macosx

SYSROOT  := $(shell xcrun --sdk $(SDK) --show-sdk-path)
ifeq ($(SYSROOT),)
$(error Could not find SDK "$(SDK)")
endif
CLANG    := $(shell xcrun --sdk $(SDK) --find clang)
CC       := $(CLANG) -isysroot $(SYSROOT) -arch $(ARCH)

CFLAGS = -O2 -Wall -Werror -Ithreadexec/include
LDFLAGS = -Lthreadexec/lib -lthreadexec

ifneq ($(DEBUG),0)
DEFINES += -DDEBUG=$(DEBUG)
endif

FRAMEWORKS =

SOURCES = launchd_portrep.c \
	  exploit.c \
	  log.c \
	  main.c

HEADERS = launchd_portrep.h \
	  exploit.h \
	  log.h

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(DEFINES) $(LDFLAGS) -o $@ $(SOURCES)

clean:
	rm -f -- $(TARGET)
