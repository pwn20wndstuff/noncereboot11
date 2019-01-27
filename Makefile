DEBUG=0
THEOS=theos
ARCHS=arm64
GO_EASY_ON_ME=1

include $(THEOS)/makefiles/common.mk

TOOL_NAME = nonceutil
$(TOOL_NAME)_FILES = $(wildcard src/*.c) patchfinder64/patchfinder64.c
$(TOOL_NAME)_CFLAGS += -Wno-unused-variable -Wno-unused-function -I./headers -I./patchfinder64
$(TOOL_NAME)_FRAMEWORKS = CoreFoundation IOKit
$(TOOL_NAME)_CODESIGN_TOOL = ldid
$(TOOL_NAME)_CODESIGN_FLAGS = -Sent.plist
include $(THEOS_MAKE_PATH)/tool.mk
