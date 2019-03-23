DEBUG=0
THEOS=theos
ARCHS=arm64 arm64e
GO_EASY_ON_ME=1

include $(THEOS)/makefiles/common.mk

TOOL_NAME = nonceutil
$(TOOL_NAME)_FILES = src/debug.c src/kutils.c src/main.c src/nonce.c src/offsets.c src/unlocknvram.c patchfinder64/patchfinder64.c src/kernel_call/kc_parameters.c src/kernel_call/kernel_alloc.c src/kernel_call/kernel_call.c src/kernel_call/kernel_memory.c src/kernel_call/kernel_slide.c src/kernel_call/log.c src/kernel_call/pac.c src/kernel_call/parameters.c src/kernel_call/platform_match.c src/kernel_call/platform.c src/kernel_call/user_client.c
$(TOOL_NAME)_CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused-label -I./src -I./headers -I./patchfinder64 -I./src/kernel_call
$(TOOL_NAME)_FRAMEWORKS = CoreFoundation IOKit
$(TOOL_NAME)_CODESIGN_TOOL = ldid
$(TOOL_NAME)_CODESIGN_FLAGS = -Sent.plist
include $(THEOS_MAKE_PATH)/tool.mk
