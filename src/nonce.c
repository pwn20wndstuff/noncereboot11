#include "nonce.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <IOKit.h>
#include <CoreFoundation/CoreFoundation.h>

#define kIONVRAMDeletePropertyKey   "IONVRAM-DELETE-PROPERTY"
#define kIONVRAMForceSyncNowPropertyKey "IONVRAM-FORCESYNCNOW-PROPERTY"

#define nonceKey                "com.apple.System.boot-nonce"

#include "debug.h"

// thx PhoenixNonce

CFMutableDictionaryRef makedict(const char *key, const char *val) {
    CFStringRef cfkey = CFStringCreateWithCStringNoCopy(NULL, key, kCFStringEncodingUTF8, kCFAllocatorNull);
    CFStringRef cfval = CFStringCreateWithCStringNoCopy(NULL, val, kCFStringEncodingUTF8, kCFAllocatorNull);

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if(!cfkey || !dict || !cfval) {
        ERRORLOG("failed to alloc cf objects {'%s': '%s'}", key, val);
        return NULL;
    } else {
        DEBUGLOG("made dict {'%s': '%s'}", key, val);
    }
    CFDictionarySetValue(dict, cfkey, cfval);

    CFRelease(cfkey);
    CFRelease(cfval);
    return dict;
}

int applydict(CFMutableDictionaryRef dict) {
    int ret = 1;

    io_service_t nvram = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    if(!MACH_PORT_VALID(nvram)) {
        ERRORLOG("Failed to get IODTNVRAM service");
    } else {
        kern_return_t kret = IORegistryEntrySetCFProperties(nvram, dict);
        DEBUGLOG("IORegistryEntrySetCFProperties: 0x%x (%s)\n", kret, mach_error_string(kret));
        if(kret == KERN_SUCCESS) {
            ret = 0;
        }
    }

    return ret;
}

char* getval(const char *key) {
    // IORegistryEntryCreateCFProperty seems to fail, btw

    char buf[1024];
    unsigned int length = sizeof(buf);
    kern_return_t err;

    io_service_t nvram = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    if(!MACH_PORT_VALID(nvram)) {
        ERRORLOG("Failed to get IODTNVRAM service");
        return NULL;
    }

    err = IORegistryEntryGetProperty(nvram, key, (void*)buf, &length);
    DEBUGLOG("IORegistryEntryGetProperty(%s) == 0x%x (%s)\n", key, err, mach_error_string(err));
    if (err != KERN_SUCCESS) {
        return NULL;
    }
    
    buf[length] = '\0';
    return strdup(buf);
}

int makenapply(const char *key, const char *val) {
    int ret = 1;

    CFMutableDictionaryRef dict = makedict(key, val);
    if(!dict) {
        ERRORLOG("failed to make cf dict\n");
        return ret;
    }

    ret = applydict(dict);

    if (ret) {
        ERRORLOG("applydict failed\n");
    }

    CFRelease(dict);
    return ret;
}

int setgen(const char *gen) {
    int ret = 0;

    ret = makenapply(kIONVRAMDeletePropertyKey, nonceKey);

    // set even if delete failed
    ret = makenapply(nonceKey, gen);
    ret = ret || makenapply(kIONVRAMForceSyncNowPropertyKey, nonceKey);

    return ret;
}

char* getgen(void) {
    return getval(nonceKey);
}

int delgen(void) {
    return makenapply(kIONVRAMDeletePropertyKey, nonceKey);
}
