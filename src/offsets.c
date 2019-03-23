#include <CoreFoundation/CoreFoundation.h>

#define OFF_TASK__ITK_SPACE (kCFCoreFoundationVersionNumber >= 1535.12 ? 0x300 : 0x308)
#if __arm64e__
#define OFF_TASK__BSD_INFO 0x368
#else
#define OFF_TASK__BSD_INFO (kCFCoreFoundationVersionNumber >= 1535.12 ? 0x358 : 0x368)
#endif

#define OFF_IPC_PORT__IP_KOBJECT 0x68

#define OFF_IPC_SPACE__IS_TABLE 0x20

#define SIZ_IPC_ENTRY_T 0x18

#define OFF_PROC__P_PID (kCFCoreFoundationVersionNumber >= 1535.12 ? 0x60 : 0x10)
#define OFF_PROC__P_LIST 0x8
#define OFF_PROC__TASK (kCFCoreFoundationVersionNumber >= 1535.12 ? 0x10 : 0x18)
