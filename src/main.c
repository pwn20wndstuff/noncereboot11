#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "unlocknvram.h"
#include "nonce.h"
#include "kutils.h"
#include "debug.h"
#include "patchfinder64.h"
#include "parameters.h"
#include "kc_parameters.h"
#include "kernel_memory.h"
#include "offsets.h"
#include "kernel_call.h"

void printusage(void) {
    printf("-h this message\n");
    printf("-q stay quiet\n");
    printf("-v be more verbose\n");
    printf("-V even more verbose\n");
    printf("-U skip unlocking nvram\n");
    printf("-L DONT DO THIS skip locking nvram back -- stays unlocked till reboot\n");
    printf("-g print generator (when combined with s/d prints twice)\n");
    printf("-s [val] set generator (WARNING: NO VALIDATION PERFORMED)\n");
    printf("-d delete generator (conflicts with s)\n");
}

int gethelper(int setdel) {
    char *gen = getgen();
    if (gen != NULL) {
        printf("%s\n", gen);
        free(gen);
    } else {
        printf("nonce_not_set\n");
        if (!setdel) {
            return 1;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int get, set, del;
    char *gentoset = NULL;
    get = set = del = 0;

    int nounlock = 0;
    int nolockback = 0;

    char c;
    while ((c = getopt(argc, argv, "hqvVUrgds:L")) != -1) {
        switch (c) {
            case 'h':
                printusage();
                return EXIT_SUCCESS;

            case 'q':
                loglevel = lvlNONE;
                break;
            case 'v':
                loglevel = lvlINFO;
                break;
            case 'V':
                loglevel = lvlDEBUG;
                break;

            case 'U':
                nounlock = 1;
                break;

            case 'g':
                get = 1;
                break;

            case 'd':
                del = 1;
                break;

            case 's':
                set = 1;
                gentoset = optarg;
                break;

            case 'L':
                nolockback = 1;
                printf("ARE YOU SURE? YOU HAVE 3 SECONDS TO CANCEL\n");
                sleep(3);
                break;

            case '?':
                ERRORLOG("Unknown option `-%c'", optopt);
                break;

            default:
                abort();
        }
    }

    if (!(get || set || del)) {
        ERRORLOG("please specify g or s or d flag");
        printusage();
        return EXIT_FAILURE;
    }

    if (set && del) {
        ERRORLOG("cant set and delete nonce at once");
        return EXIT_FAILURE;
    }

    if (init_tfpzero()) {
        ERRORLOG("failed to init tfpzero");
        return EXIT_FAILURE;
    }
    
    if (init_offsets()) {
        ERRORLOG("failed to init offsets");
        return EXIT_FAILURE;
    }
    
#if __arm64e__
    parameters_init();
    kernel_task_port = tfpzero;
    current_task = rk64(task_self_addr() + OFF_IPC_PORT__IP_KOBJECT);
    kernel_task = rk64(GETOFFSET(kernel_task));
    kernel_call_init();
#endif

    int retval = EXIT_SUCCESS;

    if (!nounlock) {
        if (unlocknvram()) {
            ERRORLOG("failed to unlock nvram, but trying anyway");
        }
    }

    if (get) {
        retval = gethelper(set || del);
        DEBUGLOG("gethelper: %d", retval);
    }

    if (del) {
        retval = delgen();
        DEBUGLOG("delgen: %d", retval);
    }

    if (set) {
        retval = setgen(gentoset);
        DEBUGLOG("setgen: %d", retval);
    }

    if (get && (set || del)) {
        retval = gethelper(set || del);
        DEBUGLOG("gethelper: %d", retval);
    }

    if (!nounlock && !nolockback) {
       if (locknvram()) {
            ERRORLOG("failed to lock nvram, can't do much about it");
        }
    }
    
#if __arm64e__
    kernel_call_init();
#endif

    return retval;
}
