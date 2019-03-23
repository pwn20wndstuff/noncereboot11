#pragma once

#include <mach/mach.h>
#include <inttypes.h>
#include <sys/types.h>

#define SETOFFSET(offset, val) (offs.offset = val)
#define GETOFFSET(offset) offs.offset

typedef struct {
    uint64_t kernel_task;
    uint64_t paciza_pointer__l2tp_domain_module_start;
    uint64_t paciza_pointer__l2tp_domain_module_stop;
    uint64_t l2tp_domain_inited;
    uint64_t sysctl__net_ppp_l2tp;
    uint64_t sysctl_unregister_oid;
    uint64_t mov_x0_x4__br_x5;
    uint64_t mov_x9_x0__br_x1;
    uint64_t mov_x10_x3__br_x6;
    uint64_t kernel_forge_pacia_gadget;
    uint64_t kernel_forge_pacda_gadget;
    uint64_t IOUserClient__vtable;
    uint64_t IORegistryEntry__getRegistryEntryID;
} offsets_t;

extern offsets_t offs;

extern mach_port_t tfpzero;
extern uint64_t kernel_base;
extern uint64_t kernel_slide;

kern_return_t init_tfpzero(void);
kern_return_t init_kernel_base(void);
kern_return_t init_offsets(void);

size_t rkbuffer(uint64_t where, void *p, size_t size);
uint32_t rk32(uint64_t where);
uint64_t rk64(uint64_t where);

size_t wkbuffer(uint64_t where, const void *p, size_t size);
void wk32(uint64_t where, uint32_t what);
void wk64(uint64_t where, uint64_t what);

uint64_t kalloc(uint64_t size);
uint64_t kalloc_wired(uint64_t size);
void kfree(uint64_t kaddr, uint64_t size);

size_t kread(uint64_t where, void *p, size_t size);
size_t kwrite(uint64_t where, const void* p, size_t size);

uint64_t get_proc_struct_for_pid(pid_t pid);
uint64_t get_address_of_port(pid_t pid, mach_port_t port);

uint64_t task_self_addr(void);
