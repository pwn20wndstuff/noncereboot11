#pragma once

#include <mach/mach.h>
#include <inttypes.h>
#include <sys/types.h>

#define SETOFFSET(offset, val) (offs.offset = val)
#define GETOFFSET(offset) offs.offset

typedef struct {
    uint64_t kernel_task;
} offsets_t;

extern offsets_t offs;

extern mach_port_t tfpzero;
extern uint64_t kernel_base;

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
