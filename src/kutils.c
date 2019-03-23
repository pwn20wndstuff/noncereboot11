#include <mach/mach.h>

#include "kutils.h"
#include "debug.h"
#include "offsets.h"

offsets_t offs;
mach_port_t tfpzero;
uint64_t kernel_base;

kern_return_t init_tfpzero(void) {
    kern_return_t ret;
    tfpzero = MACH_PORT_NULL;

    host_t host = mach_host_self();
    ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfpzero);
    
    if (ret != KERN_SUCCESS) {
        ERRORLOG("Failed to get kernel_task\n");
        return ret;
    }

    ret = MACH_PORT_VALID(tfpzero) ? KERN_SUCCESS : KERN_FAILURE;

    if (ret != KERN_SUCCESS) {
        ERRORLOG("kernel_task is not valid\n");
    } else {
        DEBUGLOG("kernel_task = 0x%08x\n", tfpzero);
    }

    return ret;
}

kern_return_t init_kernel_base(void) {
    kern_return_t ret;
    kernel_base = 0;
    
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    ret = task_info(tfpzero, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    
    if (ret != KERN_SUCCESS) {
        ERRORLOG("Failed to get task info\n");
        return ret;
    }
    
    ret = !((kernel_base = dyld_info.all_image_info_addr) != 0);
    
    if (ret != KERN_SUCCESS) {
        ERRORLOG("kernel_base is not valid\n");
    } else {
        DEBUGLOG("kernel_base = 0x%016llx\n", kernel_base);
    }
    
    kernel_slide = dyld_info.all_image_info_size;
    
    return ret;
}

kern_return_t init_offsets(void) {
    CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, CFSTR("/jb/offsets.plist"), kCFURLPOSIXPathStyle, false);
    if (fileURL == NULL) {
        ERRORLOG("Unable to create URL");
        return KERN_FAILURE;
    }
    CFDataRef off_file_data;
    SInt32 errorCode;
    Boolean status = CFURLCreateDataAndPropertiesFromResource(
            kCFAllocatorDefault, fileURL, &off_file_data,
            NULL, NULL, &errorCode);
    
    CFRelease(fileURL);
    if (!status) {
        ERRORLOG("Unable to read /jb/offsets.plist");
        return KERN_FAILURE;
    }
    
    DEBUGLOG("off_file_data: %p", off_file_data);
    CFPropertyListRef offsets = CFPropertyListCreateWithData(kCFAllocatorDefault, (CFDataRef)off_file_data, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(off_file_data);
    if (offsets == NULL) {
        ERRORLOG("Unable to convert /jb/offsets.plist to property list");
        return KERN_FAILURE;
    }
    
    if (CFGetTypeID(offsets) != CFDictionaryGetTypeID()) {
        ERRORLOG("/jb/offsets.plist did not convert to a dictionary");
        CFRelease(offsets);
        return KERN_FAILURE;
    }
    
    // TODO: CFStringGetCStringPtr is not to be relied upon like this... bad things will happen if this is not fixed
    SETOFFSET(kernel_task, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("KernelTask")), kCFStringEncodingUTF8), NULL, 16));
#if __arm64e__
    SETOFFSET(paciza_pointer__l2tp_domain_module_start, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("PacizaPointerL2TPDomainModuleStart")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(paciza_pointer__l2tp_domain_module_stop, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("PacizaPointerL2TPDomainModuleStop")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(l2tp_domain_inited, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("L2TPDomainInited")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(sysctl__net_ppp_l2tp, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("SysctlNetPPPL2TP")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(sysctl_unregister_oid, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("SysctlUnregisterOid")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(mov_x0_x4__br_x5, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("MovX0X4BrX5")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(mov_x9_x0__br_x1, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("MovX9X0BrX1")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(mov_x10_x3__br_x6, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("MovX10X3BrX6")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(kernel_forge_pacia_gadget, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("KernelForgePaciaGadget")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(kernel_forge_pacda_gadget, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("KernelForgePacdaGadget")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(IOUserClient__vtable, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("IOUserClientVtable")), kCFStringEncodingUTF8), NULL, 16));
    SETOFFSET(IORegistryEntry__getRegistryEntryID, (uint64_t)strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("IORegistryEntryGetRegistryEntryID")), kCFStringEncodingUTF8), NULL, 16));
#endif
    CFRelease(offsets);
    
    return KERN_SUCCESS;
}

/***** mach_vm.h *****/
kern_return_t mach_vm_read(
  vm_map_t target_task,
  mach_vm_address_t address,
  mach_vm_size_t size,
  vm_offset_t *data,
  mach_msg_type_number_t *dataCnt);

kern_return_t mach_vm_write(
  vm_map_t target_task,
  mach_vm_address_t address,
  vm_offset_t data,
  mach_msg_type_number_t dataCnt);

kern_return_t mach_vm_read_overwrite(
  vm_map_t target_task,
  mach_vm_address_t address,
  mach_vm_size_t size,
  mach_vm_address_t data,
  mach_vm_size_t *outsize);

kern_return_t mach_vm_allocate(
  vm_map_t target,
  mach_vm_address_t *address,
  mach_vm_size_t size,
  int flags);

kern_return_t mach_vm_deallocate (
  vm_map_t target,
  mach_vm_address_t address,
  mach_vm_size_t size);

kern_return_t mach_vm_protect (
  vm_map_t target_task,
  mach_vm_address_t address,
  mach_vm_size_t size,
  boolean_t set_maximum,
  vm_prot_t new_protection);

// The vm_* APIs are part of the mach_vm subsystem, which is a MIG thing
// and therefore has a hard limit of 0x1000 bytes that it accepts. Due to
// this, we have to do both reading and writing in chunks smaller than that.
#define MAX_CHUNK_SIZE 0xFFF

size_t rkbuffer(uint64_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = MAX_CHUNK_SIZE;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfpzero, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            ERRORLOG("error on rkbuffer(0x%016llx)", (offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

uint32_t rk32(uint64_t where) {
    uint32_t out;
    rkbuffer(where, &out, sizeof(uint32_t));
    return out;
}

uint64_t rk64(uint64_t where) {
    uint64_t out;
    rkbuffer(where, &out, sizeof(uint64_t));
    return out;
}

size_t wkbuffer(uint64_t where, const void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = MAX_CHUNK_SIZE;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfpzero, where + offset, (mach_vm_offset_t)p + offset, chunk);
        if (rv) {
            ERRORLOG("error on wkbuffer(0x%016llx)", (offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

void wk32(uint64_t where, uint32_t what) {
    uint32_t _what = what;
    wkbuffer(where, &_what, sizeof(uint32_t));
}

void wk64(uint64_t where, uint64_t what) {
    uint64_t _what = what;
    wkbuffer(where, &_what, sizeof(uint64_t));
}


uint64_t kalloc(uint64_t size) {
    kern_return_t err;
    mach_vm_address_t addr = 0;
    err = mach_vm_allocate(tfpzero, &addr, size, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        ERRORLOG("unable to allocate kernel memory via tfp0: %s 0x%x", mach_error_string(err), err);
        return 0;
    }
    return addr;
}

uint64_t kalloc_wired(uint64_t size) {  
    mach_vm_address_t addr = 0;
    addr = kalloc(size);

    if (addr == 0) {
        ERRORLOG("Not wiring NULL");
        return 0;
    }

    kern_return_t err = mach_vm_wire(mach_host_self(), tfpzero, addr, size, VM_PROT_READ|VM_PROT_WRITE);
    if (err != KERN_SUCCESS) {
        ERRORLOG("unable to wire kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        kfree(addr, size);
        return 0;
    }

    return addr;
}

void kfree(uint64_t kaddr, uint64_t size) {
  kern_return_t err;
  err = mach_vm_deallocate(tfpzero, kaddr, size);
  if (err != KERN_SUCCESS) {
    INFOLOG("unable to deallocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
  }
}

size_t kread(uint64_t where, void *p, size_t size) {
    return rkbuffer(where, p, size);
}

size_t kwrite(uint64_t where, const void* p, size_t size) {
    return wkbuffer(where, p, size);
}

uint64_t get_proc_struct_for_pid(pid_t pid)
{
    uint64_t proc = rk64(rk64(GETOFFSET(kernel_task)) + OFF_TASK__BSD_INFO);
    while (proc) {
        if (rk32(proc + OFF_PROC__P_PID) == pid)
            return proc;
        proc = rk64(proc + OFF_PROC__P_LIST);
    }
    return 0;
}

uint64_t get_address_of_port(pid_t pid, mach_port_t port)
{
    uint64_t proc_struct_addr = get_proc_struct_for_pid(pid);
    uint64_t task_addr = rk64(proc_struct_addr + OFF_PROC__TASK);
    uint64_t itk_space = rk64(task_addr + OFF_TASK__ITK_SPACE);
    uint64_t is_table = rk64(itk_space + OFF_IPC_SPACE__IS_TABLE);
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint64_t port_addr = rk64(is_table + (port_index * sizeof_ipc_entry_t));
    return port_addr;
}

uint64_t task_self_addr(void) {
    uint64_t port_addr = get_address_of_port(getpid(), mach_task_self());
    return port_addr;
}
