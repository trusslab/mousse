///
/// Copyright (C) 2015-2017, Cyberhaven
/// Copyright (C) 2020, TrussLab@University of California, Irvine. 
///     Authors: Yingtong Liu <yingtong@uci.edu>
///
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <cpu/config.h>
#include <cpu/kvm.h>
#include "s2e-kvm-interface.h"
int g_trace = 0;
int g_kvm_fd = -1;
int g_kvm_vm_fd = -1;
int g_kvm_vcpu_fd = -1;

static open_t s_original_open;
int open(const char *pathname, int flags, ...) {
    /* we have to get the original open handler here instead of in __libc_init since the linker in android will call open before __libc_init */
    s_original_open = (open_t) dlsym(RTLD_NEXT, "open");
    va_list list;
    va_start(list, flags);
    int mode = va_arg(list, int);
    va_end(list);
    if (!strcmp(pathname, "/dev/kvm")) {
        int fd = s_original_open("/dev/null", flags, mode);
        if (fd < 0) {
            fprintf(stderr, "Could not open fake kvm /dev/null\n");
            exit(-1);
        } 
        g_kvm_fd = fd;
        return fd;
    } else {
        return s_original_open(pathname, flags, mode);
    }
	return -1;
}

static close_t s_original_close;
int close(int fd) {
    s_original_close = (close_t) dlsym(RTLD_NEXT, "close");
    if (fd == g_kvm_fd) {
        s_original_close(fd);
        g_kvm_fd = -1;
        return 0;
    } else {
        return s_original_close(fd);
    }
}

static write_t s_original_write;
ssize_t write(int fd, const void *buf, size_t count) {
    s_original_write = (write_t) dlsym(RTLD_NEXT, "write");
    if (fd == g_kvm_fd || fd == g_kvm_vm_fd) {
        fprintf(stderr, "write %d count=%zu\n", fd, count);
        exit(-1);
    } else {
        return s_original_write(fd, buf, count);
    }
}
static int handle_kvm_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_GET_API_VERSION:
            return s2e_kvm_get_api_version();

        case KVM_CHECK_EXTENSION:
            ret = s2e_kvm_check_extension(fd, arg1);
            if (ret < 0) {
                errno = 1;
            }
            break;

        case KVM_CREATE_VM: {
            int tmpfd = s2e_kvm_create_vm(fd);
            if (tmpfd < 0) {
                fprintf(stderr, "Could not create vm fd (errno=%d %s)\n", errno, strerror(errno));
                exit(-1);
            }
            g_kvm_vm_fd = tmpfd;
            ret = tmpfd;
        } break;

        case KVM_GET_VCPU_MMAP_SIZE: {
            ret = s2e_kvm_get_vcpu_mmap_size();
        } break;

#ifdef HOST_I386
        case KVM_GET_MSR_INDEX_LIST: {
            ret = s2e_kvm_get_msr_index_list(fd, (struct kvm_msr_list *) arg1);
        } break;
#endif

#ifdef HOST_I386
        case KVM_GET_SUPPORTED_CPUID: {
            ret = s2e_kvm_get_supported_cpuid(fd, (struct kvm_cpuid2 *) arg1);
        } break;
#endif
        default: {
            fprintf(stderr, "libs2e: unknown KVM IOCTL %x\n", request);
            exit(-1);
        }
    }

    return ret;
}

static int handle_kvm_vm_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_SET_TSS_ADDR: {
            ret = s2e_kvm_vm_set_tss_addr(fd, arg1);
        } break;

        case KVM_CREATE_VCPU: {
            ret = s2e_kvm_vm_create_vcpu(fd);
        } break;

        case KVM_SET_USER_MEMORY_REGION: {
            ret = s2e_kvm_vm_set_user_memory_region(fd, (struct kvm_userspace_memory_region *) arg1);
        } break;

        case KVM_SET_CLOCK: {
            ret = s2e_kvm_vm_set_clock(fd, (struct kvm_clock_data *) arg1);
        } break;

        case KVM_GET_CLOCK: {
            ret = s2e_kvm_vm_get_clock(fd, (struct kvm_clock_data *) arg1);
        } break;

        case KVM_ENABLE_CAP: {
            ret = s2e_kvm_vm_enable_cap(fd, (struct kvm_enable_cap *) arg1);
        } break;

        case KVM_IOEVENTFD: {
            ret = s2e_kvm_vm_ioeventfd(fd, (struct kvm_ioeventfd *) arg1);
        } break;

        case KVM_SET_IDENTITY_MAP_ADDR: {
            ret = s2e_kvm_vm_set_identity_map_addr(fd, arg1);
        } break;

        case KVM_GET_DIRTY_LOG: {
            ret = s2e_kvm_vm_get_dirty_log(fd, (struct kvm_dirty_log *) arg1);
        } break;

        case KVM_MEM_RW: {
            ret = s2e_kvm_vm_mem_rw(fd, (struct kvm_mem_rw *) arg1);
        } break;

        case KVM_FORCE_EXIT: {
            s2e_kvm_request_exit();
            ret = 0;
        } break;

        case KVM_MEM_REGISTER_FIXED_REGION: {
            ret = s2e_kvm_vm_register_fixed_region(fd, (struct kvm_fixed_region *) arg1);
        } break;
#ifdef CONFIG_USER_KVM
	case KVM_USER_UPDATE_PAGEDESC: {
            ret = s2e_kvm_vm_update_pageDesc(fd,  (struct kvm_user_update_page *) arg1);
	} break;
#endif
        case KVM_DISK_RW: {
            ret = s2e_kvm_vm_disk_rw(fd, (struct kvm_disk_rw *) arg1);
        } break;

        case KVM_DEV_SNAPSHOT: {
            ret = s2e_kvm_vm_dev_snapshot(fd, (struct kvm_dev_snapshot *) arg1);
        } break;

        case KVM_SET_CLOCK_SCALE: {
            ret = s2e_kvm_set_clock_scale_ptr(fd, (unsigned *) arg1);
        } break;

        default: {
            fprintf(stderr, "libs2e: unknown KVM VM IOCTL %x\n", request);
            exit(-1);
        }
    }

    return ret;
}

static int handle_kvm_vcpu_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_GET_CLOCK: {
            ret = s2e_kvm_vcpu_get_clock(fd, (struct kvm_clock_data *) arg1);
        } break;
#ifdef HOST_I386
        case KVM_SET_CPUID2: {
            ret = s2e_kvm_vcpu_set_cpuid2(fd, (struct kvm_cpuid2 *) arg1);
        } break;
#endif
        case KVM_SET_SIGNAL_MASK: {
            ret = s2e_kvm_vcpu_set_signal_mask(fd, (struct kvm_signal_mask *) arg1);
        } break;

        /***********************************************/
        case KVM_SET_REGS: {
            ret = s2e_kvm_vcpu_set_regs(fd, (struct kvm_regs *) arg1);
        } break;

        case KVM_SET_FPU: {
            ret = s2e_kvm_vcpu_set_fpu(fd, (struct kvm_fpu *) arg1);
        } break;

        case KVM_SET_SREGS: {
            ret = s2e_kvm_vcpu_set_sregs(fd, (struct kvm_sregs *) arg1);
        } break;
#ifdef TARGET_ARM
        case KVM_SET_ONE_REG: {
            ret = s2e_kvm_vcpu_set_one_reg(fd, (struct kvm_one_reg *) arg1);
        } break;
#endif
#ifdef CONFIG_USER_KVM
	case KVM_SET_OPAQUE: {
            ret = s2e_kvm_vcpu_set_opaque(fd,  (void *) arg1);
	} break;
#endif
#ifdef HOST_I386
        case KVM_SET_MSRS: {
            ret = s2e_kvm_vcpu_set_msrs(fd, (struct kvm_msrs *) arg1);
        } break;
#endif
        case KVM_SET_MP_STATE: {
            ret = s2e_kvm_vcpu_set_mp_state(fd, (struct kvm_mp_state *) arg1);
        } break;
        /***********************************************/
        case KVM_GET_REGS: {
            ret = s2e_kvm_vcpu_get_regs(fd, (struct kvm_regs *) arg1);
        } break;

        case KVM_GET_FPU: {
            ret = s2e_kvm_vcpu_get_fpu(fd, (struct kvm_fpu *) arg1);
        } break;

        case KVM_GET_SREGS: {
            ret = s2e_kvm_vcpu_get_sregs(fd, (struct kvm_sregs *) arg1);
        } break;

#ifdef HOST_I386
        case KVM_GET_MSRS: {
            ret = s2e_kvm_vcpu_get_msrs(fd, (struct kvm_msrs *) arg1);
        } break;
#endif
        case KVM_GET_MP_STATE: {
            ret = s2e_kvm_vcpu_get_mp_state(fd, (struct kvm_mp_state *) arg1);
        } break;

        /***********************************************/
        case KVM_RUN: {
            return s2e_kvm_vcpu_run(fd);
        } break;

        case KVM_INTERRUPT: {
            ret = s2e_kvm_vcpu_interrupt(fd, (struct kvm_interrupt *) arg1);
        } break;

        case KVM_NMI: {
            ret = s2e_kvm_vcpu_nmi(fd);
        } break;
#ifdef HOST_ARM
        case KVM_ARM_VCPU_INIT: {
            ret = s2e_kvm_arm_vcpu_init(fd, (struct kvm_vcpu_init *) arg1);
        } break;
#endif
        default: {
            fprintf(stderr, "libs2e: unknown KVM VCPU IOCTL vcpu %d request=%#x arg=%#" PRIx64 " ret=%#x\n", fd,
                    request, arg1, ret);
            exit(-1);
        }
    }

    return ret;
}


ioctl_t g_original_ioctl;
int ioctl(int fd, int request, ...) {
    g_original_ioctl = (ioctl_t) dlsym(RTLD_NEXT, "ioctl");
    va_list vl;
    uint64_t arg1;
    va_start(vl,request);
    arg1 = va_arg(vl,uint64_t);
    va_end(vl);
    int ret = -1;
    if (g_trace) {
	    assert(false && "g_trace not supported\n");
    } else {
        if (fd == g_kvm_fd) {
            ret = handle_kvm_ioctl(fd, request, arg1);
        } else if (fd == g_kvm_vm_fd) {
            ret = handle_kvm_vm_ioctl(fd, request, arg1);
        } else if (fd == g_kvm_vcpu_fd) {
            ret = handle_kvm_vcpu_ioctl(fd, request, arg1);
        } else {
            ret = g_original_ioctl(fd, request, arg1);
        }
    }
    return ret;
}
static mmap_t s_original_mmap;
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    s_original_mmap = (mmap_t) dlsym(RTLD_NEXT, "mmap");
    if (fd < 0 || (fd != g_kvm_vcpu_fd)) {
	    void * host_addr = s_original_mmap(addr, len, prot, flags, fd, offset);
        return host_addr;
    }

    int real_size = s2e_kvm_get_vcpu_mmap_size();
    assert(real_size == len);
    assert(g_kvm_vcpu_buffer);

    return g_kvm_vcpu_buffer;
}
// ****************************
// Overriding __libc_init
// ****************************
/* Copied from libc_init_common.h */

typedef struct {
	void (**preinit_array)(void);
	void (**init_array)(void);
	void (**fini_array)(void);
} structors_array_t;

typedef __noreturn void (*T_libc_init)(void* raw_args,
                            void (*onexit)(void) __unused,
                            int (*slingshot)(int, char**, char**),
                            structors_array_t const * const structors); 
__noreturn void __libc_init(void* raw_args,
                            void (*onexit)(void) __unused,
                            int (*slingshot)(int, char**, char**),
                            structors_array_t const * const structors); 
__noreturn void __libc_init(void* raw_args,
                            void (*onexit)(void) __unused,
                            int (*slingshot)(int, char**, char**),
                            structors_array_t const * const structors) {

    T_libc_init orig_libc_init = (T_libc_init) dlsym(RTLD_NEXT, "__libc_init");

    //fprintf(stderr, "Starting libs2e...\n");

    // libs2e might spawn other processes (e.g., from plugin code).
    // This will fail if we preload libs2e.so for these processes,
    // so we must remove this environment variable.
    unsetenv("LD_PRELOAD");

    (*orig_libc_init)(raw_args, onexit, slingshot, structors);
    exit(1);
}

