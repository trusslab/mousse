/// Copyright (C) 2016  Cyberhaven
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
/// 	Authors: Yingtong Liu <yingtong@uci.edu> 
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#include <assert.h>
#include <cpu/memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "exec-all.h"
#include "exec-ram.h"

#include <sys/mman.h>
#include <s2e/s2e_libcpu.h>
#include "cpu-all.h"
/* Fix no free slot available */
static const unsigned MEM_REGION_MAX_COUNT = 6000;
static MemoryDesc s_regions[MEM_REGION_MAX_COUNT];
static unsigned s_region_count = 0;

#ifdef CONFIG_USER_KVM
static struct kvm_userspace_memory_region region;
int ram_num = 0;
#endif

#ifdef DEBUG_PAGE_ALLOC
void debug_page_alloc() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        fprintf(stderr, "Could not open mem maps %s\n", __FUNCTION__);
        exit(-1);
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), fp)) {
        uint64_t s, e;
        unsigned int pgoff, major, minor;
	unsigned long ino;
        //char r, w, x;
        char r, w, x, p;
	char name[200];
        //sscanf(buffer, "%" PRIx64 "-%" PRIx64 " %c%c%c", &s, &e, &r, &w, &x);
        sscanf(buffer, "%" PRIx64 "-%" PRIx64 " %c%c%c%c" " %x %x:%x %lu\t%s", &s, &e, &r, &w, &x, &p, &pgoff, &major, &minor, &ino, name);
        fprintf(stderr, "    Area %" PRIx64 "-%" PRIx64 "%c%c%c name=%s\n", s, e, r, w, x, name);
    }

    fclose(fp);
}
#else
void debug_page_alloc() {};
#endif

static bool get_memory_access_flags(uint64_t start, uint64_t size, bool *readable, bool *writable) {
/* The area flags are accessed by each allocated chunk. The GPM size passed to s2e is (highest - lowest), spanning many chunks.*/

    bool ret = false;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        fprintf(stderr, "Could not open mem maps %s\n", __FUNCTION__);
        exit(-1);
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), fp)) {
        uint64_t s, e;
        char r, w;
        sscanf(buffer, "%" PRIx64 "-%" PRIx64 " %c%c", &s, &e, &r, &w);
        if (start >= s && ((start + size) <= e)) {


            *writable = w == 'w';
            *readable = r == 'r';
            ret = true;
            goto end;
        }
    }

    fprintf(stderr, "Could not execute %s\n", __FUNCTION__);
    exit(-1);

end:
    fclose(fp);
    return ret;
}

const MemoryDesc *mem_desc_register(struct kvm_userspace_memory_region *kr) {
    if (!kr->memory_size) {
        return NULL;
    }


    assert(kr->slot < MEM_REGION_MAX_COUNT);
//For user mode, the memory access flags should be maintained per page in PageDesc
#ifndef CONFIG_USER_KVM

    bool readable, writable;
    get_memory_access_flags(kr->userspace_addr, kr->memory_size, &readable, &writable);

    bool ro = readable && !writable;

    // There shouldn't be any readonly regions, we don't support KVM_CAP_READONLY_MEM
    assert(!ro);
#else
    bool ro = false;
#endif
    MemoryDesc *r = &s_regions[kr->slot];
    r->kvm = *kr;
    r->read_only = ro;

    if (s_region_count < kr->slot + 1) {
        s_region_count = kr->slot + 1;
    }

    r->ram_addr = qemu_ram_alloc_from_ptr(kr->memory_size, (void *) kr->userspace_addr);

    return r;
}

///
/// \brief mem_desc_find
/// \param guest_phys_addr
/// \return null if there is no ram at this address, which means mmio
///
const MemoryDesc *mem_desc_find(uint64_t guest_phys_addr) {
    for (unsigned i = 0; i < s_region_count; ++i) {
        const MemoryDesc *r = &s_regions[i];
        if (!r->kvm.memory_size) {
            continue;
        }

        uint64_t a = r->kvm.guest_phys_addr;
        uint64_t b = a - 1 + r->kvm.memory_size;

        if (guest_phys_addr >= a && guest_phys_addr <= b) {
            return r;
        }
    }

    return NULL;
}

const MemoryDesc *mem_desc_get_slot(unsigned slot) {
    assert(slot < MEM_REGION_MAX_COUNT);
    return &s_regions[slot];
}

void mem_desc_unregister(unsigned slot) {
    // TODO: notify all listeners to reset their maps
    MemoryDesc *r = &s_regions[slot];
    if (!r->kvm.memory_size) {
        return;
    }

    qemu_ram_free_from_ptr(r->ram_addr);


    memset(r, 0, sizeof(*r));
}

void *mem_desc_get_ram_ptr(const MemoryDesc *r) {
    return qemu_get_ram_ptr(r->ram_addr & TARGET_PAGE_MASK);
}
#ifdef CONFIG_USER_KVM
void kvm_user_tb_invalidate_phys_range(target_ulong start, target_ulong end, int is_cpu_write_access) {
	user_tb_invalidate_phys_range(start, end, is_cpu_write_access);	
}	

void kvm_user_page_set_flags(target_ulong start, target_ulong end, int flags) {
	page_set_flags(start, end, flags);	
}

static __u32 kvm_find_slot()
{
    __u32 i;
    
    for (i = 0; i < ARRAY_SIZE(s_regions); i++) {
        if (s_regions[i].kvm.memory_size == 0) {
            //return &s_regions[i];
            return i;
        }
    }

    fprintf(stderr, "%s: no free slot available\n", __func__);
    abort();
}

/*
 * Find overlapping slot with lowest start address
 */
static struct MemoryDesc* kvm_lookup_overlapping_slot(target_phys_addr_t start_addr, target_phys_addr_t end_addr)
{
    MemoryDesc *found = NULL;
    int i;

    for (i = 0; i < ARRAY_SIZE(s_regions); i++) {
        MemoryDesc *mem = &s_regions[i];

        if (mem->kvm.memory_size == 0 ||
            (found && found->kvm.guest_phys_addr < mem->kvm.guest_phys_addr)) {
            continue;
        }

        if (end_addr > mem->kvm.guest_phys_addr &&
            start_addr < mem->kvm.guest_phys_addr + mem->kvm.memory_size) {
            found = mem;
        }
    }

    return found;
}
static int kvm_set_user_memory_region(struct kvm_userspace_memory_region *mem)
{
    mem_desc_unregister(mem->slot);
    mem_desc_register(mem);
    return 0;
}

//static void kvm_set_phys_mem(MemoryRegionSection *section, bool add)
void kvm_set_user_phys_mem(target_phys_addr_t start_addr, ram_addr_t size)
{
    struct MemoryDesc *mem, old;
    int err;
    while (1) {
        mem = kvm_lookup_overlapping_slot(start_addr, start_addr + size);
        if (!mem) {
            break;
        }
        old = *mem;
	    region = mem->kvm; 
        /* unregister the overlapping slot */
        region.memory_size = 0;
        err = kvm_set_user_memory_region(&region);
        if (err) {
            fprintf(stderr, "%s: error unregistering overlapping slot: %s\n",
                    __func__, strerror(-err));
            abort();
        }

        /* register prefix slot */
        if (old.kvm.guest_phys_addr < start_addr) {
            region.slot = kvm_find_slot();
            region.memory_size = start_addr - old.kvm.guest_phys_addr;
            region.guest_phys_addr = old.kvm.guest_phys_addr;
            region.userspace_addr = old.kvm.userspace_addr;

            err = kvm_set_user_memory_region(&region);
            if (err) {
                fprintf(stderr, "%s: error registering prefix slot: %s\n",
                        __func__, strerror(-err));
#ifdef TARGET_PPC
                fprintf(stderr, "%s: This is probably because your kernel's " \
                                "PAGE_SIZE is too big. Please try to use 4k " \
                                "PAGE_SIZE!\n", __func__);
#endif
                abort();
            }
        }

        /* register suffix slot */
        if (old.kvm.guest_phys_addr + old.kvm.memory_size > start_addr + size) {
            ram_addr_t size_delta;

            region.slot = kvm_find_slot();
            region.guest_phys_addr = start_addr + size;
            size_delta = region.guest_phys_addr - old.kvm.guest_phys_addr;
            region.memory_size = old.kvm.memory_size - size_delta;
            region.userspace_addr = old.kvm.userspace_addr + size_delta;

            err = kvm_set_user_memory_region(&region);
            if (err) {
                fprintf(stderr, "%s: error registering suffix slot: %s\n",
                        __func__, strerror(-err));
                abort();
            }
        }
    }
    region.slot = kvm_find_slot();
    region.memory_size = size;
    region.guest_phys_addr = start_addr;
    region.userspace_addr = start_addr;
    region.flags = 0;

    err = kvm_set_user_memory_region(&region);
    if (err) {
        fprintf(stderr, "%s: error registering slot: %s\n", __func__,
                strerror(-err));
        abort();
    }
}

void ram_memory_change(target_phys_addr_t start, ram_addr_t size, int prot)
{
	debug_page_alloc();
#ifdef CONFIG_SYMBEX_MP
    		char ram_name[12];
    		sprintf(ram_name, "user.ram.%d", ram_num++);
     		s2e_register_ram2((const char*)ram_name, start, size, 0);
#endif
     		kvm_set_user_phys_mem(start, size);
}
#endif
