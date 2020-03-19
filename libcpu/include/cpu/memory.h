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

#ifndef MEMORY_H
#define MEMORY_H

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include "kvm.h"
#include "types.h"

/////////////////////////////////////////////////////////////////////
typedef uint64_t (*mem_read_t)(target_phys_addr_t guest_phys_addr, unsigned size);
typedef void (*mem_write_t)(target_phys_addr_t guest_phys_addr, uint64_t value, unsigned size);
struct MemoryDescOps {
    mem_read_t read;
    mem_write_t write;
};

typedef struct MemoryDesc {
    struct kvm_userspace_memory_region kvm;
    struct MemoryDescOps ops;
    bool read_only;

    // TODO: get rid of this too
    uint64_t ram_addr;
} MemoryDesc;

const MemoryDesc *mem_desc_register(struct kvm_userspace_memory_region *kr);

///
/// \brief mem_desc_find
/// \param guest_phys_addr
/// \return null if there is no ram at this address, which means mmio
///
const MemoryDesc *mem_desc_find(uint64_t guest_phys_addr);

const MemoryDesc *mem_desc_get_slot(unsigned slot);

void mem_desc_unregister(unsigned slot);
#ifdef CONFIG_USER_KVM
void kvm_set_user_phys_mem(target_phys_addr_t start_addr, ram_addr_t size);
void kvm_user_tb_invalidate_phys_range(target_ulong start, target_ulong end, int is_cpu_write_access);
void kvm_user_page_set_flags(target_ulong start, target_ulong end, int flags);
#endif

static inline uintptr_t mem_desc_addend(const MemoryDesc *r, uint64_t phys_addr) {
    return phys_addr - r->kvm.guest_phys_addr + r->kvm.userspace_addr;
}

static inline uint64_t mem_desc_get_offset(const MemoryDesc *r, uint64_t phys_addr) {
    uint64_t a = r->kvm.guest_phys_addr;
    uint64_t b = a - 1 + r->kvm.memory_size;
    if (!(phys_addr >= a && phys_addr <= b)) {
        abort();
    }
    return phys_addr -= a;
}

void *mem_desc_get_ram_ptr(const MemoryDesc *r);
void debug_page_alloc();
//#define DEBUG_PAGE_ALLOC
#ifdef CONFIG_USER_KVM
void ram_memory_change(target_phys_addr_t start, ram_addr_t size, int prot);
#endif
#endif
