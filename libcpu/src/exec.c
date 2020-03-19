/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
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

#include <cpu/config.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <cpu/ioport.h>
#include <cpu/memory.h>
#include <tcg/tcg.h>
#include "cpu.h"
#include "osdep.h"
#include "qemu-common.h"

#ifdef CONFIG_SYMBEX
#include <cpu-all.h>
#include <cpu/se_libcpu.h>
#include <cpu/se_libcpu_config.h>
#endif
#include "exec-phys.h"
#include "exec-ram.h"
#include "exec-tb.h"
#include "exec-tlb.h"
#include "exec.h"
#ifdef CONFIG_USER_KVM
#include "syscall_hdr.h"
#include "exec-phystb.h"
#endif
//#define DEBUG_TB_INVALIDATE
//#define DEBUG_FLUSH
//#define DEBUG_TLB
//#define DEBUG_UNASSIGNED

/* make various TB consistency checks */
//#define DEBUG_TB_CHECK
//#define DEBUG_TLB_CHECK

//#define DEBUG_IOPORT
//#define DEBUG_SUBPAGE

/* TB consistency checks only implemented for usermode emulation.  */
#undef DEBUG_TB_CHECK
CPUArchState *first_cpu;
DEFINE_TLS(CPUArchState *,cpu_single_env);
#ifdef CONFIG_SYMBEX
struct se_libcpu_interface_t g_sqi;
#endif
static void io_mem_init(void);

void cpu_exec_init_all(void) {
    io_mem_init();

#ifdef CONFIG_USER_KVM
     syscall_init();
	 signal_init();
     read_in_mmap_min_addr();
#endif
#ifdef CONFIG_SYMBEX
    g_sqi.libcpu.ldub_code = ldub_code;
    g_sqi.libcpu.ldl_code = ldl_code;
#endif
}
void cpu_exec_init(CPUArchState *env) {
    CPUArchState **penv;
    int cpu_index;

    env->next_cpu = NULL;
    penv = &first_cpu;
    cpu_index = 0;
    while (*penv != NULL) {
        penv = &(*penv)->next_cpu;
        cpu_index++;
    }
    env->cpu_index = cpu_index;
    env->numa_node = 0;
    QTAILQ_INIT(&env->breakpoints);
    QTAILQ_INIT(&env->watchpoints);
    *penv = env;
}

/* mask must never be zero, except for A20 change call */
static void tcg_handle_interrupt(CPUArchState *env, int mask) {
    int old_mask;

    old_mask = env->interrupt_request;
    env->interrupt_request |= mask;

    cpu_unlink_tb(env);
}

CPUInterruptHandler cpu_interrupt_handler = tcg_handle_interrupt;

void cpu_reset_interrupt(CPUArchState *env, int mask) {
    env->interrupt_request &= ~mask;
}

void cpu_exit(CPUArchState *env) {
    env->exit_request = 1;
    cpu_unlink_tb(env);
}

void cpu_abort(CPUArchState *env, const char *fmt, ...) {
    va_list ap;
    va_list ap2;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    fprintf(stderr, "qemu: fatal: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
#ifdef TARGET_I386
    cpu_dump_state(env, stderr, fprintf, X86_DUMP_FPU | X86_DUMP_CCOP);
#else
    cpu_dump_state(env, stderr, fprintf, 0);
#endif
    if (libcpu_log_enabled()) {
        libcpu_log("qemu: fatal: ");
        libcpu_log_vprintf(fmt, ap2);
        libcpu_log("\n");
#ifdef TARGET_I386
        log_cpu_state(env, X86_DUMP_FPU | X86_DUMP_CCOP);
#else
        log_cpu_state(env, 0);
#endif
        libcpu_log_flush();
        libcpu_log_close();
    }
    va_end(ap2);
    va_end(ap);
    abort();
}
CPUArchState *cpu_copy(CPUArchState *env)
{
    CPUArchState *new_env = cpu_init(env->cpu_model_str);
    CPUArchState *next_cpu = new_env->next_cpu;
    int cpu_index = new_env->cpu_index;
#if defined(TARGET_HAS_ICE)
    CPUBreakpoint *bp;
    CPUWatchpoint *wp;
#endif
    memcpy(new_env, env, sizeof(CPUArchState));

    /* Preserve chaining and index. */
    new_env->next_cpu = next_cpu;
    new_env->cpu_index = cpu_index;

    /* Clone all break/watchpoints.
       Note: Once we support ptrace with hw-debug register access, make sure
       BP_CPU break/watchpoints are handled correctly on clone. */
    QTAILQ_INIT(&env->breakpoints);
    QTAILQ_INIT(&env->watchpoints);
#if defined(TARGET_HAS_ICE)
    QTAILQ_FOREACH(bp, &env->breakpoints, entry) {
        cpu_breakpoint_insert(new_env, bp->pc, bp->flags, NULL);
    }
    QTAILQ_FOREACH(wp, &env->watchpoints, entry) {
        cpu_watchpoint_insert(new_env, wp->vaddr, (~wp->len_mask) + 1,
                              wp->flags, NULL);
    }
#endif

    return new_env;
}
//#endif
/* Note: start and end must be within the same ram block.  */
void cpu_physical_memory_reset_dirty(ram_addr_t start, ram_addr_t end, int dirty_flags) {
    CPUArchState *env;
    unsigned long length, start1;
    int i;

    start &= TARGET_PAGE_MASK;
    end = TARGET_PAGE_ALIGN(end);

    length = end - start;
    if (length == 0)
        return;
    cpu_physical_memory_mask_dirty_range(start, length, dirty_flags);

    /* we modify the TLB cache so that the dirty bit will be set again
       when accessing the range */
    start1 = (unsigned long) qemu_safe_ram_ptr(start);
    /* Check that we don't span multiple blocks - this breaks the
       address comparisons below.  */
    if ((unsigned long) qemu_safe_ram_ptr(end - 1) - start1 != (end - 1) - start) {
        abort();
    }

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        int mmu_idx;
        for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
            for (i = 0; i < CPU_TLB_SIZE; i++)
////                tlb_reset_dirty_range(&env->tlb_table[mmu_idx][i], start1, length);
                tlb_reset_dirty_range(&tlb_table[mmu_idx][i], start1, length);
        }
    }
}
intptr_t se_get_host_address(target_phys_addr_t paddr) {
  const MemoryDesc *sreg = mem_desc_find(paddr);
  if (!sreg) {
      return -1;
  }

  return sreg->kvm.userspace_addr + mem_desc_get_offset(sreg, paddr);
}

#if defined(__linux__) && !defined(TARGET_S390X)

static void unassigned_mem_write(target_phys_addr_t addr, uint64_t val, unsigned size) {
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem write " TARGET_FMT_plx " = 0x%" PRIx64 "\n", addr, val);
#endif
#if defined(TARGET_ALPHA) || defined(TARGET_SPARC) || defined(TARGET_MICROBLAZE)
    cpu_unassigned_access(cpu_single_env, addr, 1, 0, 0, size);
#endif
}

/** All writes to unassigned memory cause a vm exit */
static const struct MemoryDescOps unassigned_mem_ops = {
    .read = cpu_mmio_read, .write = cpu_mmio_write,
};

static uint64_t error_mem_read(target_phys_addr_t addr, unsigned size) {
    abort();
}

static const struct MemoryDescOps rom_mem_ops = {
    .read = error_mem_read, .write = unassigned_mem_write,
};

static void notdirty_mem_write(target_phys_addr_t ram_addr, uint64_t val, unsigned size) {
    int dirty_flags;
    dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);
    if (!(dirty_flags & CODE_DIRTY_FLAG)) {
        tb_invalidate_phys_page_fast(ram_addr, size);
        dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);
    }

    switch (size) {
        case 1:
            stb_raw(qemu_get_ram_ptr(ram_addr), val);
            break;
        case 2:
            stw_raw(qemu_get_ram_ptr(ram_addr), val);
            break;
        case 4:
            stl_raw(qemu_get_ram_ptr(ram_addr), val);
            break;
        default:
            abort();
    }

    dirty_flags |= (0xff & ~CODE_DIRTY_FLAG);
    cpu_physical_memory_set_dirty_flags(ram_addr, dirty_flags);
    /* we remove the notdirty callback only if the code has been
       flushed */
    if (dirty_flags == 0xff) {
#ifdef CONFIG_SYMBEX
        target_ulong iovaddr = g_sqi.mem.read_mem_io_vaddr(1);
        tlb_set_dirty(cpu_single_env, iovaddr);
#else
        tlb_set_dirty(cpu_single_env, cpu_single_env->mem_io_vaddr);
#endif
    }
}

#ifdef CONFIG_SYMBEX
uintptr_t se_notdirty_mem_write(target_phys_addr_t ram_addr) {
    int dirty_flags;

    target_ulong iovaddr = g_sqi.mem.read_mem_io_vaddr(1);

    if (tlb_is_dirty(cpu_single_env, iovaddr)) {
        return (uintptr_t) qemu_get_ram_ptr(ram_addr);
    }

    dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);

    if (!(dirty_flags & CODE_DIRTY_FLAG)) {
        tb_invalidate_phys_page_fast(ram_addr, 4);
        dirty_flags = cpu_physical_memory_get_dirty_flags(ram_addr);
    }

    dirty_flags |= (0xff & ~CODE_DIRTY_FLAG);

    cpu_physical_memory_set_dirty_flags(ram_addr, dirty_flags);

    /* we remove the notdirty callback only if the code has been
       flushed */
    if (dirty_flags == 0xff)
        tlb_set_dirty(cpu_single_env, iovaddr);

    return (uintptr_t) qemu_get_ram_ptr(ram_addr);
}

uintptr_t se_notdirty_mem_read(target_phys_addr_t ram_addr) {
    uintptr_t ret = (uintptr_t) qemu_get_ram_ptr(ram_addr);
    // g_sqi.log.debug("se_notdirty_mem_read: %llx => %llx\n", ram_addr, ret);
    return ret;
}

/* Some pages might be partially used for DMA. All read accesses outside DMA
   regions in a page go here. */
static uint64_t se_dma_mem_read(target_phys_addr_t ram_addr, unsigned size) {
    switch (size) {
        case 1:
            return ldub_raw(qemu_get_ram_ptr(ram_addr));
        case 2:
            return lduw_raw(qemu_get_ram_ptr(ram_addr));
        case 4:
            return ldl_raw(qemu_get_ram_ptr(ram_addr));
        case 8:
            return ldq_raw(qemu_get_ram_ptr(ram_addr));
    }
    assert(false && "Invalid size");
    return 0;
}

static void se_dma_mem_write(target_phys_addr_t ram_addr, uint64_t val, unsigned size) {
    target_ulong iovaddr = g_sqi.mem.read_mem_io_vaddr(1);
    if (!tlb_is_dirty(cpu_single_env, iovaddr)) {
        notdirty_mem_write(ram_addr, val, size);
        return;
    }
    switch (size) {
        case 1:
            stb_raw(qemu_get_ram_ptr(ram_addr), val);
            break;
        case 2:
            stw_raw(qemu_get_ram_ptr(ram_addr), val);
            break;
        case 4:
            stl_raw(qemu_get_ram_ptr(ram_addr), val);
            break;
        case 8:
            stq_raw(qemu_get_ram_ptr(ram_addr), val);
            break;
        default:
            abort();
    }
}

#endif

#ifdef CONFIG_SYMBEX
static const struct MemoryDescOps se_dma_mem_ops = {
    .read = se_dma_mem_read, .write = se_dma_mem_write,
};

bool se_ismemfunc(const struct MemoryDescOps *ops, int isWrite) {
    if (isWrite) {
        return ops->write == se_dma_mem_ops.write;
    } else {
        return ops->read == se_dma_mem_ops.read;
    }
}

#else

static const struct MemoryDescOps notdirty_mem_ops = {
    .read = error_mem_read, .write = notdirty_mem_write,
};
#endif

static void io_mem_init(void) {
    phys_register_section(phys_section_rom, &rom_mem_ops);
    phys_register_section(phys_section_unassigned, &unassigned_mem_ops);
#ifdef CONFIG_SYMBEX
    phys_register_section(phys_section_notdirty, &se_dma_mem_ops);
#else
    phys_register_section(phys_section_notdirty, &notdirty_mem_ops);
#endif
    phys_register_section(phys_section_watch, &watch_mem_ops);
}

#endif

/* warning: addr must be aligned */
static inline uint32_t ldl_phys_internal(target_phys_addr_t addr) {
    uint8_t *ptr;
    uint32_t val;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        val = cpu_mmio_read(addr, 4);
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr((sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr));
        val = ldl_raw(ptr);
    }

    return val;
}

uint32_t ldl_phys(target_phys_addr_t addr) {
    return ldl_phys_internal(addr);
}

/* warning: addr must be aligned */
static inline uint64_t ldq_phys_internal(target_phys_addr_t addr) {
    uint8_t *ptr;
    uint64_t val;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        /* I/O case */

        /* XXX This is broken when device endian != cpu endian.
               Fix and add "endian" variable check */
        val = cpu_mmio_read(addr, 4);
        val |= cpu_mmio_read(addr + 4, 4) << 32;
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr((sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr));
        val = ldq_raw(ptr);
    }
    return val;
}

uint64_t ldq_phys(target_phys_addr_t addr) {
    return ldq_phys_internal(addr);
}

/* XXX: optimize */
uint32_t ldub_phys(target_phys_addr_t addr) {
    uint8_t val;
    cpu_physical_memory_read(addr, &val, 1);
    return val;
}

/* warning: addr must be aligned */
static inline uint32_t lduw_phys_internal(target_phys_addr_t addr) {
    uint8_t *ptr;
    uint64_t val;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        val = cpu_mmio_read(addr, 2);
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr((sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr));
        val = lduw_raw(ptr);
    }
    return val;
}

uint32_t lduw_phys(target_phys_addr_t addr) {
    return lduw_phys_internal(addr);
}

/* warning: addr must be aligned. The ram page is not masked as dirty
   and the code inside is not invalidated. It is useful if the dirty
   bits are used to track modified PTEs */
void stl_phys_notdirty(target_phys_addr_t addr, uint32_t val) {
    uint8_t *ptr;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        cpu_mmio_write(addr, val, 4);
    } else {
        unsigned long addr1 = (sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr);
        ptr = qemu_get_ram_ptr(addr1);
        stl_raw(ptr, val);
    }
}

/* warning: addr must be aligned */
static inline void stl_phys_internal(target_phys_addr_t addr, uint32_t val) {
    uint8_t *ptr;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        cpu_mmio_write(addr, val, 4);
    } else {
        unsigned long addr1;
        addr1 = (sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr);
        /* RAM case */
        ptr = qemu_get_ram_ptr(addr1);
        stl_raw(ptr, val);

        if (!cpu_physical_memory_is_dirty(addr1)) {
            /* invalidate code */
            tb_invalidate_phys_page_range(addr1, addr1 + 4, 0);
            /* set dirty bit */
            cpu_physical_memory_set_dirty_flags(addr1, (0xff & ~CODE_DIRTY_FLAG));
        }
    }
}

void stl_phys(target_phys_addr_t addr, uint32_t val) {
    stl_phys_internal(addr, val);
}

/* XXX: optimize */
void stb_phys(target_phys_addr_t addr, uint32_t val) {
    uint8_t v = val;
    cpu_physical_memory_write(addr, &v, 1);
}

/* warning: addr must be aligned */
static inline void stw_phys_internal(target_phys_addr_t addr, uint32_t val) {
    uint8_t *ptr;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        cpu_mmio_write(addr, val, 2);
    } else {
        unsigned long addr1;
        addr1 = (sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr);
        /* RAM case */
        ptr = qemu_get_ram_ptr(addr1);
        stw_raw(ptr, val);
        if (!cpu_physical_memory_is_dirty(addr1)) {
            /* invalidate code */
            tb_invalidate_phys_page_range(addr1, addr1 + 2, 0);
            /* set dirty bit */
            cpu_physical_memory_set_dirty_flags(addr1, (0xff & ~CODE_DIRTY_FLAG));
        }
    }
}

void stw_phys(target_phys_addr_t addr, uint32_t val) {
    stw_phys_internal(addr, val);
}

/* XXX: optimize */
void stq_phys(target_phys_addr_t addr, uint64_t val) {
    val = tswap64(val);
    cpu_physical_memory_write(addr, &val, 8);
}

void stq_le_phys(target_phys_addr_t addr, uint64_t val) {
    val = cpu_to_le64(val);
    cpu_physical_memory_write(addr, &val, 8);
}

void stq_be_phys(target_phys_addr_t addr, uint64_t val) {
    val = cpu_to_be64(val);
    cpu_physical_memory_write(addr, &val, 8);
}

/* NOTE: this function can trigger an exception */
/* NOTE2: the returned address is not exactly the physical address: it
   is the offset relative to phys_ram_base */
tb_page_addr_t get_page_addr_code(CPUArchState *env1, target_ulong addr) {
	//FIXME
	if(addr > 0xffff0000 && addr <= 0xffff1000) {
		fprintf(stderr,"%s: FIXME addr=%x\n",__FUNCTION__,addr);
		return (tb_page_addr_t)addr;
	}
    int mmu_idx, page_index, pd;
    void *p;
    page_index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = cpu_mmu_index(env1);

    if (unlikely(tlb_table[mmu_idx][page_index].addr_code != (addr & TARGET_PAGE_MASK))) {

#ifdef CONFIG_TCG_PASS_AREG0
        cpu_ldub_code(env1, addr);
#else
        	ldub_code(addr);
#endif
    }
    pd = iotlb[mmu_idx][page_index] & ~TARGET_PAGE_MASK;
#ifndef CONFIG_USER_KVM
    if (!mem_desc_find(pd)) {
#if defined(TARGET_ALPHA) || defined(TARGET_MIPS) || defined(TARGET_SPARC)
        cpu_unassigned_access(env1, addr, 0, 1, 0, 4);
#else
        cpu_abort(env1, "Trying to execute code outside RAM or ROM at 0x" TARGET_FMT_lx "\n", addr);
#endif
    }
#endif
    p = (void *) ((uintptr_t) addr + tlb_table[mmu_idx][page_index].addend);

    tb_page_addr_t ram_addr = qemu_ram_addr_from_host_nofail(p);
	
	return ram_addr;
}
#ifdef CONFIG_USER_KVM
int page_get_flags(target_ulong address)
{
    PageDesc *p;
	tb_page_addr_t address_new;
	address_new = qemu_ram_addr_from_host_nofail(g2h(address));
	p = page_find(address_new >> TARGET_PAGE_BITS);
    if (!p)
        return 0;
    return p->flags;
}

/* Modify the flags of a page and invalidate the code if necessary.
   The flag PAGE_WRITE_ORG is positioned automatically depending
   on PAGE_WRITE.  The mmap_lock should already be held.  */
void page_set_flags(target_ulong start, target_ulong end, int flags)
{

    /* This function should never be called with addresses outside the
       guest address space.  If this assert fires, it probably indicates
       a missing call to h2g_valid.  */
	tb_page_addr_t addr_new;
	target_ulong addr, len;
#if TARGET_ABI_BITS > L1_MAP_ADDR_SPACE_BITS
    assert(end < ((abi_ulong)1 << L1_MAP_ADDR_SPACE_BITS));
#endif
    assert(start < end);
  	start = start & TARGET_PAGE_MASK;
    	end = TARGET_PAGE_ALIGN(end);

    if (flags & PAGE_WRITE) {
        flags |= PAGE_WRITE_ORG;
    }

    for (addr = start, len = end - start;
         len != 0;
         len -= TARGET_PAGE_SIZE, addr += TARGET_PAGE_SIZE) {
	        addr_new = qemu_ram_addr_from_host_nofail(g2h(addr));
            PageDesc *p = page_find_alloc(addr_new >> TARGET_PAGE_BITS, 1);

        /* If the write protection bit is set, then we invalidate
           the code inside.  */
        if (!(p->flags & PAGE_WRITE) &&
            (flags & PAGE_WRITE) &&
            p->first_tb) {
                tb_invalidate_phys_page(addr_new, 0, NULL);
        }
        p->flags = flags;
    }
}

int page_check_range(target_ulong start, target_ulong len, int flags)
{
    PageDesc *p;
    tb_page_addr_t addr_new;
    target_ulong end;
    target_ulong addr;
    /* This function should never be called with addresses outside the
       guest address space.  If this assert fires, it probably indicates
       a missing call to h2g_valid.  */
#if TARGET_ABI_BITS > L1_MAP_ADDR_SPACE_BITS
    assert(start < ((abi_ulong)1 << L1_MAP_ADDR_SPACE_BITS));
#endif

    if (len == 0) {
        return 0;
    }

    if (start + len - 1 < start) {
        /* We've wrapped around.  */
        return -1;
    }

    end = TARGET_PAGE_ALIGN(start+len); /* must do before we loose bits in the next step */
    start = start & TARGET_PAGE_MASK;

    for (addr = start, len = end - start;
         len != 0;
         len -= TARGET_PAGE_SIZE, addr += TARGET_PAGE_SIZE) {
	     addr_new = qemu_ram_addr_from_host_nofail(g2h(addr));
         p = page_find(addr_new >> TARGET_PAGE_BITS);
        if( !p )
            return -1;
        if( !(p->flags & PAGE_VALID) )
            return -1;

        if ((flags & PAGE_READ) && !(p->flags & PAGE_READ))
            return -1;
        if (flags & PAGE_WRITE) {
            if (!(p->flags & PAGE_WRITE_ORG))
                return -1;
            /* unprotect the page if it was put read-only because it
               contains translated code */
            if (!(p->flags & PAGE_WRITE)) {
                if (!page_unprotect(addr, 0, NULL))
                    return -1;
            }
            return 0;
        }
    }
    return 0;
}

/* called from signal handler: invalidate the code and unprotect the
   page. Return TRUE if the fault was successfully handled. */
int page_unprotect(target_ulong address, uintptr_t pc, void *puc)
{
    unsigned int prot;
    PageDesc *p;
    target_ulong host_start, host_end, addr;
	tb_page_addr_t address_new, addr_new;
	address_new = qemu_ram_addr_from_host_nofail(g2h(address));
    /* Technically this isn't safe inside a signal handler.  However we
       know this only ever happens in a synchronous SEGV handler, so in
       practice it seems to be ok.  */
    mmap_lock();
      p = page_find(address_new >> TARGET_PAGE_BITS);
    if (!p) {
        mmap_unlock();
        return 0;
    }

    /* if the page was really writable, then we change its
       protection back to writable */
    if ((p->flags & PAGE_WRITE_ORG) && !(p->flags & PAGE_WRITE)) {
        host_start = address & qemu_host_page_mask;
        host_end = host_start + qemu_host_page_size;

        prot = 0;
        for (addr = host_start ; addr < host_end ; addr += TARGET_PAGE_SIZE) {
	    addr_new = qemu_ram_addr_from_host_nofail(g2h(addr));
            p = page_find(addr_new >> TARGET_PAGE_BITS);
            p->flags |= PAGE_WRITE;
            prot |= p->flags;

            /* and since the content will be modified, we must invalidate
               the corresponding translated code. */
            	tb_invalidate_phys_page(addr_new, pc, puc);
#ifdef DEBUG_TB_CHECK
            tb_invalidate_check(addr);
#endif
        }
        mprotect((void *)g2h(host_start), qemu_host_page_size,
                 prot & PAGE_BITS);

        mmap_unlock();
        return 1;
    }
    mmap_unlock();
    return 0;
}
#endif /* defined(CONFIG_USER_ONLY) */


#define MMUSUFFIX _cmmu
#undef GETPC
#define GETPC() NULL
#define env cpu_single_env
#define SOFTMMU_CODE_ACCESS

#define SHIFT 0
#include "softmmu_template.h"

#define SHIFT 1
#include "softmmu_template.h"

#define SHIFT 2
#include "softmmu_template.h"

#define SHIFT 3
#include "softmmu_template.h"

#undef env
