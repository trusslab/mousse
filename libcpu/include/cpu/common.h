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

#ifndef __LIBCPU_COMMON_H__

#define __LIBCPU_COMMON_H__

#include <cpu/tb.h>
#include <cpu/tlb.h>
#include <cpu/types.h>
#include <qqueue.h>
#include <setjmp.h>
#include <signal.h>

typedef struct CPUBreakpoint {
    target_ulong pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

typedef struct CPUWatchpoint {
    target_ulong vaddr;
    target_ulong len_mask;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
} CPUWatchpoint;
#ifdef HOST_WORDS_BIGENDIAN
typedef struct icount_decr_u16 {
    uint16_t high;
    uint16_t low;
} icount_decr_u16;
#else
typedef struct icount_decr_u16 {
    uint16_t low;
    uint16_t high;
} icount_decr_u16;
#endif
#define CPU_TEMP_BUF_NLONGS 128
/* We maintain one global TLB for all threads in UserMode*/
#include <cpu/arm/defs.h>
//extern CPU_COMMON_TLB                                                                                  
extern CPUTLBEntry tlb_table[NB_MMU_MODES][CPU_TLB_SIZE];                
extern target_phys_addr_t iotlb[NB_MMU_MODES][CPU_TLB_SIZE];             
#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
extern target_phys_addr_t iotlb_ramaddr[NB_MMU_MODES][CPU_TLB_SIZE];
#endif
extern target_ulong tlb_flush_addr;                                      
extern target_ulong tlb_flush_mask;
//extern CPU_COMMON_PHYSRAM_TLB                                                                            
#if defined(SE_ENABLE_PHYSRAM_TLB)
extern CPUTLBRAMEntry se_ram_tlb[CPU_TLB_SIZE];
#endif
extern CPUTLBEntry *se_tlb_current;                                                                   

#define CPU_COMMON                                                                                    \
    int se_common_start;                    /* Dummy variable to mark the start of the common area */ \
    struct TranslationBlock *current_tb;    /* currently executing TB  */                             \
    struct TranslationBlock *se_current_tb; /* currently executing TB  */                             \
    /* soft mmu support */                                                                            \
    /* in order to avoid passing too many arguments to the MMIO                                       \
       helpers, we store some rarely used information in the CPU                                      \
       context) */                                                                                    \
    unsigned long mem_io_pc;   /* host pc at which the memory was                                     \
                                  accessed */                                                         \
    target_ulong mem_io_vaddr; /* target virtual addr at which the                                    \
                                     memory was accessed */                                           \
    uint32_t halted;           /* Nonzero if the CPU is in suspend state */                           \
    uint32_t interrupt_request;                                                                       \
    volatile sig_atomic_t exit_request;                                                               \
    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];                                         \
    /* buffer for temporaries in the code generator */                                                \
    long temp_buf[CPU_TEMP_BUF_NLONGS];                                                               \
    int64_t icount_extra; /* Instructions until next timer event.  */   \
    /* Number of cycles left, with interrupt flag in high bit.          \
       This allows a single read-compare-cbranch-write sequence to test \
       for both decrementer underflow and exceptions.  */               \
    union {                                                             \
        uint32_t u32;                                                   \
        icount_decr_u16 u16;                                            \
    } icount_decr;                                                      \
    uint32_t can_do_io; /* nonzero if memory mapped IO is safe.  */     \
    /* Used to handle self-modifying code */                                                          \
    unsigned restored_instruction_size;                                                               \
                                                                                                      \
    /* from this point: preserved by CPU reset */                                                     \
    /* ice debug support */                                                                           \
    QTAILQ_HEAD(breakpoints_head, CPUBreakpoint) breakpoints;                                         \
    int singlestep_enabled;                                                                           \
                                                                                                      \
    QTAILQ_HEAD(watchpoints_head, CPUWatchpoint) watchpoints;                                         \
    CPUWatchpoint *watchpoint_hit;                                                                    \
                                                                                                      \
    /* Core interrupt code */                                                                         \
    jmp_buf jmp_env;                                                                                  \
    int exception_index;                                                                              \
                                                                                                      \
    CPUArchState *next_cpu; /* next CPU sharing TB cache */                                           \
    int cpu_index;          /* CPU index (informative) */                                             \
    uint32_t host_tid; /* host thread ID */                             				\
    int numa_node;          /* NUMA node this cpu is belonging to  */                                 \
    int nr_cores;           /* number of cores within this CPU package */                             \
    int nr_threads;         /* number of threads within this CPU */                                   \
    int running;            /* Nonzero if cpu is currently running(usermode).  */                                \
    /* user data */                                                                                   \
    int thread_id;                                                      \
    void *opaque;                                                                                     \
    unsigned size; /* Size of this structure */                                                       \
                                                                                                      \
    uint32_t created;                                                                                 \
    uint32_t stop; /* Stop request */                                                                 \
    const char *cpu_model_str;                                                                        \
    int se_common_end; /* Dummy variable to mark the end of the common area */

#endif
