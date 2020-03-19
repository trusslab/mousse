/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017  Adrian Herrera
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

#ifndef __LIBCPU_ARM_CPU_H__
#define __LIBCPU_ARM_CPU_H__

#include <stdbool.h>

#include <cpu/common.h>
#include <cpu/interrupt.h>
#include <cpu/types.h>
#include <fpu/softfloat.h>

#define CPUArchState struct CPUARMState

#include "defs.h"
#if defined(CONFIG_USE_NPTL)
#define THREAD __thread
#else
#define THREAD
#endif
typedef void ARMWriteCPFunc(void *opaque, int cp_info, int srcreg, int operand, uint32_t value);
typedef uint32_t ARMReadCPFunc(void *opaque, int cp_info, int dstreg, int operand);

/*
 * We currently assume float and double are IEEE single and double precision respectively. Doing runtime conversions is
 * tricky because VFP registers may contain integer values (eg. as the result of a FTOSI instruction).
 *
 * s<2n> maps to the least significant half of d<n>
 * s<2n+1> maps to the most significant half of d<n>
 */

typedef struct CPUARMState {
    uint32_t spsr;

    /* Banked registers.  */
    uint32_t banked_spsr[6];
    uint32_t banked_r13[6];
    uint32_t banked_r14[6];

    /* These hold r8-r12.  */
    uint32_t usr_regs[5];
    uint32_t fiq_regs[5];

    /* cpsr flag cache for faster execution */
    uint32_t CF; /* 0 or 1 */
    uint32_t VF; /* V is the bit 31. All other bits are undefined */
    uint32_t NF; /* N is bit 31. All other bits are undefined.  */
    uint32_t ZF; /* Z set if zero.  */
    uint32_t GE;            /* cpsr[19:16] */

    /*
     * Regs for current mode.
     *
     * regs[15] is the border between concrete and symbolic area, i.e., regs[15] is in concrete-only-area
     */
    uint32_t regs[16];
    uint32_t tlb_table_addr;

    uint32_t QF;            /* 0 or 1 */
    uint32_t thumb;         /* cpsr[5]. 0 = arm mode, 1 = thumb mode. */
    uint32_t condexec_bits; /* IT bits.  cpsr[15:10,26:25].  */

    /*
     * Frequently accessed CPSR bits are stored separately for efficiently. This contains all the other bits. Use
     * cpsr_{read,write} to access the whole CPSR.
     */
    uint32_t uncached_cpsr;

    /* System control coprocessor (cp15) */
    struct {
        uint32_t c0_cpuid;
        uint32_t c0_cachetype;
        uint32_t c0_ccsid[16];   /* Cache size.  */
        uint32_t c0_clid;        /* Cache level.  */
        uint32_t c0_cssel;       /* Cache size selection.  */
        uint32_t c0_c1[8];       /* Feature registers.  */
        uint32_t c0_c2[8];       /* Instruction set registers.  */
        uint32_t c1_sys;         /* System control register.  */
        uint32_t c1_coproc;      /* Coprocessor access register.  */
        uint32_t c1_xscaleauxcr; /* XScale auxiliary control register.  */
        uint32_t c1_scr;         /* secure config register.  */
        uint32_t c2_base0;       /* MMU translation table base 0.  */
//copied from qemu
        uint32_t c2_base0_hi; /* MMU translation table base 0, high 32 bits */
        uint32_t c2_base1;       /* MMU translation table base 1.  */
//copied from qemu
        uint32_t c2_base1_hi; /* MMU translation table base 1, high 32 bits */
        uint32_t c2_control;     /* MMU translation table base control.  */
        uint32_t c2_mask;        /* MMU translation table base selection mask.  */
        uint32_t c2_base_mask;   /* MMU translation table base 0 mask. */
        uint32_t c2_data;        /* MPU data cachable bits.  */
        uint32_t c2_insn;        /* MPU instruction cachable bits.  */
        uint32_t c3;             /* MMU domain access control register
                                    MPU write buffer control.  */
        uint32_t c5_insn;        /* Fault status registers.  */
        uint32_t c5_data;
        uint32_t c6_region[8]; /* MPU base/size registers.  */
        uint32_t c6_insn;      /* Fault address registers.  */
        uint32_t c6_data;
        uint32_t c7_par;  /* Translation result. */
        uint32_t c9_insn; /* Cache lockdown registers.  */
        uint32_t c9_data;
        uint32_t c9_pmcr;                 /* performance monitor control register */
        uint32_t c9_pmcnten;              /* perf monitor counter enables */
        uint32_t c9_pmovsr;               /* perf monitor overflow status */
        uint32_t c9_pmxevtyper;           /* perf monitor event type */
        uint32_t c9_pmuserenr;            /* perf monitor user enable */
        uint32_t c9_pminten;              /* perf monitor interrupt enables */
        uint32_t c13_fcse;                /* FCSE PID.  */
        uint32_t c13_context;             /* Context ID.  */
        uint32_t c13_tls1;                /* User RW Thread register.  */
        uint32_t c13_tls2;                /* User RO Thread register.  */
        uint32_t c13_tls3;                /* Privileged Thread register.  */
        uint32_t c15_cpar;                /* XScale Coprocessor Access Register */
        uint32_t c15_ticonfig;            /* TI925T configuration byte.  */
        uint32_t c15_i_max;               /* Maximum D-cache dirty line index.  */
        uint32_t c15_i_min;               /* Minimum D-cache dirty line index.  */
        uint32_t c15_threadid;            /* TI debugger thread-ID.  */
        uint32_t c15_config_base_address; /* SCU base address.  */
        uint32_t c15_diagnostic;          /* diagnostic register */
        uint32_t c15_power_diagnostic;
        uint32_t c15_power_control; /* power control */
    } cp15;

    struct {
        uint32_t other_sp;
        uint32_t vecbase;
        uint32_t basepri;
        uint32_t control;
        int current_sp;
        int exception;
        int pending_exception;
    } v7m;

    /* Thumb-2 EE state.  */
    uint32_t teecr;
    uint32_t teehbr;

    /* Internal CPU feature flags.  */
    uint32_t features;

    /* VFP coprocessor state.  */
    struct {
        float64 regs[32];

        uint32_t xregs[16];
        /* We store these fpcsr fields separately for convenience.  */
        int vec_len;
        int vec_stride;

        /* scratch space when Tn are not sufficient.  */
        uint32_t scratch[8];

        /* fp_status is the "normal" fp status. standard_fp_status retains
         * values corresponding to the ARM "Standard FPSCR Value", ie
         * default-NaN, flush-to-zero, round-to-nearest and is used by
         * any operations (generally Neon) which the architecture defines
         * as controlled by the standard FPSCR value rather than the FPSCR.
         *
         * To avoid having to transfer exception bits around, we simply
         * say that the FPSCR cumulative exception flags are the logical
         * OR of the flags in the two fp statuses. This relies on the
         * only thing which needs to read the exception flags being
         * an explicit FPSCR read.
         */
        float_status fp_status;
        float_status standard_fp_status;
    } vfp;
    uint32_t exclusive_addr;
    uint32_t exclusive_val;
    uint32_t exclusive_high;
#ifdef CONFIG_USER_KVM
    uint32_t exclusive_test;
    uint32_t exclusive_info;
#endif
    /* iwMMXt coprocessor state.  */
    struct {
        uint64_t regs[16];
        uint64_t val;

        uint32_t cregs[16];
    } iwmmxt;

    /* For mixed endian mode.  */
    bool bswap_code;
#ifdef CONFIG_USER_KVM
    int eabi;
#endif
    CPU_COMMON

    /* These fields after the common ones so they are preserved on reset.  */

    /* Coprocessor IO used by peripherals */
    struct {
        ARMReadCPFunc *cp_read;
        ARMWriteCPFunc *cp_write;
        void *opaque;
    } cp[15];
    void *nvic;
    const struct arm_boot_info *boot_info;

    /* For KVM */
    int kvm_request_interrupt_window;
    int kvm_irq;
} CPUARMState;

/* copied from libcpu/target-arm/cpu.h */
#define CPSR_M (0x1f)
enum arm_cpu_mode {
    ARM_CPU_MODE_USR = 0x10,
    ARM_CPU_MODE_FIQ = 0x11,
    ARM_CPU_MODE_IRQ = 0x12,
    ARM_CPU_MODE_SVC = 0x13,
    ARM_CPU_MODE_ABT = 0x17,
    ARM_CPU_MODE_UND = 0x1b,
    ARM_CPU_MODE_SYS = 0x1f
};
static inline int cpu_mmu_index(CPUARMState *env) {
    return (env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_USR ? 1 : 0;
}
CPUARMState *cpu_arm_init(const char *cpu_model);
#ifdef CONFIG_USER_KVM
void cpu_parse_opaque(const CPUARMState *env);	
void process_cpu_arm_exec(CPUARMState *env);
void clone_process_cpu_arm_exec(CPUARMState *env);
#endif
static inline void cpu_clone_regs(CPUARMState *env, target_ulong newsp)
{
    if (newsp)
        env->regs[13] = newsp;
    env->regs[0] = 0;
}
#endif
