/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017  Adrian Herrera
/// Copyright (C) 2020, TrussLab@University of California, Irvine. 
///    Authors: Yingtong Liu <yingtong@uci.edu> 
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

#include "cpu-defs.h"
#include "cpu.h"
#include "dyngen-exec.h"
#include "helper.h"
#include "host-utils.h"
#include <s2e/s2e_libcpu_coreplugin.h>
#include <cpu/se_libcpu.h>

#define SIGNBIT (uint32_t) 0x80000000
#define SIGNBIT64 ((uint64_t) 1 << 63)

#ifdef SYMBEX_LLVM_LIB
//#include "llvm-lib.h"
#endif

THREAD CPUArchState *env = 0;

static void raise_exception(int tt) {
	fprintf(stderr, "%s [1]: env->exception_index = %d\n",__FUNCTION__, tt);
    env->exception_index = tt;
    cpu_loop_exit(env);
}
void helper_wrmsr_v(target_ulong index, uint64_t val) {
	assert(false && "helper_wrmsr_v failed\n");
}
uint32_t HELPER(neon_tbl)(uint32_t ireg, uint32_t def, uint32_t rn, uint32_t maxindex) {
    uint32_t val;
    uint32_t tmp;
    int index;
    int shift;
    uint64_t *table;
    table = (uint64_t *) &env->vfp.regs[rn];
    val = 0;
    for (shift = 0; shift < 32; shift += 8) {
        index = (ireg >> shift) & 0xff;
        if (index < maxindex) {
            tmp = (table[index >> 3] >> ((index & 7) << 3)) & 0xff;
            val |= tmp << shift;
        } else {
            val |= def & (0xff << shift);
        }
    }
    return val;
}

#include "softmmu_exec.h"

#define MMUSUFFIX _mmu

#define SHIFT 0
#include "softmmu_template.h"

#define SHIFT 1
#include "softmmu_template.h"

#define SHIFT 2
#include "softmmu_template.h"

#define SHIFT 3
#include "softmmu_template.h"

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
#undef MMUSUFFIX
#define MMUSUFFIX _mmu_symb
#define _raw _raw_symb

#define SHIFT 0
//#include "softmmu_header.h"
#include "softmmu_template.h"

#define SHIFT 1
//#include "softmmu_header.h"
#include "softmmu_template.h"

#define SHIFT 2
//#include "softmmu_header.h"
#include "softmmu_template.h"

#define SHIFT 3
//#include "softmmu_header.h"
#include "softmmu_template.h"

#undef _raw
#endif

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
void se_do_interrupt_arm() {
//user mode
	env->exception_index = -1;
	return;
}

/* This will be called from S2EExecutor if running concretely; It will
   in turn call the real ARM IRQ handler with current CPUARMState.*/
void s2e_do_interrupt(void) {
	assert(false && "s2e_do_interrupt failed\n");
}
#endif
#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
void helper_load_seg(int seg_reg, int selector) {
	assert(false && "helper_load_seg failed\n");
}
void helper_iret_protected(int shift, int next_eip) {
	assert(false && "helper_load_seg failed\n");
}
void helper_register_symbols() {
    g_sqi.exec.helper_register_symbol("helper_load_seg", helper_load_seg);
    g_sqi.exec.helper_register_symbol("helper_iret_protected", helper_iret_protected);
}
#endif

/* try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUArchState *env1, target_ulong addr, target_ulong page_addr, int is_write, int mmu_idx, void *retaddr) {
    TranslationBlock *tb;
    CPUArchState *saved_env;
    unsigned long pc;
    int ret;

    saved_env = env;

    if (env != env1)
        env = env1;

#ifdef CONFIG_SYMBEX
    //s2e_on_tlb_miss(g_s2e, g_s2e_state, addr, is_write);
    if (unlikely(*g_sqi.events.on_tlb_miss_signals_count)) {
        g_sqi.events.on_tlb_miss(addr, is_write, retaddr);
    }
    ret = cpu_arm_handle_mmu_fault(env, page_addr, is_write, mmu_idx);
#else
    ret = cpu_arm_handle_mmu_fault(env, addr, is_write, mmu_idx);
#endif

    if (unlikely(ret)) {

#ifdef CONFIG_SYMBEX
        /* In S2E we pass page address instead of addr to cpu_arm_handle_mmu_fault,
           since the latter can be symbolic while the former is always concrete.
           To compensate, we reset fault address here. */
        if (env->exception_index == EXCP_PREFETCH_ABORT || env->exception_index == EXCP_DATA_ABORT) {
            assert(1 && "handle coprocessor exception properly");
        }
#endif

        if (retaddr) {
            /* now we have a real cpu fault */
            pc = (uintptr_t) retaddr;
            tb = tb_find_pc(pc);
            if (tb) {
                /* the PC is inside the translated code. It means that we have
                   a virtual CPU fault */
                cpu_restore_state(tb, env, pc);
            }
        }

#ifdef CONFIG_SYMBEX
//        s2e_on_page_fault(g_s2e, g_s2e_state, addr, is_write);
        if (unlikely(*g_sqi.events.on_page_fault_signals_count)) {
            g_sqi.events.on_page_fault(addr, is_write, retaddr);
        }
#endif
        raise_exception(env->exception_index);
    }
    if (saved_env != env)
        env = saved_env;
}

//FIXME
#ifdef SYMBEX_LLVM_LIB
//A bogus function never being used. To avoid "can't get tcg_llvm_get_value, tcg_llvm_trace_port_access functions in LLVM Module" assertion.
//See S2EExecutor.cpp and tcg-llvm.cpp
uint32_t helper_test(uint32_t port) {
    if (*g_sqi.mode.concretize_io_addresses) {
        tcg_llvm_get_value(&port, sizeof(port), false);
    }

    return tcg_llvm_trace_port_access(port, 0, 8, 0);
}
#endif

/* FIXME: Pass an axplicit pointer to QF to CPUARMState, and move saturating
   instructions into helper.c  */
uint32_t HELPER(add_setq)(uint32_t a, uint32_t b) {
    uint32_t res = a + b;
    if (((res ^ a) & SIGNBIT) && !((a ^ b) & SIGNBIT))
        env->QF = 1;
    return res;
}

uint32_t HELPER(add_saturate)(uint32_t a, uint32_t b) {
    uint32_t res = a + b;
    if (((res ^ a) & SIGNBIT) && !((a ^ b) & SIGNBIT)) {
        env->QF = 1;
        res = ~(((int32_t) a >> 31) ^ SIGNBIT);
    }
    return res;
}

uint32_t HELPER(sub_saturate)(uint32_t a, uint32_t b) {
    uint32_t res = a - b;
    if (((res ^ a) & SIGNBIT) && ((a ^ b) & SIGNBIT)) {
        env->QF = 1;
        res = ~(((int32_t) a >> 31) ^ SIGNBIT);
    }
    return res;
}

uint32_t HELPER(double_saturate)(int32_t val) {
    uint32_t res;
    if (val >= 0x40000000) {
        res = ~SIGNBIT;
        env->QF = 1;
    } else if (val <= (int32_t) 0xc0000000) {
        res = SIGNBIT;
        env->QF = 1;
    } else {
        res = val << 1;
    }
    return res;
}

uint32_t HELPER(add_usaturate)(uint32_t a, uint32_t b) {
    uint32_t res = a + b;
    if (res < a) {
        env->QF = 1;
        res = ~0;
    }
    return res;
}

uint32_t HELPER(sub_usaturate)(uint32_t a, uint32_t b) {
    uint32_t res = a - b;
    if (res > a) {
        env->QF = 1;
        res = 0;
    }
    return res;
}

/* Signed saturation.  */
static inline uint32_t do_ssat(int32_t val, int shift) {
    int32_t top;
    uint32_t mask;

    top = val >> shift;
    mask = (1u << shift) - 1;
    if (top > 0) {
        env->QF = 1;
        return mask;
    } else if (top < -1) {
        env->QF = 1;
        return ~mask;
    }
    return val;
}

/* Unsigned saturation.  */
static inline uint32_t do_usat(int32_t val, int shift) {
    uint32_t max;

    max = (1u << shift) - 1;
    if (val < 0) {
        env->QF = 1;
        return 0;
    } else if (val > max) {
        env->QF = 1;
        return max;
    }
    return val;
}

/* Signed saturate.  */
uint32_t HELPER(ssat)(uint32_t x, uint32_t shift) {
    return do_ssat(x, shift);
}

/* Dual halfword signed saturate.  */
uint32_t HELPER(ssat16)(uint32_t x, uint32_t shift) {
    uint32_t res;

    res = (uint16_t) do_ssat((int16_t) x, shift);
    res |= do_ssat(((int32_t) x) >> 16, shift) << 16;
    return res;
}

/* Unsigned saturate.  */
uint32_t HELPER(usat)(uint32_t x, uint32_t shift) {
    return do_usat(x, shift);
}

/* Dual halfword unsigned saturate.  */
uint32_t HELPER(usat16)(uint32_t x, uint32_t shift) {
    uint32_t res;

    res = (uint16_t) do_usat((int16_t) x, shift);
    res |= do_usat(((int32_t) x) >> 16, shift) << 16;
    return res;
}

void HELPER(wfi)(void) {
    env->exception_index = EXCP_HLT;
    env->halted = 1;
    cpu_loop_exit(env);
}

#ifdef SYMBEX_LLVM_LIB
#define SYSCALL_NUM_MAX 378
static uint8_t syscall_reg_mask[SYSCALL_NUM_MAX] = {
    0, 1, 0, 7, 7, 7, 1, 0, 3, 3,
    1, 7, 1, 1, 7, 3, 7, 0, 0, 7,
    0, 31, 3, 1, 0, 1, 15, 1, 0, 0,
    3, 0, 0, 3, 1, 0, 0, 3, 3, 3,
    1, 1, 1, 1, 0, 1, 1, 0, 0, 0,
    0, 1, 3, 0, 7, 7, 0, 3, 0, 0,
    1, 1, 3, 3, 0, 0, 0, 7, 0, 0,
    3, 3, 7, 1, 3, 3, 3, 3, 3, 3,
    3, 3, 31, 3, 0, 7, 1, 3, 15, 7,
    1, 3, 3, 3, 3, 7, 3, 7, 0, 3,
    3, 0, 3, 7, 7, 3, 3, 3, 3, 0,
    0, 0, 0, 0, 15, 1, 1, 63, 1, 0,
    31, 3, 1, 0, 1, 7, 7, 0, 7, 3,
    0, 15, 1, 1, 3, 7, 1, 0, 1, 1,
    31, 7, 31, 3, 7, 7, 7, 1, 1, 1,
    3, 3, 1, 0, 3, 3, 7, 1, 0, 1,
    1, 3, 3, 31, 7, 7, 0, 0, 7, 0,
    7, 7, 31, 0, 15, 15, 3, 15, 7, 3,
    3, 3, 7, 3, 3, 3, 0, 15, 0, 0,
    0, 3, 63, 1, 1, 3, 3, 3, 7, 0,
    0, 0, 0, 3, 3, 3, 3, 7, 7, 7,
    7, 7, 7, 1, 1, 1, 1, 7, 3, 7,
    7, 7, 0, 0, 0, 1, 31, 31, 31, 15,
    15, 15, 7, 7, 7, 3, 3, 3, 3, 15,
    63, 7, 7, 3, 1, 31, 7, 7, 1, 1,
    1, 15, 15, 31, 0, 0, 1, 7, 15, 3,
    1, 1, 3, 3, 3, 15, 7, 7, 7, 3,
    15, 0, 31, 31, 15, 1, 31, 31, 3, 7,
    31, 7, 7, 7, 3, 7, 7, 7, 15, 15,
    63, 15, 63, 3, 31, 31, 7, 7, 7, 7,
    3, 15, 31, 3, 7, 7, 1, 7, 7, 31,
    15, 31, 15, 0, 7, 3, 0, 7, 3, 63,
    31, 7, 15, 7, 15, 31, 7, 15, 7, 15,
    31, 7, 15, 7, 7, 63, 31, 1, 3, 7,
    63, 3, 15, 15, 63, 7, 63, 15, 15, 7,
    3, 1, 3, 15, 3, 15, 3, 1, 7, 3,
    1, 31, 31, 15, 31, 31, 15, 3, 3, 15,
    31, 7, 3, 1, 15, 3, 63, 63
};
#endif
void HELPER(exception)(uint32_t excp) {
    env->exception_index = excp;
#ifdef SYMBEX_LLVM_LIB
    if (excp == EXCP_SWI) {
        int reg_mask_exist = (env->regs[7] < SYSCALL_NUM_MAX);
        int reg_mask = reg_mask_exist? syscall_reg_mask[env->regs[7]] : 0;
        g_sqi.events.on_concretize_syscall_args(1, reg_mask, 0);
        if (reg_mask_exist) {
            int reg;
            for (reg = 0; reg < 8; reg++ ) {
                if (reg_mask & (1 << reg)) {
                    evaluate_value_for_reg("externalSyscall", env, reg, env->regs[reg]);
                } else {
                    break;
                }
            }
        } else {
            evaluate_values_for_regs("externalSyscall",env, env->regs[0], env->regs[1],
                                     env->regs[2], env->regs[3], env->regs[4],
                                     env->regs[5], env->regs[6], env->regs[7]);
        }
    }
    if (excp == EXCP_STREX) {
        uint8_t size = env->exclusive_info & 0xf;
        uint8_t rd = (env->exclusive_info >> 4) & 0xf;
        uint8_t rt = (env->exclusive_info >> 8) & 0xf;
        evaluate_value_for_reg("null", env, rd, env->regs[rd]);
        evaluate_value_for_reg("null", env, rt, env->regs[rt]);
        if (size == 3) {
            uint8_t rt2 = (env->exclusive_info >> 12) & 0xf;
            evaluate_value_for_reg("null", env, rt2, env->regs[rt2]);
        }
    }
#endif
    cpu_loop_exit(env);
}

uint32_t HELPER(cpsr_read)(void) {
    return cpsr_read(env) & ~CPSR_EXEC;
}

void HELPER(cpsr_write)(uint32_t val, uint32_t mask) {
    cpsr_write(env, val, mask);
}

/* Access to user mode registers from privileged modes.  */
uint32_t HELPER(get_user_reg)(uint32_t regno) {
    uint32_t val;

    if (regno == 13) {
        val = RR_cpu(env, banked_r13[0]);
    } else if (regno == 14) {
        val = RR_cpu(env, banked_r14[0]);
    } else if (regno == 15) {
        val = env->regs[regno];
    } else if (regno >= 8 && (env->uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        val = RR_cpu(env, usr_regs[regno - 8]);
    } else {
        val = RR_cpu(env, regs[regno]);
    }
    return val;
}

void HELPER(set_user_reg)(uint32_t regno, uint32_t val) {
    if (regno == 13) {
        WR_cpu(env, banked_r13[0], val);
    } else if (regno == 14) {
        WR_cpu(env, banked_r14[0], val);
    } else if (regno == 15) {
        env->regs[regno] = val;
    } else if (regno >= 8 && (env->uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        WR_cpu(env, usr_regs[regno - 8], val);
    } else {
        WR_cpu(env, regs[regno], val);
    }
}

/* ??? Flag setting arithmetic is awkward because we need to do comparisons.
   The only way to do that in TCG is a conditional branch, which clobbers
   all our temporaries.  For now implement these as helper functions.  */

uint32_t HELPER(add_cc)(uint32_t a, uint32_t b) {
    uint32_t result;
    result = a + b;
    WR_cpu(env, NF, result);
    WR_cpu(env, ZF, result);
    WR_cpu(env, CF, (result < a));
    WR_cpu(env, VF, ((a ^ b ^ -1) & (a ^ result)));
    return result;
}

uint32_t HELPER(adc_cc)(uint32_t a, uint32_t b) {
    uint32_t result;
    if (!(RR_cpu(env, CF))) {
        result = a + b;
        WR_cpu(env, CF, (result < a));
    } else {
        result = a + b + 1;
        WR_cpu(env, CF, (result <= a));
    }
    WR_cpu(env, VF, ((a ^ b ^ -1) & (a ^ result)));
    WR_cpu(env, NF, result);
    WR_cpu(env, ZF, result);
    return result;
}

uint32_t HELPER(sub_cc)(uint32_t a, uint32_t b) {
    uint32_t result;
    result = a - b;

    WR_cpu(env, NF, result);
    WR_cpu(env, ZF, result);
    WR_cpu(env, CF, (a >= b));
    WR_cpu(env, VF, ((a ^ b) & (a ^ result)));
    return result;
}

uint32_t HELPER(sbc_cc)(uint32_t a, uint32_t b) {
    uint32_t result;
    if (!(RR_cpu(env, CF))) {
        result = a - b - 1;
        WR_cpu(env, CF, (a > b));
    } else {
        result = a - b;
        WR_cpu(env, CF, (a >= b));
    }
    WR_cpu(env, VF, ((a ^ b) & (a ^ result)));
    WR_cpu(env, NF, result);
    WR_cpu(env, ZF, result);
    return result;
}

/* Similarly for variable shift instructions.  */

uint32_t HELPER(shl)(uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32)
        return 0;
    return x << shift;
}

uint32_t HELPER(shr)(uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32)
        return 0;
    return (uint32_t) x >> shift;
}

uint32_t HELPER(sar)(uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32)
        shift = 31;
    return (int32_t) x >> shift;
}

uint32_t HELPER(shl_cc)(uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            WR_cpu(env, CF, (x & 1));
        else
            WR_cpu(env, CF, 0);
        return 0;
    } else if (shift != 0) {
        WR_cpu(env, CF, ((x >> (32 - shift)) & 1));
        return x << shift;
    }
    return x;
}

uint32_t HELPER(shr_cc)(uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            WR_cpu(env, CF, ((x >> 31) & 1));
        else
            WR_cpu(env, CF, 0);
        return 0;
    } else if (shift != 0) {
        WR_cpu(env, CF, ((x >> (shift - 1)) & 1));
        return x >> shift;
    }
    return x;
}

uint32_t HELPER(sar_cc)(uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32) {
        WR_cpu(env, CF, ((x >> 31) & 1));
        return (int32_t) x >> 31;
    } else if (shift != 0) {
        WR_cpu(env, CF, ((x >> (shift - 1)) & 1));
        return (int32_t) x >> shift;
    }
    return x;
}

uint32_t HELPER(ror_cc)(uint32_t x, uint32_t i) {
    int shift1, shift;
    shift1 = i & 0xff;
    shift = shift1 & 0x1f;
    if (shift == 0) {
        if (shift1 != 0)
            WR_cpu(env, CF, ((x >> 31) & 1));
        return x;
    } else {
        WR_cpu(env, CF, ((x >> (shift - 1)) & 1));
        return ((uint32_t) x >> shift) | (x << (32 - shift));
    }
}
/* Sign/zero extend */
uint32_t HELPER(sxtb16)(uint32_t x) {
    uint32_t res;
    res = (uint16_t)(int8_t) x;
    res |= (uint32_t)(int8_t)(x >> 16) << 16;
    return res;
}

uint32_t HELPER(uxtb16)(uint32_t x) {
    uint32_t res;
    res = (uint16_t)(uint8_t) x;
    res |= (uint32_t)(uint8_t)(x >> 16) << 16;
    return res;
}

uint32_t HELPER(clz)(uint32_t x) {
    return clz32(x);
}

int32_t HELPER(sdiv)(int32_t num, int32_t den) {
    if (den == 0)
        return 0;
    if (num == INT_MIN && den == -1)
        return INT_MIN;
    return num / den;
}

uint32_t HELPER(udiv)(uint32_t num, uint32_t den) {
    if (den == 0)
        return 0;
    return num / den;
}

uint32_t HELPER(rbit)(uint32_t x) {
    x = ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24);
    x = ((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4);
    x = ((x & 0x88888888) >> 3) | ((x & 0x44444444) >> 1) | ((x & 0x22222222) << 1) | ((x & 0x11111111) << 3);
    return x;
}

uint32_t HELPER(abs)(uint32_t x) {
    return ((int32_t) x < 0) ? -x : x;
}
/* moved from helper.c */
static inline uint8_t do_usad(uint8_t a, uint8_t b) {
    if (a > b)
        return a - b;
    else
        return b - a;
}

/* Unsigned sum of absolute byte differences.  */
uint32_t HELPER(usad8)(uint32_t a, uint32_t b) {
    uint32_t sum;
    sum = do_usad(a, b);
    sum += do_usad(a >> 8, b >> 8);
    sum += do_usad(a >> 16, b >> 16);
    sum += do_usad(a >> 24, b >> 24);
    return sum;
}

/* For ARMv6 SEL instruction.  */
uint32_t HELPER(sel_flags)(uint32_t flags, uint32_t a, uint32_t b) {
    uint32_t mask;

    mask = 0;
    if (flags & 1)
        mask |= 0xff;
    if (flags & 2)
        mask |= 0xff00;
    if (flags & 4)
        mask |= 0xff0000;
    if (flags & 8)
        mask |= 0xff000000;
    return (a & mask) | (b & ~mask);
}
///* Unsigned modulo arithmetic.  */
#define ADD16(a, b, n)                                           \
    do {                                                         \
        uint32_t sum;                                            \
        sum = (uint32_t)(uint16_t)(a) + (uint32_t)(uint16_t)(b); \
        RESULT(sum, n, 16);                                      \
        if ((sum >> 16) == 1)                                    \
            ge |= 3 << (n * 2);                                  \
    } while (0)

#define ADD8(a, b, n)                                          \
    do {                                                       \
        uint32_t sum;                                          \
        sum = (uint32_t)(uint8_t)(a) + (uint32_t)(uint8_t)(b); \
        RESULT(sum, n, 8);                                     \
        if ((sum >> 8) == 1)                                   \
            ge |= 1 << n;                                      \
    } while (0)

#define SUB16(a, b, n)                                           \
    do {                                                         \
        uint32_t sum;                                            \
        sum = (uint32_t)(uint16_t)(a) - (uint32_t)(uint16_t)(b); \
        RESULT(sum, n, 16);                                      \
        if ((sum >> 16) == 0)                                    \
            ge |= 3 << (n * 2);                                  \
    } while (0)

#define SUB8(a, b, n)                                          \
    do {                                                       \
        uint32_t sum;                                          \
        sum = (uint32_t)(uint8_t)(a) - (uint32_t)(uint8_t)(b); \
        RESULT(sum, n, 8);                                     \
        if ((sum >> 8) == 0)                                   \
            ge |= 1 << n;                                      \
    } while (0)

#define PFX u
#define ARITH_GE

#include "op_addsub.h"
#if defined(CONFIG_SYMBEX)
/* These are dummy functions, to be redefined by the instrumentation code */
__attribute__((weak)) void helper_se_call(target_ulong pc) {
}

__attribute__((weak)) void helper_se_ret(target_ulong pc) {
}
#endif

#if defined(CONFIG_SYMBEX) && defined(CONFIG_USER_KVM)
#define ADDR_MAX ((target_ulong) -1)
#include <cpu/se_libcpu_config.h>
// clang-format off
#if defined(SYMBEX_LLVM_LIB) && !defined(STATIC_TRANSLATOR)
    #define INSTR_BEFORE_MEMORY_ACCESS(vaddr, value, flags) \
        if (*g_sqi.events.before_memory_access_signals_count) tcg_llvm_before_memory_access(vaddr, value, sizeof(value), flags);
    #define INSTR_AFTER_MEMORY_ACCESS(vaddr, value, flags, retaddr) \
        if (*g_sqi.events.after_memory_access_signals_count) tcg_llvm_after_memory_access(vaddr, value, sizeof(value), flags, 0);
    #define INSTR_FORK_AND_CONCRETIZE(val, max) \
        tcg_llvm_fork_and_concretize(val, 0, max, 0)
    #define SE_SET_MEM_IO_VADDR(env, addr, reset) \
        tcg_llvm_write_mem_io_vaddr(addr, reset)
#else // SYMBEX_LLVM_LIB
    #if defined(SE_ENABLE_MEM_TRACING) && !defined(STATIC_TRANSLATOR)
        #ifdef SOFTMMU_CODE_ACCESS
            #define INSTR_BEFORE_MEMORY_ACCESS(vaddr, value, flags)
            #define INSTR_AFTER_MEMORY_ACCESS(vaddr, value, flags, retaddr)
        #else
            #define INSTR_BEFORE_MEMORY_ACCESS(vaddr, value, flags)
            #define INSTR_AFTER_MEMORY_ACCESS(vaddr, value, flags, retaddr) \
                if (unlikely(*g_sqi.events.after_memory_access_signals_count)) g_sqi.events.after_memory_access(vaddr, value, sizeof(value), flags, (uintptr_t) 0);
        #endif
    #else
        #define INSTR_BEFORE_MEMORY_ACCESS(vaddr, value, flags)
        #define INSTR_AFTER_MEMORY_ACCESS(vaddr, value, flags, retaddr)
    #endif

    #define INSTR_FORK_AND_CONCRETIZE(val, max) (val)

    #define SE_SET_MEM_IO_VADDR(env, addr, reset) \
            env->mem_io_vaddr = addr;

#endif // SYMBEX_LLVM_LIB

#define INSTR_FORK_AND_CONCRETIZE_ADDR(val, max) \
    (*g_sqi.mode.fork_on_symbolic_address ? INSTR_FORK_AND_CONCRETIZE(val, max) : val)

#define SE_RAM_OBJECT_DIFF (TARGET_PAGE_BITS - SE_RAM_OBJECT_BITS)
// clang-format on

#else // CONFIG_SYMBEX

#define INSTR_BEFORE_MEMORY_ACCESS(...)
#define INSTR_AFTER_MEMORY_ACCESS(...)
#define INSTR_FORK_AND_CONCRETIZE(val, max) (val)
#define INSTR_FORK_AND_CONCRETIZE_ADDR(val, max) (val)

#define SE_RAM_OBJECT_BITS TARGET_PAGE_BITS
#define SE_RAM_OBJECT_SIZE TARGET_PAGE_SIZE
#define SE_RAM_OBJECT_MASK TARGET_PAGE_MASK
#define SE_RAM_OBJECT_DIFF 0

#define SE_SET_MEM_IO_VADDR(env, addr, reset) env->mem_io_vaddr = addr;
#endif

#if defined(CONFIG_SYMBEX) && defined(CONFIG_USER_KVM)
void s2e_g2h_io_write_chk(target_phys_addr_t physaddr, target_ulong addr, void *retaddr) {
    const struct MemoryDescOps *ops = phys_get_ops(physaddr);

    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;

#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)

    if (unlikely(is_notdirty_ops(ops))) {
        CPUTLBEntry *e = se_tlb_current;
        if (!(e->addr_write & (TLB_NOT_OURS | TLB_NOTDIRTY))) {
            // The symbolic value will be overwritten by the concrete one
            // in the slow path for not-dirty pages.
        }
    }
#endif

    SE_SET_MEM_IO_VADDR(env, addr, 0);
    env->mem_io_pc = (uintptr_t) retaddr;
	return;
/* We are trying to get the host address in klee's concrete buffer */
}
void* s2e_g2h(target_ulong addr, int write) {
	return (void *)addr;
} 
#endif
