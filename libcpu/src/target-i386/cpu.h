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

#ifndef CPU_I386_H
#define CPU_I386_H

#include <assert.h>
#include <cpu/common.h>
#include <cpu/interrupt.h>
#include <cpu/tb.h>
#include <cpu/types.h>
#include <libcpu-log.h>

#include "cpu-defs.h"

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

#include <cpu/i386/cpu.h>

#ifdef HOST_WORDS_BIGENDIAN
#define XMM_B(n) _b[15 - (n)]
#define XMM_W(n) _w[7 - (n)]
#define XMM_L(n) _l[3 - (n)]
#define XMM_S(n) _s[3 - (n)]
#define XMM_Q(n) _q[1 - (n)]
#define XMM_D(n) _d[1 - (n)]

#define MMX_B(n) _b[7 - (n)]
#define MMX_W(n) _w[3 - (n)]
#define MMX_L(n) _l[1 - (n)]
#define MMX_S(n) _s[1 - (n)]
#else
#define XMM_B(n) _b[n]
#define XMM_W(n) _w[n]
#define XMM_L(n) _l[n]
#define XMM_S(n) _s[n]
#define XMM_Q(n) _q[n]
#define XMM_D(n) _d[n]

#define MMX_B(n) _b[n]
#define MMX_W(n) _w[n]
#define MMX_L(n) _l[n]
#define MMX_S(n) _s[n]
#endif
#define MMX_Q(n) q

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
/* Macros to access registers */
static inline target_ulong __RR_env_raw(CPUX86State *cpuState, unsigned offset, unsigned size) {
    if (likely(*g_sqi.mode.fast_concrete_invocation)) {
        switch (size) {
            case 1:
                return *((uint8_t *) cpuState + offset);
            case 2:
                return *(uint16_t *) ((uint8_t *) cpuState + offset);
            case 4:
                return *(uint32_t *) ((uint8_t *) cpuState + offset);
            case 8:
                return *(uint64_t *) ((uint8_t *) cpuState + offset);
            default:
                assert(false);
                return 0;
        }
    } else {
        target_ulong result = 0;
        g_sqi.regs.read_concrete(offset, (uint8_t *) &result, size);
        return result;
    }
}
static inline void __WR_env_raw(CPUX86State *cpuState, unsigned offset, target_ulong value, unsigned size) {
    if (likely(*g_sqi.mode.fast_concrete_invocation)) {
        switch (size) {
            case 1:
                *((uint8_t *) cpuState + offset) = value;
                break;
            case 2:
                *(uint16_t *) ((uint8_t *) cpuState + offset) = value;
                break;
            case 4:
                *(uint32_t *) ((uint8_t *) cpuState + offset) = value;
                break;
            case 8:
                *(uint64_t *) ((uint8_t *) cpuState + offset) = value;
                break;
            default:
                assert(false);
        }
    } else {
        g_sqi.regs.write_concrete(offset, (uint8_t *) &value, size);
    }
}

#define RR_cpu(cpu, reg) ((__typeof__(cpu->reg)) __RR_env_raw(cpu, offsetof(CPUX86State, reg), sizeof(cpu->reg)))

#define WR_cpu(cpu, reg, value) __WR_env_raw(cpu, offsetof(CPUX86State, reg), (target_ulong) value, sizeof(cpu->reg))
#else
#define RR_cpu(cpu, reg) cpu->reg
#define WR_cpu(cpu, reg, value) cpu->reg = value
#endif

#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING
////#define WR_se_eip(cpu, value) cpu->precise_eip = value
static void WR_se_eip(struct CPUX86State *cpu, target_ulong value) { cpu->precise_eip = value; }
#else
#define WR_se_eip(cpu, value)
#endif

uint32_t compute_eflags(void);

// XXX: Temporary hack to dump cpu state without crashing
static inline target_ulong cpu_get_eflags_dirty(CPUX86State *env) {
    return compute_eflags();
}

void cpu_x86_close(CPUX86State *s);
void x86_cpu_list(FILE *f, fprintf_function cpu_fprintf, const char *optarg);
int cpu_x86_support_mca_broadcast(CPUX86State *env);

int cpu_get_pic_interrupt(CPUX86State *s);
/* MSDOS compatibility mode FPU exception support */
void cpu_set_ferr(CPUX86State *s);

/* this function must always be used to load data in the segment
   cache: it synchronizes the hflags with the segment cache values */
static inline void cpu_x86_load_seg_cache(CPUX86State *env, int seg_reg, unsigned int selector, target_ulong base,
                                          unsigned int limit, unsigned int flags) {
    SegmentCache *sc;
    unsigned int new_hflags;

    sc = &env->segs[seg_reg];
    sc->selector = selector;
    sc->base = base;
    sc->limit = limit;
    sc->flags = flags;

    /* update the hidden flags */
    {
        if (seg_reg == R_CS) {
#ifdef TARGET_X86_64
            if ((env->hflags & HF_LMA_MASK) && (flags & DESC_L_MASK)) {
                /* long mode */
                env->hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK;
                env->hflags &= ~(HF_ADDSEG_MASK);
            } else
#endif
            {
                /* legacy / compatibility case */
                new_hflags = (env->segs[R_CS].flags & DESC_B_MASK) >> (DESC_B_SHIFT - HF_CS32_SHIFT);
                env->hflags = (env->hflags & ~(HF_CS32_MASK | HF_CS64_MASK)) | new_hflags;
            }
        }
        new_hflags = (env->segs[R_SS].flags & DESC_B_MASK) >> (DESC_B_SHIFT - HF_SS32_SHIFT);
        if (env->hflags & HF_CS64_MASK) {
            /* zero base assumed for DS, ES and SS in long mode */
        } else if (!(env->cr[0] & CR0_PE_MASK) || (env->mflags & VM_MASK) || !(env->hflags & HF_CS32_MASK)) {
            /* XXX: try to avoid this test. The problem comes from the
               fact that is real mode or vm86 mode we only modify the
               'base' and 'selector' fields of the segment cache to go
               faster. A solution may be to force addseg to one in
               translate-i386.c. */
            new_hflags |= HF_ADDSEG_MASK;
        } else {
            new_hflags |= ((env->segs[R_DS].base | env->segs[R_ES].base | env->segs[R_SS].base) != 0)
                          << HF_ADDSEG_SHIFT;
        }
        env->hflags = (env->hflags & ~(HF_SS32_MASK | HF_ADDSEG_MASK)) | new_hflags;
    }
}

static inline void cpu_x86_load_seg_cache_sipi(CPUX86State *env, int sipi_vector) {
    WR_se_eip(env, 0);
    env->eip = 0;
    cpu_x86_load_seg_cache(env, R_CS, sipi_vector << 8, sipi_vector << 12, env->segs[R_CS].limit,
                           env->segs[R_CS].flags);
    env->halted = 0;
}

int cpu_x86_get_descr_debug(CPUX86State *env, unsigned int selector, target_ulong *base, unsigned int *limit,
                            unsigned int *flags);

/* wrapper, just in case memory mappings must be changed */
static inline void cpu_x86_set_cpl(CPUX86State *s, int cpl) {
#ifdef CONFIG_SYMBEX
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count))
        g_sqi.events.on_privilege_change(s->hflags & HF_CPL_MASK, cpl);
#endif
#if HF_CPL_MASK == 3
    s->hflags = (s->hflags & ~HF_CPL_MASK) | cpl;
#else
#error HF_CPL_MASK is hardcoded
#endif
}

/* op_helper.c */
/* used for debug or cpu save/restore */
void cpu_get_fp80(uint64_t *pmant, uint16_t *pexp, floatx80 f);
floatx80 cpu_set_fp80(uint64_t mant, uint16_t upper);

/* cpu-exec.c */
/* the following helpers are only usable in user mode simulation as
   they can trigger unexpected exceptions */
void cpu_x86_load_seg(CPUX86State *s, int seg_reg, int selector);
void cpu_x86_fsave(CPUX86State *s, target_ulong ptr, int data32);
void cpu_x86_frstor(CPUX86State *s, target_ulong ptr, int data32);

/* you can call this signal handler from your SIGBUS and SIGSEGV
   signal handlers to inform the virtual CPU of exceptions. non zero
   is returned if the signal was handled by the virtual CPU.  */
int cpu_x86_signal_handler(int host_signum, void *pinfo, void *puc);

/* cpuid.c */
int cpu_x86_register(CPUX86State *env, const char *cpu_model);
void cpu_clear_apic_feature(CPUX86State *env);

/* helper.c */

#define cpu_handle_mmu_fault cpu_x86_handle_mmu_fault
void cpu_x86_set_a20(CPUX86State *env, int a20_state);

static inline int hw_breakpoint_enabled(unsigned long dr7, int index) {
    return (dr7 >> (index * 2)) & 3;
}

static inline int hw_breakpoint_type(unsigned long dr7, int index) {
    return (dr7 >> (DR7_TYPE_SHIFT + (index * 4))) & 3;
}

static inline int hw_breakpoint_len(unsigned long dr7, int index) {
    int len = ((dr7 >> (DR7_LEN_SHIFT + (index * 4))) & 3);
    return (len == 2) ? 8 : len + 1;
}

/* used to debug */
#define X86_DUMP_FPU 0x0001  /* dump FPU state too */
#define X86_DUMP_CCOP 0x0002 /* dump qemu flag cache */

#ifdef TARGET_X86_64
#define TARGET_PHYS_ADDR_SPACE_BITS 52
/* ??? This is really 48 bits, sign-extended, but the only thing
   accessible to userland with bit 48 set is the VSYSCALL, and that
   is handled via other mechanisms.  */
#define TARGET_VIRT_ADDR_SPACE_BITS 47
#else
#define TARGET_PHYS_ADDR_SPACE_BITS 36
#define TARGET_VIRT_ADDR_SPACE_BITS 32
#endif

#define cpu_init cpu_x86_init
#define cpu_exec cpu_x86_exec
#define cpu_gen_code cpu_x86_gen_code
#define cpu_signal_handler cpu_x86_signal_handler
#define cpu_list_id x86_cpu_list
#define cpudef_setup x86_cpudef_setup

//#define CPU_SAVE_VERSION 12

/* MMU modes definitions */
#define MMU_MODE0_SUFFIX _kernel
#define MMU_MODE1_SUFFIX _user
#define MMU_USER_IDX 1

#undef EAX
#define EAX (RR_cpu(env, regs[R_EAX]))
#define EAX_W(v) (WR_cpu(env, regs[R_EAX], v))
#define REGS0_W(v) (WR_cpu(env, regs[0], v))
#undef ECX
#define ECX (RR_cpu(env, regs[R_ECX]))
#define ECX_W(v) (WR_cpu(env, regs[R_ECX], v))
#undef EDX
#define EDX (RR_cpu(env, regs[R_EDX]))
#define EDX_W(v) (WR_cpu(env, regs[R_EDX], v))
#undef EBX
#define EBX (RR_cpu(env, regs[R_EBX]))
#define EBX_W(v) (WR_cpu(env, regs[R_EBX], v))
#undef ESP
#define ESP (RR_cpu(env, regs[R_ESP]))
#define ESP_W(v) (WR_cpu(env, regs[R_ESP], v))
#undef EBP
#define EBP (RR_cpu(env, regs[R_EBP]))
#define EBP_W(v) (WR_cpu(env, regs[R_EBP], v))
#undef ESI
#define ESI (RR_cpu(env, regs[R_ESI]))
#define ESI_W(v) (WR_cpu(env, regs[R_ESI], v))
#undef EDI
#define EDI (RR_cpu(env, regs[R_EDI]))
#define EDI_W(v) (WR_cpu(env, regs[R_EDI], v))

#define CC_SRC (RR_cpu(env, cc_src))
#define CC_DST (RR_cpu(env, cc_dst))
#define CC_OP (RR_cpu(env, cc_op))

#define CC_SRC_W(v) (WR_cpu(env, cc_src, v))
#define CC_DST_W(v) (WR_cpu(env, cc_dst, v))
#define CC_OP_W(v) (WR_cpu(env, cc_op, v))

#define DF (env->df)
#define DF_W(v) (env->df = (v))

#undef EIP
#define EIP (env->eip)

/* float macros */
#define FT0 (env->ft0)
#define ST0 (env->fpregs[env->fpstt].d)
#define ST(n) (env->fpregs[(env->fpstt + (n)) & 7].d)
#define ST1 ST(1)

/* translate.c */
void optimize_flags_init(void);

#include "cpu-all.h"
#include "svm.h"

#include <cpu/apic.h>

#include "exec-all.h"

static inline void cpu_pc_from_tb(CPUX86State *env, TranslationBlock *tb) {
    WR_se_eip(env, tb->pc - tb->cs_base);
    env->eip = tb->pc - tb->cs_base;
}

static inline void cpu_get_tb_cpu_state(CPUX86State *env, target_ulong *pc, target_ulong *cs_base, int *flags) {
    *cs_base = env->segs[R_CS].base;
    *pc = *cs_base + env->eip;
    *flags = env->hflags | (env->mflags & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK));
}

void do_cpu_sipi(CPUX86State *env);

/* op_helper.c */
void do_interrupt(CPUX86State *env);
void do_interrupt_x86_hardirq(CPUX86State *env, int intno, int is_hw);
void LIBCPU_NORETURN raise_exception_env(int exception_index, CPUX86State *nenv);
void LIBCPU_NORETURN raise_exception_err_env(CPUX86State *nenv, int exception_index, int error_code);

void do_smm_enter(CPUX86State *env1);

void svm_check_intercept(CPUX86State *env1, uint32_t type);

uint32_t cpu_cc_compute_all(CPUX86State *env1, int op);

void cpu_report_tpr_access(CPUX86State *env, TPRAccess access);

#endif /* CPU_I386_H */
