///
/// Copyright (C) 2015-2017, Cyberhaven
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
/// 	Authors: Yingtong Liu <yingtong@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIT(n) (1 << (n))
#include <cpu/kvm.h>
#include <cpu/config-target.h>
#ifdef TARGET_I386
#include <cpu/i386/cpu.h>
#elif defined(TARGET_ARM)
#include <cpu/arm/cpu.h>
#endif
#include <timer.h>
#include "s2e-kvm-interface.h"
extern THREAD CPUArchState *env;

// clang-format off
#ifdef TARGET_I386
static uint32_t s_msr_list [] = {
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,
    MSR_IA32_APICBASE,
    MSR_EFER,
    MSR_STAR,
    MSR_PAT,
    MSR_VM_HSAVE_PA,
    #ifdef TARGET_X86_64
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_FMASK,
    MSR_FSBASE,
    MSR_GSBASE,
    MSR_KERNELGSBASE,
    #endif
    MSR_MTRRphysBase(0),
    MSR_MTRRphysBase(1),
    MSR_MTRRphysBase(2),
    MSR_MTRRphysBase(3),
    MSR_MTRRphysBase(4),
    MSR_MTRRphysBase(5),
    MSR_MTRRphysBase(6),
    MSR_MTRRphysBase(7),
    MSR_MTRRphysMask(0),
    MSR_MTRRphysMask(1),
    MSR_MTRRphysMask(2),
    MSR_MTRRphysMask(3),
    MSR_MTRRphysMask(4),
    MSR_MTRRphysMask(5),
    MSR_MTRRphysMask(6),
    MSR_MTRRphysMask(7),
    MSR_MTRRfix64K_00000,
    MSR_MTRRfix16K_80000,
    MSR_MTRRfix16K_A0000,
    MSR_MTRRfix4K_C0000,
    MSR_MTRRfix4K_C8000,
    MSR_MTRRfix4K_D0000,
    MSR_MTRRfix4K_D8000,
    MSR_MTRRfix4K_E0000,
    MSR_MTRRfix4K_E8000,
    MSR_MTRRfix4K_F0000,
    MSR_MTRRfix4K_F8000,
    MSR_MTRRdefType,
    MSR_MCG_STATUS,
    MSR_MCG_CTL,
    MSR_TSC_AUX,
    MSR_IA32_MISC_ENABLE,
    MSR_MC0_CTL,
    MSR_MC0_STATUS,
    MSR_MC0_ADDR,
    MSR_MC0_MISC
};
#endif

#ifdef TARGET_I386
/* Array of valid (function, index) entries */
static uint32_t s_cpuid_entries[][2] = {
    {0, -1},
    {1, -1},
    {2, -1},
    {4, 0},
    {4, 1},
    {4, 2},
    {4, 3},
    {5, -1},
    {6, -1},
    {7, -1},
    {9, -1},
    {0xa, -1},
    {0xd, -1},
    {0x80000000, -1},
    {0x80000001, -1},
    {0x80000002, -1},
    {0x80000003, -1},
    {0x80000004, -1},
    {0x80000005, -1},
    {0x80000006, -1},
    {0x80000008, -1},
    {0x8000000a, -1},
    {0xc0000000, -1},
    {0xc0000001, -1},
    {0xc0000002, -1},
    {0xc0000003, -1},
    {0xc0000004, -1}
};
// clang-format on

int s2e_kvm_get_msr_index_list(int kvm_fd, struct kvm_msr_list *list) {
    if (list->nmsrs == 0) {
        list->nmsrs = sizeof(s_msr_list) / sizeof(s_msr_list[0]);
    } else {
        for (int i = 0; i < list->nmsrs; ++i) {
            list->indices[i] = s_msr_list[i];
        }
    }

    return 0;
}

#ifdef SE_KVM_DEBUG_CPUID
static void print_cpuid2(struct kvm_cpuid_entry2 *e) {
    printf("cpuid function=%#010" PRIx32 " index=%#010" PRIx32 " flags=%#010" PRIx32 " eax=%#010" PRIx32
           " ebx=%#010" PRIx32 " ecx=%#010" PRIx32 " edx=%#010" PRIx32 "\n",
           e->function, e->index, e->flags, e->eax, e->ebx, e->ecx, e->edx);
}
#endif

int s2e_kvm_get_supported_cpuid(int kvm_fd, struct kvm_cpuid2 *cpuid) {
#ifdef SE_KVM_DEBUG_CPUID
    printf("%s\n", __FUNCTION__);
#endif
    unsigned int nentries = sizeof(s_cpuid_entries) / sizeof(s_cpuid_entries[0]);
    if (cpuid->nent < nentries) {
        errno = E2BIG;
        return -1;
    } else if (cpuid->nent >= nentries) {
        cpuid->nent = nentries;
        // errno = ENOMEM;
        // return -1;
    }

    for (unsigned i = 0; i < nentries; ++i) {
        struct kvm_cpuid_entry2 *e = &cpuid->entries[i];
        cpu_x86_cpuid(env, s_cpuid_entries[i][0], s_cpuid_entries[i][1], &e->eax, &e->ebx, &e->ecx, &e->edx);

        e->flags = 0;
        e->index = 0;
        if (s_cpuid_entries[i][1] != -1) {
            e->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
            e->index = s_cpuid_entries[i][1];
        }
        e->function = s_cpuid_entries[i][0];

#ifdef SE_KVM_DEBUG_CPUID
        print_cpuid2(e);
#endif
    }

    return 0;
}

int s2e_kvm_vcpu_set_cpuid2(int vcpu_fd, struct kvm_cpuid2 *cpuid) {
/**
 * QEMU insists on using host cpuid flags when running in KVM mode.
 * We want to use those set in DBT mode instead.
 * TODO: for now, we have no way to configure custom flags.
 * Snapshots will not work if using anything other that defaults.
 */

/// This check ensures that users don't mistakenly use the wrong build of libs2e.
#if defined(TARGET_X86_64)
    if (cpuid->nent == 15) {
        fprintf(stderr, "libs2e for 64-bit guests is used but the KVM client requested 32-bit features\n");
        exit(1);
    }
#elif defined(TARGET_I386) || defined(TARGET_ARM)
    if (cpuid->nent == 21) {
        fprintf(stderr, "libs2e for 32-bit guests is used but the KVM client requested 64-bit features\n");
        exit(1);
    }
#else
#error unknown architecture
#endif

    return 0;
}
#endif

#ifdef TARGET_ARM
int s2e_kvm_arm_vcpu_init(int fd, struct kvm_vcpu_init * arg1) {
	return 0;
}
#endif
int s2e_kvm_vcpu_set_regs(int vcpu_fd, struct kvm_regs *regs) {
	assert(false && "s2e_kvm_vcpu_set_regs failed\n");
}

int s2e_kvm_vcpu_set_fpu(int vcpu_fd, struct kvm_fpu *fpu) {
	assert(false && "s2e_kvm_vcpu_set_fpu failed\n");
}
int s2e_kvm_vcpu_set_sregs(int vcpu_fd, struct kvm_sregs *sregs) {
	assert(false && "s2e_kvm_vcpu_set_sregs failed\n");
}
#ifdef TARGET_ARM
typedef struct Reg {
    uint64_t id;
    int offset;
} Reg;

#define COREREG(KERNELNAME, QEMUFIELD)                       \
    {                                                        \
        KVM_REG_ARM | KVM_REG_SIZE_U32 |                     \
        KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(KERNELNAME), \
        offsetof(CPUARMState, QEMUFIELD)                     \
    }

#define CP15REG(CRN, CRM, OPC1, OPC2, QEMUFIELD) \
    {                                            \
        KVM_REG_ARM | KVM_REG_SIZE_U32 |         \
        (15 << KVM_REG_ARM_COPROC_SHIFT) |       \
        ((CRN) << KVM_REG_ARM_32_CRN_SHIFT) |    \
        ((CRM) << KVM_REG_ARM_CRM_SHIFT) |       \
        ((OPC1) << KVM_REG_ARM_OPC1_SHIFT) |     \
        ((OPC2) << KVM_REG_ARM_32_OPC2_SHIFT),   \
        offsetof(CPUARMState, QEMUFIELD)         \
    }

static const Reg regs[] = {
    /* R0_usr .. R14_usr */
    COREREG(usr_regs.uregs[0], regs[0]),
    COREREG(usr_regs.uregs[1], regs[1]),
    COREREG(usr_regs.uregs[2], regs[2]),
    COREREG(usr_regs.uregs[3], regs[3]),
    COREREG(usr_regs.uregs[4], regs[4]),
    COREREG(usr_regs.uregs[5], regs[5]),
    COREREG(usr_regs.uregs[6], regs[6]),
    COREREG(usr_regs.uregs[7], regs[7]),
    COREREG(usr_regs.uregs[8], usr_regs[0]),
    COREREG(usr_regs.uregs[9], usr_regs[1]),
    COREREG(usr_regs.uregs[10], usr_regs[2]),
    COREREG(usr_regs.uregs[11], usr_regs[3]),
    COREREG(usr_regs.uregs[12], usr_regs[4]),
    COREREG(usr_regs.uregs[13], banked_r13[0]),
    COREREG(usr_regs.uregs[14], banked_r14[0]),
    /* R13, R14, SPSR for SVC, ABT, UND, IRQ banks */
    COREREG(svc_regs[0], banked_r13[1]),
    COREREG(svc_regs[1], banked_r14[1]),
    COREREG(svc_regs[2], banked_spsr[1]),
    COREREG(abt_regs[0], banked_r13[2]),
    COREREG(abt_regs[1], banked_r14[2]),
    COREREG(abt_regs[2], banked_spsr[2]),
    COREREG(und_regs[0], banked_r13[3]),
    COREREG(und_regs[1], banked_r14[3]),
    COREREG(und_regs[2], banked_spsr[3]),
    COREREG(irq_regs[0], banked_r13[4]),
    COREREG(irq_regs[1], banked_r14[4]),
    COREREG(irq_regs[2], banked_spsr[4]),
    /* R8_fiq .. R14_fiq and SPSR_fiq */
    COREREG(fiq_regs[0], fiq_regs[0]),
    COREREG(fiq_regs[1], fiq_regs[1]),
    COREREG(fiq_regs[2], fiq_regs[2]),
    COREREG(fiq_regs[3], fiq_regs[3]),
    COREREG(fiq_regs[4], fiq_regs[4]),
    COREREG(fiq_regs[5], banked_r13[5]),
    COREREG(fiq_regs[6], banked_r14[5]),
    COREREG(fiq_regs[7], banked_spsr[5]),
    /* R15 */
    COREREG(usr_regs.uregs[15], regs[15]),
    /* A non-comprehensive set of cp15 registers.
     * TODO: drive this from the cp_regs hashtable instead.
     */
    CP15REG(1, 0, 0, 0, cp15.c1_sys), /* SCTLR */
    CP15REG(2, 0, 0, 2, cp15.c2_control), /* TTBCR */
    CP15REG(3, 0, 0, 0, cp15.c3), /* DACR */
};
extern int bank_number(CPUARMState *env, int mode);
extern void cpsr_write(CPUARMState *env, uint32_t val, uint32_t mask);
int s2e_kvm_vcpu_set_one_reg(int fd, struct kvm_one_reg * arg1){
    struct kvm_one_reg r = *arg1;
    int mode, bn;
    ////int ret, i;
    int i;
    uint32_t cpsr;
    uint32_t ttbr;

    for (i = 0; i < ARRAY_SIZE(regs); i++) {
        if(r.id == regs[i].id) {
        	memcpy((void*)env + regs[i].offset,(void *)r.addr, sizeof(uint32_t));
		return 0;	
    	}
     }

//    /* Special cases which aren't a single CPUARMState field */
    	if(r.id == (KVM_REG_ARM | KVM_REG_SIZE_U32 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(usr_regs.ARM_cpsr)))
	{
        	memcpy(&cpsr, (void *)r.addr, sizeof(uint32_t));
    		cpsr_write(env, cpsr, 0xffffffff);
		return 0;
	}
//    /* TTBR0: cp15 crm=2 opc1=0 */
   	if(r.id == (KVM_REG_ARM | KVM_REG_SIZE_U64 | (15 << KVM_REG_ARM_COPROC_SHIFT) | (2 << KVM_REG_ARM_CRM_SHIFT) | (0 << KVM_REG_ARM_OPC1_SHIFT))) {
        	memcpy(&ttbr, (void *)r.addr, sizeof(uint32_t));
		env->cp15.c2_base0 = ttbr;
		return 0;
	}
    /* TTBR1: cp15 crm=2 opc1=1 */
    	if(r.id == (KVM_REG_ARM | KVM_REG_SIZE_U64 | (15 << KVM_REG_ARM_COPROC_SHIFT) |
        (2 << KVM_REG_ARM_CRM_SHIFT) | (1 << KVM_REG_ARM_OPC1_SHIFT)))
	{
        	memcpy(&ttbr, (void *)r.addr, sizeof(uint32_t));
    		env->cp15.c2_base1 = ttbr;
    	} else {
		assert(false && "s2e_kvm_vcpu_set_one_reg: unhandled register id\n");
	}
/*FIXME move this to a seperate function. we only need to do this once after all the KVM_SET_ONE_REG commands. */
    /* Make sure the current mode regs are properly set */
    mode = env->uncached_cpsr & CPSR_M;
    bn = bank_number(env, mode);
    if (mode == ARM_CPU_MODE_FIQ) {
        memcpy(env->regs + 8, env->fiq_regs, 5 * sizeof(uint32_t));
    } else {
        memcpy(env->regs + 8, env->usr_regs, 5 * sizeof(uint32_t));
    }
    env->regs[13] = env->banked_r13[bn];
    env->regs[14] = env->banked_r14[bn];
    env->spsr = env->banked_spsr[bn];

    /* The main GET_ONE_REG loop above set c2_control, but we need to
     * update some extra cached precomputed values too.
     * When this is driven from the cp_regs hashtable then this ugliness
     * can disappear because we'll use the access function which sets
     * these values automatically.
     */
    env->cp15.c2_mask = ~(0xffffffffu >> env->cp15.c2_control);
    env->cp15.c2_base_mask = ~(0x3fffu >> env->cp15.c2_control);
	return 0;
}
#endif

#ifdef CONFIG_USER_KVM
int s2e_kvm_vcpu_set_opaque(int vcpu_fd, void * arg1) {
	env->opaque = arg1;
	cpu_parse_opaque(env);
	return 0;	
}
#endif
#ifdef TARGET_I386
void helper_wrmsr_v(target_ulong index, uint64_t val);
int s2e_kvm_vcpu_set_msrs(int vcpu_fd, struct kvm_msrs *msrs) {
    for (unsigned i = 0; i < msrs->nmsrs; ++i) {
        helper_wrmsr_v(msrs->entries[i].index, msrs->entries[i].data);
    }
    return 0;
}
#endif
int s2e_kvm_vcpu_set_mp_state(int vcpu_fd, struct kvm_mp_state *mp) {
    /* Only needed when using an irq chip */
    return 0;
}

int s2e_kvm_vcpu_get_regs(int vcpu_fd, struct kvm_regs *regs) {
	assert(false && "s2e_kvm_vcpu_get_regs failed\n");
}

int s2e_kvm_vcpu_get_fpu(int vcpu_fd, struct kvm_fpu *fpu) {
	assert(false && "s2e_kvm_vcpu_get_fpu failed\n");
}
int s2e_kvm_vcpu_get_sregs(int vcpu_fd, struct kvm_sregs *sregs) {
	assert(false && "s2e_kvm_vcpu_get_sregs failed\n");
}

int s2e_kvm_vcpu_get_msrs(int vcpu_fd, struct kvm_msrs *msrs) {
	assert(false && "s2e_kvm_vcpu_get_msrs failed\n");
}

int s2e_kvm_vcpu_get_mp_state(int vcpu_fd, struct kvm_mp_state *mp) {
    // Not needed without IRQ chip?
    mp->mp_state = KVM_MP_STATE_RUNNABLE;
    return 0;
}

int s2e_kvm_vm_set_tss_addr(int vm_fd, uint64_t tss_addr) {
#ifdef SE_KVM_DEBUG_INTERFACE
    printf("Setting tss addr %#" PRIx64 " not implemented yet\n", tss_addr);
#endif
    return 0;
}

uint64_t g_clock_start = 0;
uint64_t g_clock_offset = 0;
int s2e_kvm_vm_set_clock(int vm_fd, struct kvm_clock_data *clock) {
    g_clock_start = clock->clock;
    g_clock_offset = cpu_get_real_ticks();
    return 0;
}

int s2e_kvm_vm_get_clock(int vm_fd, struct kvm_clock_data *clock) {
    clock->clock = cpu_get_real_ticks() - g_clock_offset + g_clock_start;
    clock->flags = 0;
    return 0;
}
