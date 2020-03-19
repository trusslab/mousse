///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
/// 	Authors: Yingtong Liu <yingtong@uci.edu> Hsin-Wei Hung<hsinweih@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionStateRegisters.h>
#include <s2e/Utils.h>

#include <klee/util/ExprTemplates.h>
#include <llvm/Support/CommandLine.h>

// XXX: The idea is to avoid function calls
//#define small_memcpy(dest, source, count) asm volatile ("cld; rep movsb"::"S"(source), "D"(dest), "c" (count):"flags",
//"memory")
#define small_memcpy __builtin_memcpy

extern llvm::cl::opt<bool> PrintModeSwitch;
extern CPUARMState *g_thread_env;

namespace s2e {

using namespace klee;
MemoryObject *S2EExecutionStateRegisters::s_concreteRegs = NULL;
MemoryObject *S2EExecutionStateRegisters::s_symbolicRegs = NULL;
void S2EExecutionStateRegisters::initialize(klee::AddressSpace &addressSpace, klee::MemoryObject *symbolicRegs,
                                            klee::MemoryObject *concreteRegs) {
    s_concreteRegs = concreteRegs;
    s_symbolicRegs = symbolicRegs;
    assert(s_concreteRegs && s_symbolicRegs);
    s_concreteRegs->setName("ConcreteCpuRegisters");
    s_symbolicRegs->setName("SymbolicCpuRegisters");

    /* The fast path in the cpu loop relies on this */
    s_symbolicRegs->doNotifyOnConcretenessChange = true;

    update(addressSpace, NULL, NULL, NULL, NULL);
}

void S2EExecutionStateRegisters::update(klee::AddressSpace &addressSpace, const bool *active,
                                        const bool *running_concrete, klee::IAddressSpaceNotification *notification,
                                        klee::IConcretizer *concretizer) {
    const ObjectState *concreteState = addressSpace.findObject(s_concreteRegs);
    const ObjectState *symbolicState = addressSpace.findObject(s_symbolicRegs);
    if(!concreteState) {
        fprintf(stderr, "thread = %lx update env symbolicRegs = %p\n",(unsigned long)pthread_self(), (void *)s_symbolicRegs->address);
    }
    if(!symbolicState) {
        fprintf(stderr, "thread = %lx update env concreteRegs = %p\n",(unsigned long)pthread_self(), (void *)s_concreteRegs->address);
    }
    assert(concreteState && symbolicState);
    addressSpace.addCachedObject(s_concreteRegs, concreteState);
    addressSpace.addCachedObject(s_symbolicRegs, symbolicState);

    m_symbolicRegs = addressSpace.getWriteable(s_symbolicRegs, symbolicState);
    m_concreteRegs = addressSpace.getWriteable(s_concreteRegs, concreteState);
    if (active && running_concrete) {
        m_runningConcrete = running_concrete;
        m_active = active;
        m_notification = notification;
        m_concretizer = concretizer;
    }
}

void S2EExecutionStateRegisters::copySymbRegs(bool toNative) {
    // It is allowed to have mixed/concrete symbolic register state.
    // All register accesses are wrapped, so it is ok.
    // assert(m_symbolicRegs->isAllConcrete());

    if (toNative) {
        assert(!*m_runningConcrete);
        memcpy((void *) s_symbolicRegs->address, m_symbolicRegs->getConcreteStore(true), m_symbolicRegs->size);
    } else {
        assert(*m_runningConcrete);
        memcpy(m_symbolicRegs->getConcreteStore(true), (void *) s_symbolicRegs->address, m_symbolicRegs->size);
    }
}

// XXX: The returned pointer cannot be used to modify symbolic state
// It's gonna crash the system. We should really fix that.
#ifdef TARGET_I386
CPUX86State *S2EExecutionStateRegisters::getCpuState() const {
    CPUX86State *cpu = *m_active
                           ? (CPUX86State *) (s_concreteRegs->address - offsetof(CPUX86State, eip))
                           : (CPUX86State *) (m_concreteRegs->getConcreteStore(true) - offsetof(CPUX86State, eip));

    return cpu;
}
#elif defined(TARGET_ARM)
CPUARMState *S2EExecutionStateRegisters::getCpuState() const {
    CPUARMState *cpu = *m_active
                           ? (CPUARMState *) (s_concreteRegs->address - offsetof(CPUARMState, regs[15]))
                           : (CPUARMState *) (m_concreteRegs->getConcreteStore(true) - offsetof(CPUARMState, regs[15]));

    return cpu;
}
#endif
void S2EExecutionStateRegisters::addressSpaceChange(const klee::MemoryObject *mo, const klee::ObjectState *oldState,
                                                    klee::ObjectState *newState) {
    if (mo == s_concreteRegs) {
        // It may happen that an execution state is copied in other places
        // than fork, in which case clone() is not called and the state
        // is left with stale references to memory objects. We patch these
        // objects here.
        m_concreteRegs = newState;
    } else if (mo == s_symbolicRegs) {
        m_symbolicRegs = newState;
    }
}
#ifdef TARGET_I386
bool S2EExecutionStateRegisters::flagsRegistersAreSymbolic() const {
    if (m_symbolicRegs->isAllConcrete())
        return false;

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_op), sizeof(env->cc_op) * 8)) {
        return true;
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_src), sizeof(env->cc_src) * 8)) {
        return true;
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_dst), sizeof(env->cc_dst) * 8)) {
        return true;
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_tmp), sizeof(env->cc_tmp) * 8)) {
        return true;
    }

    return false;
}
#elif defined(TARGET_ARM)
bool S2EExecutionStateRegisters::flagsRegistersAreSymbolic() const {
	assert(false && "flagsRegistersAreSymbolic not implemented\n");
}
#endif

#ifdef TARGET_I386
uint64_t S2EExecutionStateRegisters::getSymbolicRegistersMask() const {
    if (m_symbolicRegs->isAllConcrete())
        return 0;

    uint64_t mask = 0;
    uint64_t offset = 0;
    /* XXX: x86-specific */
    for (int i = 0; i < CPU_NB_REGS; ++i) { /* regs */
        if (!m_symbolicRegs->isConcrete(offset, sizeof(*env->regs) * 8)) {
            mask |= (1 << (i + 5));
        }
        offset += sizeof(*env->regs);
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_op), sizeof(env->cc_op) * 8)) // cc_op
        mask |= _M_CC_OP;
    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_src), sizeof(env->cc_src) * 8)) // cc_src
        mask |= _M_CC_SRC;
    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_dst), sizeof(env->cc_dst) * 8)) // cc_dst
        mask |= _M_CC_DST;
    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_tmp), sizeof(env->cc_tmp) * 8)) // cc_tmp
        mask |= _M_CC_TMP;
    return mask;
}
#elif defined(TARGET_ARM)
uint64_t S2EExecutionStateRegisters::getSymbolicRegistersMask() const {
/* This is copied from s2e-old, arm-experimental branch */
    //const ObjectState* os = m_cpuRegistersObject;
    const ObjectState* os = m_symbolicRegs;
    if(os->isAllConcrete()) {
        return 0;
    }
            

    uint64_t mask = 0;

        if(!os->isConcrete( 29*4, 4*8)) // CF
            mask |= (1 << 1);
        if(!os->isConcrete( 30*4, 4*8)) // VF
            mask |= (1 << 2);
        if(!os->isConcrete(31*4, 4*8)) // NF
            mask |= (1 << 3);
        if(!os->isConcrete(32*4, 4*8)) // ZF
            mask |= (1 << 4);
        for(int i = 0; i < 15; ++i) { /* regs */
                if(!os->isConcrete((33+i)*4, 4*8))
                    mask |= (1 << (i+5));
        }
        if(!os->isConcrete(0, 4*8)) // spsr
            mask |= (1 << 20);
        for(int i = 0; i < 6; ++i) { /* banked_spsr */
                if(!os->isConcrete((1+i)*4, 4*8))
                    mask |= (1 << (i+21));
        }
        for(int i = 0; i < 6; ++i) { /* banked r13 */
                if(!os->isConcrete((7+i)*4, 4*8))
                    mask |= (1 << (i+27));
        }
        for(int i = 0; i < 6; ++i) { /* banked r14 */
                if(!os->isConcrete((13+i)*4, 4*8))
                    mask |= (1 << (i+33));
        }
        for(int i = 0; i < 5; ++i) { /* usr_regs */
                if(!os->isConcrete((19+i)*4, 4*8))
                    mask |= (1 << (i+39));
        }
        for(int i = 0; i < 5; ++i) { /* fiq_regs */
                if(!os->isConcrete((24+i)*4, 4*8))
                    mask |= (1 << (i+44));
        }

    return mask;
}
#endif

bool S2EExecutionStateRegisters::readSymbolicRegion(unsigned offset, void *_buf, unsigned size, bool concretize) const {
#ifdef TARGET_I386
    static const char *regNames[] = {"eax", "ecx", "edx",   "ebx",    "esp",    "ebp",
                                     "esi", "edi", "cc_op", "cc_src", "cc_dst", "cc_tmp"};
    assert(*m_active);
    // assert(((uint64_t) env) == s_symbolicRegs->address);
    assert(offset + size <= CPU_OFFSET(eip));
#elif defined(TARGET_ARM)
    static const char *regNames[] = {
        "spsr",
        //1
        "banked_spsr[0]", "banked_spsr[1]", "banked_spsr[2]", "banked_spsr[3]", "banked_spsr[4]", "banked_spsr[5]",
        //7
        "banked_r13[0]", "banked_r13[1]", "banked_r13[2]", "banked_r13[3]", "banked_r13[4]", "banked_r13[5]",
        //13
        "banked_r14[0]", "banked_r14[1]", "banked_r14[2]", "banked_r14[3]", "banked_r14[4]", "banked_r14[5]",
        //19
        "usr_regs[0]", "usr_regs[1]", "usr_regs[2]", "usr_regs[3]", "usr_regs[4]",
        //24
        "fiq_regs[0]", "fiq_regs[1]", "fiq_regs[2]", "fiq_regs[3]", "fiq_regs[4]",
        //29
        "CF", "VF", "NF", "ZF",
        //33
        "regs[0]", "regs[1]", "regs[2]", "regs[3]", "regs[4]", "regs[5]", "regs[6]", "regs[7]",
        "regs[8]", "regs[9]", "regs[10]" "regs[11]", "regs[12]", "regs[13]", "regs[14]", "regs[15]",
        //49
        "QF", "GE", "thumb", "condexec_bits", "uncached_cpsr",
        "c0_cpuid", "c0_cachetype", 
        //56
        "c0_ccsid[0]", "c0_ccsid[1]", "c0_ccsid[2]", "c0_ccsid[3]",
        "c0_ccsid[4]", "c0_ccsid[5]", "c0_ccsid[6]", "c0_ccsid[7]",
        "c0_ccsid[8]", "c0_ccsid[9]", "c0_ccsid[10]", "c0_ccsid[11]",
        "c0_ccsid[12]", "c0_ccsid[13]", "c0_ccsid[14]", "c0_ccsid[15]",
        //72
        "c0_clid", "c0_cssel",
        "c0_c1[0]", "c0_c1[1]", "c0_c1[2]", "c0_c1[3]", "c0_c1[4]", "c0_c1[5]", "c0_c1[6]", "c0_c1[7]",
        "c0_c2[0]", "c0_c2[1]", "c0_c2[2]", "c0_c2[3]", "c0_c2[4]", "c0_c2[5]", "c0_c2[6]", "c0_c2[7]",
        //90
        "c1_sys", "c1_coproc", "c1_xscaleauxcr", "c1_scr",
        //94
        "c2_base0", "c2_base0_hi", "c2_base1", "c2_base1_hi",
        "c2_control", "c2_mask", "c2_base_mask", "c2_data", "c2_insn",
        //103
        "c3",
        "c5_insn", "c5_data",
        "c6_region[8]",
        "c6_insn", "c6_data",
        "c7_par",
        "c9_insn", "c9_data", "c9_pmcr", "c9_pmcnten",
        "c9_pmovsr", "c9_pmxevtyper", "c9_pmuserenr", "c9_pminten",
        "c13_fcse", "c13_context", "c13_tls1", "c13_tls2", "c13_tls3",
        "c15_cpar", "c15_ticonfig", "c15_i_max", "c15_i_min",
        "c15_threadid", "c15_config_base_address", "c15_diagnostic", "c15_power_diagnostic"};
    assert(*m_active);
    // assert(((uint64_t) env) == s_symbolicRegs->address);
    assert(offset + size <= CPU_OFFSET(regs[15]));
#endif
    /* Simple case, the register is concrete */
    if (likely(*m_runningConcrete &&
               (m_symbolicRegs->isAllConcrete() || m_symbolicRegs->isConcrete(offset, size * 8)))) {
        // XXX: check if the size if always small enough
        small_memcpy(_buf, ((uint8_t *) env) + offset, size);
        return true;
    }

    /* Deal with the symbolic case */
    ObjectState *wos = m_symbolicRegs;
    bool oldAllConcrete = wos->isAllConcrete();

    // XXX: deal with alignment and overlaps?

    ref<Expr> value = wos->read(offset, size * 8);
    uint64_t concreteValue;
    if (!isa<ConstantExpr>(value)) {
        if (!concretize) {
            return false;
        }
        std::string reason =
            std::string("access to ") + regNames[offset / sizeof(target_ulong)] + " register from libcpu helper";

        concreteValue = m_concretizer->concretize(value, reason.c_str());
        wos->write(offset, ConstantExpr::create(concreteValue, size * 8));
    } else {
        ConstantExpr *ce = dyn_cast<ConstantExpr>(value);
        concreteValue = ce->getZExtValue(size * 8);
    }

    bool newAllConcrete = wos->isAllConcrete();
    if ((oldAllConcrete != newAllConcrete) && (wos->getObject()->doNotifyOnConcretenessChange)) {
        m_notification->addressSpaceSymbolicStatusChange(wos, newAllConcrete);
    }

    // XXX: endianness issues on the host...
    small_memcpy(_buf, &concreteValue, size);

#ifdef S2E_TRACE_EFLAGS
    if (offsetof(CPUX86State, cc_src) == offset) {
        m_s2e->getDebugStream() << std::hex << getPc() << "read conc cc_src " << (*(uint32_t *) ((uint8_t *) buf))
                                << '\n';
    }
#endif

    return true;
}

void S2EExecutionStateRegisters::writeSymbolicRegion(unsigned offset, const void *_buf, unsigned size) {
    assert(*m_active);
    assert(((uint64_t) env) == s_symbolicRegs->address);
#ifdef TARGET_I386
    assert(offset + size <= CPU_OFFSET(eip));
#elif defined(TARGET_ARM)
    assert(offset + size <= CPU_OFFSET(regs[15]));
#endif

    const uint8_t *buf = (const uint8_t *) _buf;

    if (likely(*m_runningConcrete &&
               (m_symbolicRegs->isAllConcrete() || m_symbolicRegs->isConcrete(offset, size * 8)))) {
        small_memcpy(((uint8_t *) env) + offset, buf, size);
    } else {

        ObjectState *wos = m_symbolicRegs;
        bool oldAllConcrete = wos->isAllConcrete();

        for (unsigned i = 0; i < size; ++i)
            wos->write8(offset + i, buf[i]);

        bool newAllConcrete = wos->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && (wos->getObject()->doNotifyOnConcretenessChange)) {
            m_notification->addressSpaceSymbolicStatusChange(wos, newAllConcrete);
        }
    }

#ifdef S2E_TRACE_EFLAGS
    if (offsetof(CPUX86State, cc_src) == offset) {
        m_s2e->getDebugStream() << std::hex << getPc() << "write conc cc_src " << (*(uint32_t *) ((uint8_t *) buf))
                                << '\n';
    }
#endif
}

ref<Expr> S2EExecutionStateRegisters::readSymbolicRegion(unsigned offset, Expr::Width width) const {
    assert((width == 1 || (width & 7) == 0) && width <= 64);
#ifdef TARGET_I386 
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(eip));
#elif defined(TARGET_ARM)
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(regs[15]));
#endif
    if (!(*m_runningConcrete) || !m_symbolicRegs->isConcrete(offset, width)) {
        return m_symbolicRegs->read(offset, width);
    } else {
        /* XXX: should we check getSymbolicRegisterMask ? */
        uint64_t ret = 0;
        small_memcpy((void *) &ret, (void *) (s_symbolicRegs->address + offset), Expr::getMinBytesForWidth(width));
        return ConstantExpr::create(ret, width);
    }
}

void S2EExecutionStateRegisters::writeSymbolicRegion(unsigned offset, klee::ref<klee::Expr> value) {
    unsigned width = value->getWidth();
    assert((width == 1 || (width & 7) == 0) && width <= 64);
#ifdef TARGET_I386
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(eip));
#elif defined(TARGET_ARM)
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(regs[15]));
#endif

    if (!(*m_runningConcrete) || !m_symbolicRegs->isConcrete(offset, width)) {
        bool oldAllConcrete = m_symbolicRegs->isAllConcrete();

        m_symbolicRegs->write(offset, value);

        bool newAllConcrete = m_symbolicRegs->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && (m_symbolicRegs->getObject()->doNotifyOnConcretenessChange)) {
            m_notification->addressSpaceSymbolicStatusChange(m_symbolicRegs, newAllConcrete);
        }

    } else {
        /* XXX: should we check getSymbolicRegisterMask ? */
        /* XXX: why don't we allow writing symbolic values here ??? */
        assert(isa<ConstantExpr>(value) && "Cannot write symbolic values to registers while executing"
                                           " in concrete mode. TODO: fix it by fast_longjmping to main loop");
        ConstantExpr *ce = cast<ConstantExpr>(value);
        uint64_t v = ce->getZExtValue(64);
        small_memcpy((void *) (s_symbolicRegs->address + offset), (void *) &v,
                     Expr::getMinBytesForWidth(ce->getWidth()));
    }
}

// XXX: this must be used carefully, especially when running in concrete mode.
// Normally used from concrete helpers to manipulate symbolic data punctually.
void S2EExecutionStateRegisters::writeSymbolicRegionUnsafe(unsigned offset, klee::ref<klee::Expr> value) {
    unsigned width = value->getWidth();
    assert((width == 1 || (width & 7) == 0) && width <= 64);
#ifdef TARGET_I386 
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(eip));
#elif defined(TARGET_ARM)
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(regs[15]));
#endif

    bool oldAllConcrete = m_symbolicRegs->isAllConcrete();

    m_symbolicRegs->write(offset, value);

    bool newAllConcrete = m_symbolicRegs->isAllConcrete();
    if ((oldAllConcrete != newAllConcrete) && (m_symbolicRegs->getObject()->doNotifyOnConcretenessChange)) {
        m_notification->addressSpaceSymbolicStatusChange(m_symbolicRegs, newAllConcrete);
    }
}

/***/

void S2EExecutionStateRegisters::readConcreteRegion(unsigned offset, void *buffer, unsigned size) const {
#ifdef TARGET_I386
    unsigned width = size * 8;
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUX86State, eip));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUX86State));

    const uint8_t *address;
    if (*m_active) {
        address = (uint8_t *) s_concreteRegs->address - CPU_OFFSET(eip);
    } else {
        address = m_concreteRegs->getConcreteStore();
        assert(address);
        address -= CPU_OFFSET(eip);
    }

    small_memcpy(buffer, address + offset, size);
#elif defined(TARGET_ARM)
    unsigned width = size * 8;
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUARMState, regs[15]));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUARMState));

    const uint8_t *address;
    if (*m_active) {
        address = (uint8_t *) s_concreteRegs->address - CPU_OFFSET(regs[15]);
    } else {
	assert(0 && "Should always access SharedConcrete CPU registers\n");
        address = m_concreteRegs->getConcreteStore();
        assert(address);
        address -= CPU_OFFSET(regs[15]);
    }

    small_memcpy(buffer, address + offset, size);
#endif
}

void S2EExecutionStateRegisters::writeConcreteRegion(unsigned offset, const void *buffer, unsigned size) {
#ifdef TARGET_I386
    unsigned width = size * 8;
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUX86State, eip));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUX86State));

    uint8_t *address;
    if (*m_active) {
        address = (uint8_t *) s_concreteRegs->address - CPU_OFFSET(eip);
    } else {
        address = m_concreteRegs->getConcreteStore();
        assert(address);
        address -= CPU_OFFSET(eip);
    }

    small_memcpy(address + offset, buffer, size);
#elif defined(TARGET_ARM)
    unsigned width = size * 8;
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUARMState, regs[15]));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUARMState));

    uint8_t *address;
    if (*m_active) {
        address = (uint8_t *) s_concreteRegs->address - CPU_OFFSET(regs[15]);
    } else {
	assert(0 && "Should always access SharedConcrete CPU registers\n");
        address = m_concreteRegs->getConcreteStore();
        assert(address);
        address -= CPU_OFFSET(regs[15]);
    }

    small_memcpy(address + offset, buffer, size);
#endif
}

bool S2EExecutionStateRegisters::getRegionType(unsigned offset, unsigned size, bool *isConcrete) {
#ifdef TARGET_I386
    if (offset + size <= offsetof(CPUX86State, eip)) {
        *isConcrete = false;
        return true;
    } else if (offset >= offsetof(CPUX86State, eip)) {
        *isConcrete = true;
        return true;
    } else {
        return false;
    }
#elif defined(TARGET_ARM)
    if (offset + size <= offsetof(CPUARMState, regs[15])) {
        *isConcrete = false;
        return true;
    } else if (offset >= offsetof(CPUARMState, regs[15])) {
        *isConcrete = true;
        return true;
    } else {
        return false;
    }
#endif
}

/**
 * The architectural part of the concrete portion of CPUState contains the COMMON stuff.
 * We skip this stuff in the comparison.
 */
int S2EExecutionStateRegisters::compareArchitecturalConcreteState(const S2EExecutionStateRegisters &other) {
#ifdef TARGET_I386
    CPUX86State *a = getCpuState();
    CPUX86State *b = other.getCpuState();
    int ret = memcmp(&a->eip, &b->eip, CPU_OFFSET(se_common_start) - CPU_OFFSET(eip));
    if (ret) {
        return ret;
    }

    ret = memcmp(&a->se_common_end, &b->se_common_end, sizeof(CPUX86State) - CPU_OFFSET(se_common_end));
    return ret;
#elif defined(TARGET_ARM)
    CPUARMState *a = getCpuState();
    CPUARMState *b = other.getCpuState();
    int ret = memcmp(&a->regs[15], &b->regs[15], CPU_OFFSET(se_common_start) - CPU_OFFSET(regs[15]));
    if (ret) {
        return ret;
    }

    ret = memcmp(&a->se_common_end, &b->se_common_end, sizeof(CPUARMState) - CPU_OFFSET(se_common_end));
    return ret;
#endif
}

/***/

klee::ref<klee::Expr> S2EExecutionStateRegisters::read(unsigned offset, klee::Expr::Width width) const {
    bool isConcrete = false;
    unsigned size = klee::Expr::getMinBytesForWidth(width);
    if (!getRegionType(offset, size, &isConcrete)) {
        return nullptr;
    }

    if (isConcrete) {
        switch (width) {
            case klee::Expr::Bool:
                return klee::ConstantExpr::create(read<uint8>(offset) & 1, width);
            case klee::Expr::Int8:
                return klee::ConstantExpr::create(read<uint8>(offset), width);
            case klee::Expr::Int16:
                return klee::ConstantExpr::create(read<uint16>(offset), width);
            case klee::Expr::Int32:
                return klee::ConstantExpr::create(read<uint32>(offset), width);
            case klee::Expr::Int64:
                return klee::ConstantExpr::create(read<uint64>(offset), width);
            default:
                return nullptr;
        }
    } else {
        return readSymbolicRegion(offset, width);
    }
}

bool S2EExecutionStateRegisters::read(unsigned offset, void *buffer, unsigned size, bool concretize) const {
    bool isConcrete = false;
    if (!getRegionType(offset, size, &isConcrete)) {
        return false;
    }

    if (isConcrete) {
        readConcreteRegion(offset, buffer, size);
        return true;
    } else {
        return readSymbolicRegion(offset, buffer, size, concretize);
    }
}

bool S2EExecutionStateRegisters::write(unsigned offset, const void *buffer, unsigned size) {
    bool isConcrete = false;
    if (!getRegionType(offset, size, &isConcrete)) {
        return false;
    }

    if (isConcrete) {
        writeConcreteRegion(offset, buffer, size);
    } else {
        writeSymbolicRegion(offset, buffer, size);
    }

    return true;
}

bool S2EExecutionStateRegisters::write(unsigned offset, const klee::ref<klee::Expr> &value) {
    bool isConcrete = false;
    unsigned size = klee::Expr::getMinBytesForWidth(value->getWidth());
    if (!getRegionType(offset, size, &isConcrete)) {
        return false;
    }

    if (isConcrete) {
        uint64_t val = m_concretizer->concretize(value, "Writing symbolic value to concrete area");
        writeConcreteRegion(offset, &val, size);
    } else {
        writeSymbolicRegion(offset, value);
    }

    return true;
}

// Get the program counter in the current state.
// Allows plugins to retrieve it in a hardware-independent manner.
uint64_t S2EExecutionStateRegisters::getPc() const {
#ifdef TARGET_ARM
    return read<target_ulong>(CPU_OFFSET(regs[15]));
#elif defined(TARGET_I386)
    return read<target_ulong>(CPU_OFFSET(eip));
#endif
}

void S2EExecutionStateRegisters::setPc(uint64_t pc) {
#ifdef TARGET_ARM
    write<target_ulong>(CPU_OFFSET(regs[15]), pc);
#elif defined(TARGET_I386)
    write<target_ulong>(CPU_OFFSET(eip), pc);
#endif
}

uint64_t S2EExecutionStateRegisters::getSp() const {
#ifdef TARGET_ARM
    return read<target_ulong>(CPU_OFFSET(regs[13]));
#elif defined(TARGET_I386)
    return read<target_ulong>(CPU_OFFSET(regs[R_ESP]));
#endif
}

void S2EExecutionStateRegisters::setSp(uint64_t sp) {
#ifdef TARGET_ARM
    write<target_ulong>(CPU_OFFSET(regs[13]), sp);
#elif defined(TARGET_I386)
    write<target_ulong>(CPU_OFFSET(regs[R_ESP]), sp);
#endif
}

uint64_t S2EExecutionStateRegisters::getBp() const {
#ifdef TARGET_ARM
    return read<target_ulong>(CPU_OFFSET(regs[11]));
#elif defined(TARGET_I386)
    return read<target_ulong>(CPU_OFFSET(regs[R_EBP]));
#endif
}

void S2EExecutionStateRegisters::setBp(uint64_t bp) {
#ifdef TARGET_ARM
    write<target_ulong>(CPU_OFFSET(regs[11]), bp);
#elif defined(TARGET_I386)
    write<target_ulong>(CPU_OFFSET(regs[R_EBP]), bp);
#endif
}

uint64_t S2EExecutionStateRegisters::getPageDir() const {
#ifdef TARGET_ARM
    return read<target_ulong>(CPU_OFFSET(cp15.c2_base0));
#elif defined(TARGET_I386)
    return read<target_ulong>(CPU_OFFSET(cr[3]));
#endif
}

uint64_t S2EExecutionStateRegisters::getFlags() {
#ifdef TARGET_ARM
	assert(false && "S2EExecutionStateRegisters::getFlags failed\n");
#elif defined(TARGET_I386)
    /* restore flags in standard format */
    cpu_restore_eflags(env);
    return cpu_get_eflags(env);
#endif
}

/// \brief Print register values
///
/// \param ss output stream
///
void S2EExecutionStateRegisters::dump(std::ostream &ss) const {
    std::ostringstream concreteBytes;
    std::ostringstream symbolicBytes;

#define PRINT_REG(name)                                                                          \
    do {                                                                                         \
        ref<Expr> reg;                                                                           \
        /* TODO: use state->getPointerWidth() instead of Expr::Int32. */                         \
        /* It currenly fails because se_current_tb is NULL after state switch. */                \
        reg = readSymbolicRegion(CPU_OFFSET(regs[R_##name]), Expr::Int32);                       \
        concreteBytes << #name << " ";                                                           \
        for (int i = reg->getWidth() / CHAR_BIT - 1; i >= 0; i--) {                              \
            ref<Expr> byte = E_EXTR(reg, i * CHAR_BIT, Expr::Int8);                              \
            if (isa<ConstantExpr>(byte)) {                                                       \
                concreteBytes << hexval(dyn_cast<ConstantExpr>(byte)->getZExtValue(), 2, false); \
            } else {                                                                             \
                concreteBytes << "SS";                                                           \
                symbolicBytes << #name << "[" << i << "] " << byte << "\n";                      \
            }                                                                                    \
        }                                                                                        \
        concreteBytes << "\n";                                                                   \
    } while (0)
	assert(false && "PRINT_REG");
    ss << "Registers\n" << concreteBytes.str() << symbolicBytes.str();
}
}
