/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Hsin-Wei Hung<hsinweih@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "LibcMemoryChecker.h"

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <cpu/se_libcpu.h>
#include <cpu/tb.h>
#include <cpu/exec.h>
#include <klee/Solver.h>
#include <klee/util/ExprTemplates.h>

#include <ctime>
#include <sstream>

extern llvm::cl::opt<bool> ConcolicMode;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LibcMemoryChecker, "Check libc memory allocation", "LibcMemoryChecker",
                  "ProcessMonitor");


void LibcMemoryChecker::initialize()
{
    ConfigFile *cfg = s2e()->getConfig();

    m_debugLevel = cfg->getInt(getConfigKey() + ".debugLevel", 0);

    m_libcFunctions.resize(LIBC_MEM_FUNC_NUM, LibcFunction("", 3, 0));

    m_libcFunctions.at(LIBC_FREE) =
            LibcFunction("free", 1, cfg->getInt(getConfigKey() + ".freeOffset"));
    m_libcFunctions.at(LIBC_FREE).call_handler = &LibcMemoryChecker::onFreeCall;

    m_libcFunctions.at(LIBC_MALLOC) =
            LibcFunction("malloc", 1, cfg->getInt(getConfigKey() + ".mallocOffset"));
    m_libcFunctions.at(LIBC_MALLOC).return_handler = &LibcMemoryChecker::onMallocReturn;

    m_libcFunctions.at(LIBC_CALLOC) =
            LibcFunction("calloc", 2, cfg->getInt(getConfigKey() + ".callocOffset"));
    m_libcFunctions.at(LIBC_CALLOC).return_handler = &LibcMemoryChecker::onCallocReturn;

    m_libcFunctions.at(LIBC_REALLOC) =
            LibcFunction("realloc", 2, cfg->getInt(getConfigKey() + ".reallocOffset"));
    m_libcFunctions.at(LIBC_REALLOC).return_handler = &LibcMemoryChecker::onReallocReturn;

    m_libcFunctions.at(LIBC_MEMALIGN) =
            LibcFunction("memalign", 2, cfg->getInt(getConfigKey() + ".memalignOffset"));
    m_libcFunctions.at(LIBC_MEMALIGN).return_handler = &LibcMemoryChecker::onMemalignReturn;

    m_libcFunctions.at(LIBC_POSIX_MEMALIGN) =
            LibcFunction("posix_memalign", 3, cfg->getInt(getConfigKey() + ".posixMemalignOffset"));
    m_libcFunctions.at(LIBC_POSIX_MEMALIGN).return_handler = &LibcMemoryChecker::onPosixMemalignReturn;

    m_libcFunctions.at(LIBC_ALIGNED_ALLOC) =
            LibcFunction("aligned_alloc", 2, cfg->getInt(getConfigKey() + ".alignedAllocOffset"));
    m_libcFunctions.at(LIBC_ALIGNED_ALLOC).return_handler = &LibcMemoryChecker::onAlignedAllocReturn;

    m_libcFunctions.at(LIBC_PVALLOC) =
            LibcFunction("pvalloc", 1, cfg->getInt(getConfigKey() + ".pvallocOffset"));
    m_libcFunctions.at(LIBC_PVALLOC).return_handler = &LibcMemoryChecker::onPvallocReturn;

    m_libcFunctions.at(LIBC_VALLOC) =
            LibcFunction("valloc", 1, cfg->getInt(getConfigKey() + ".vallocOffset"));
    m_libcFunctions.at(LIBC_VALLOC).return_handler = &LibcMemoryChecker::onVallocReturn;

    m_checkDoubleFreeBug = cfg->getBool(getConfigKey() + ".checkDoubleFreeBug", false);

    m_pm = s2e()->getPlugin<ProcessMonitor>();
    assert(m_pm);

    m_sm = s2e()->getPlugin<StackMonitor>();
    assert(m_sm);

//    s2e()->getCorePlugin()->onTranslateRegisterAccessEnd.connect(
//            sigc::mem_fun(*this, &LibcMemoryChecker::onTranslateRegisterAccess));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &LibcMemoryChecker::onTranslateBlockEnd));

    s2e()->getCorePlugin()->onTranslateJumpStart.connect(
            sigc::mem_fun(*this, &LibcMemoryChecker::onTranslateJumpStart));
}

void LibcMemoryChecker::emitOnBugDetected(S2EExecutionState *state, uint32_t bug,
                                          StackMonitor::CallStack *cs)
{
    uint64_t pc = state->regs()->getPc();
    std::string file = m_pm->getFileName(pc);
    uint32_t offset = m_pm->getOffsetWithinFile(file, pc);

    uint32_t insn;
    if (!state->mem()->read<uint32_t>(pc, &insn, VirtualAddress, false)) {
        getWarningsStream(state) << "cannot get instruction at " << hexval(pc);
        insn = 0xffffffff;
    }

    if (cs == NULL)
        onBugDetected.emit(state, bug, offset, insn, file, m_bugInputs);
    else
        onBugDetected2.emit(state, bug, offset, insn, file, m_bugInputs, cs);
}

void LibcMemoryChecker::libcAllocateMemory(S2EExecutionState *state, uint32_t addr, uint32_t size)
{
    m_allocatedRegions.push_back(std::make_pair(addr, addr + size));

    for (auto it = m_freeAddresses.begin(); it != m_freeAddresses.end(); it++) {
        if (it->addr == addr) {
            m_freeAddresses.erase(it);
            break;
        }
    }
}

void LibcMemoryChecker::onMallocReturn(S2EExecutionState *state, uint64_t pc)
{
    uint32_t size = m_libcFunctions.at(LIBC_MALLOC).args[0];
    uint32_t ret = m_libcFunctions.at(LIBC_MALLOC).ret;

    if (ret != 0)
        libcAllocateMemory(state, ret, size);
}

void LibcMemoryChecker::onCallocReturn(S2EExecutionState *state, uint64_t pc)
{
    uint32_t size = m_libcFunctions.at(LIBC_CALLOC).args[1] * m_libcFunctions.at(LIBC_CALLOC).args[0];
    uint32_t ret = m_libcFunctions.at(LIBC_CALLOC).ret;

    if (ret != 0)
        libcAllocateMemory(state, ret, size);
}

void LibcMemoryChecker::onReallocReturn(S2EExecutionState *state, uint64_t pc)
{
    uint32_t addr = m_libcFunctions.at(LIBC_REALLOC).args[0];
    uint32_t size = m_libcFunctions.at(LIBC_REALLOC).args[1];
    uint32_t ret = m_libcFunctions.at(LIBC_REALLOC).ret;

    for (auto& region : m_allocatedRegions) {
        if (addr == region.first) {
            region.first = ret;
            region.second = ret + size;
        }
    }

    for (auto it = m_freeAddresses.begin(); it != m_freeAddresses.end(); it++) {
        if (it->addr == ret) {
            m_freeAddresses.erase(it);
            break;
        }
    }
}

void LibcMemoryChecker::onMemalignReturn(S2EExecutionState *state, uint64_t pc)
{
    uint32_t size = m_libcFunctions.at(LIBC_MEMALIGN).args[1];
    uint32_t ret = m_libcFunctions.at(LIBC_MEMALIGN).ret;

    if (ret != 0)
        libcAllocateMemory(state, ret, size);
}

void LibcMemoryChecker::onPosixMemalignReturn(S2EExecutionState *state, uint64_t pc)
{
    uint32_t addr = m_libcFunctions.at(LIBC_POSIX_MEMALIGN).args[0];
    uint32_t size = m_libcFunctions.at(LIBC_POSIX_MEMALIGN).args[2];
    uint32_t ret = m_libcFunctions.at(LIBC_POSIX_MEMALIGN).ret;

    if (ret != 0)
        libcAllocateMemory(state, addr, size);
}

void LibcMemoryChecker::onAlignedAllocReturn(S2EExecutionState *state, uint64_t pc)
{
    uint32_t size = m_libcFunctions.at(LIBC_POSIX_MEMALIGN).args[1];
    uint32_t ret = m_libcFunctions.at(LIBC_POSIX_MEMALIGN).ret;

    if (ret != 0)
        libcAllocateMemory(state, ret, size);
}

void LibcMemoryChecker::onPvallocReturn(S2EExecutionState *state, uint64_t pc)
{
    uint32_t size = m_libcFunctions.at(LIBC_PVALLOC).args[0];
    uint32_t ret = m_libcFunctions.at(LIBC_PVALLOC).ret;

    if (ret != 0)
        libcAllocateMemory(state, ret, size);
}

void LibcMemoryChecker::onVallocReturn(S2EExecutionState *state, uint64_t pc)
{
    uint32_t size = m_libcFunctions.at(LIBC_VALLOC).args[0];
    uint32_t ret = m_libcFunctions.at(LIBC_VALLOC).ret;

    if (ret != 0)
        libcAllocateMemory(state, ret, size);
}

void LibcMemoryChecker::onReturn(S2EExecutionState *state, uint64_t pc)
{
    if (m_debugLevel > 2) {
        uint32_t ret;
        if (!state->regs()->read(CPU_OFFSET(regs[0]), &ret, sizeof(ret), klee::Expr::Int32))
            getWarningsStream(state) << "cannot get return value (r0)\n";
        getWarningsStream(state) << "function return at " << hexval(pc)
                << " ret = " << hexval(ret) << "\n";
    }

    for (auto& func : m_libcFunctions) {
        if (func.call_depth > 0) {
            int callDepth = m_sm->getCallStackDepth(state, 1, pthread_self());
            if (callDepth == func.call_depth - 1 && func.return_handler != NULL) {
                uint32_t ret;
                if (!state->regs()->read(CPU_OFFSET(regs[0]), &ret, sizeof(ret), klee::Expr::Int32))
                    getWarningsStream(state) << "cannot get return value (r0)\n";

                if (m_debugLevel > 1) {
                    getWarningsStream(state) << hexval(pc) << " libc " << func.name
                            << " return " << hexval(ret) << "\n";
                }

                func.ret = ret;
                func.call_depth = 0;
                (this->*func.return_handler)(state, pc);
            }
        }
    }
}

void LibcMemoryChecker::onFreeCall(S2EExecutionState *state)
{
    uint32_t doubleFreeBug = 0;
    std::stringstream err;

#if defined(TARGET_I386)
    klee::ref<klee::Expr> ptrExpr =
            state->regs()->read(CPU_OFFSET(regs[R_EDI]), state->getPointerWidth());
#elif defined(TARGET_ARM)
    klee::ref<klee::Expr> ptrExpr =
            state->regs()->read(CPU_OFFSET(regs[0]), state->getPointerWidth());
#endif

    uint64_t ptrValue;
    unsigned i;
    if (ptrExpr->getKind() != klee::Expr::Constant) {
        for (i = 0; i < m_freeAddresses.size(); i++) {
            klee::ref<klee::Expr> previousFreeAddress =
                    E_CONST(m_freeAddresses.at(i).addr, state->getPointerWidth());
            klee::ref<klee::Expr> sameFreeAddressExpr =
                    klee::EqExpr::create(previousFreeAddress, ptrExpr);
            if (assume(state, sameFreeAddressExpr)) {
                doubleFreeBug = BUG_S_LIBC_DOUBLEFREE;
                err << "BUG: potential double free pointer " << ptrExpr << "\n"
                    << "    Instruction: " << getPrettyCodeLocation(state) << "\n";
                break;
            }
        }
    } else {
        ptrValue = cast<klee::ConstantExpr>(ptrExpr)->getAPValue().getLimitedValue();
        if (ptrValue != 0) {
            for (i = 0; i < m_freeAddresses.size(); i++) {
                if (ptrValue == m_freeAddresses.at(i).addr) {
                    doubleFreeBug = BUG_C_LIBC_DOUBLEFREE;
                    err << "BUG: double free pointer " << hexval(ptrValue) << "\n"
                        << "    Instruction: " << getPrettyCodeLocation(state) << "\n";
                    break;
                }
            }
        }
    }

    if (doubleFreeBug != 0) {
        emitOnBugDetected(state, doubleFreeBug, &m_freeAddresses.at(i).cs);
        s2e()->getWarningsStream(state) << err.str();
        s2e()->getWarningsStream(state) << "call stack of previous free\n";
        m_sm->printCallStack(state, m_freeAddresses.at(i).cs);
    } else {
        uint32_t addr = 0;
        if (!state->regs()->read(CPU_OFFSET(regs[0]), &addr, sizeof(addr), klee::Expr::Int32)) {
            getWarningsStream(state) << "cannot get arg1 (r0)\n";
            return;
        }

        if (addr != 0) {
            StackMonitor::CallStack cs;
            m_sm->getCallStack(state, 1, pthread_self(), cs);
            m_freeAddresses.push_back(FreeRecord(addr, cs));

            auto region = m_allocatedRegions.begin();
            for (; region != m_allocatedRegions.end(); region++) {
                if (addr == region->first) {
                    break;
                }
            }
            m_allocatedRegions.erase(region);
        }
    }


}

void LibcMemoryChecker::onCall(S2EExecutionState *state, uint64_t pc)
{
    if (m_debugLevel > 2) {
        getDebugStream(state) << "function call at " << hexval(pc)
                << " thread " << hexval(pthread_self()) <<"\n";
    }
}

void LibcMemoryChecker::onTranslateRegisterAccess(ExecutionSignal *signal, S2EExecutionState *state,
                                                  TranslationBlock *tb, uint64_t pc, uint64_t rmask,
                                                  uint64_t wmask, bool accessesMemory)
{
    if ((wmask & (1 << 14 | 1 << 15)) && tb->se_tb_type == TB_CALL_IND)
        signal->connect(sigc::mem_fun(*this, &LibcMemoryChecker::onCall));
}

void LibcMemoryChecker::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                            TranslationBlock *tb, uint64_t pc, bool isStatic,
                                            uint64_t staticTarget)
{
    if (tb->se_tb_type == TB_RET)
        signal->connect(sigc::mem_fun(*this, &LibcMemoryChecker::onReturn));
}

void LibcMemoryChecker::onAbortCall(S2EExecutionState *state)
{
    getWarningsStream(state) << "abort called\n";
    ConcreteInputs state_inputs;
    bool success = s2e()->getExecutor()->getSymbolicSolution(*state, state_inputs);
    if (success) {
        printConcreteInputs(getWarningsStream(state), state_inputs);
    }
}

void LibcMemoryChecker::onPthreadCondTimewaitCall(S2EExecutionState *state)
{
    uint32_t arg3;
    if (!state->regs()->read(CPU_OFFSET(regs[2]), &arg3, sizeof(arg3), klee::Expr::Int32))
        getWarningsStream(state) << "cannot get arg3 (r2)\n";

    getWarningsStream(state) << "Overwrite pthread_cond_timewait arguement\n";
    struct timespec *tp = (struct timespec *)arg3;
    tp->tv_sec += 10;
}

static uint8_t libc_mem_alloc_size_reg[9] = {0, 1, 3, 2, 2, 4, 1, 1, 2};
bool LibcMemoryChecker::isSizeArgReg(unsigned func, unsigned reg)
{
    return libc_mem_alloc_size_reg[func] & (1 << reg);
}

int LibcMemoryChecker::whichLibcFunction(uint32_t pc)
{
    std::string libc("/system/lib/libc.so");
    for (unsigned i = 0; i < LIBC_MEM_FUNC_NUM; i++) {
        if (pc == m_pm->getAddressWithinFile(libc, m_libcFunctions.at(i).offset))
            return i;
    }
    return LIBC_MEM_FUNC_NUM;
}

/**
 *  Record the target of the indirect PLT brach at the first time and then
 *  check if it is a libc function of our interest
 *  ldr pc, [ip, #imm12]!
 *
 *  The signal is emitted right after the target pc being written to ip
 *  and before the jump
 */
void LibcMemoryChecker::onIndirectPLTBranch(S2EExecutionState *state, uint64_t pc)
{
    uint32_t target_pc = m_PLTMap[pc];
    // Store target pc when branching to the address for the first time
    if (target_pc == 0xffffffff) {
        uint32_t rn;
        if (!state->regs()->read(CPU_OFFSET(regs[12]), &rn, sizeof(rn), klee::Expr::Int32))
            getWarningsStream(state) << "cannot get ip (r12)\n";

        if (!state->mem()->read<uint32_t>(rn, &target_pc, VirtualAddress, false))
            getWarningsStream(state) << "cannot get target_pc at " << hexval(rn);

        // lsb indicates if we are branching into thumb mode
        target_pc &= 0xfffffffe;
        m_PLTMap[pc] = target_pc;

        // Update process memory map if the target pc is unknown
        if (m_pm->isAddressUnknown(target_pc))
            m_pm->updateProcessAddressMap("/system/lib/libc.so", target_pc);

//        uint64_t offset;
//        std::string file = m_pm->getFileName(target_pc, offset);
//        getWarningsStream(state) << hexval(pc) << " jumping to " << file << ":" << hexval(offset) << "\n";
    }

    // Check if we are jumping to libc functions of interest
    unsigned func = whichLibcFunction(target_pc);
    if (func < LIBC_MEM_FUNC_NUM) {
        std::stringstream ss;
        LibcFunction *function = &m_libcFunctions.at(func);
        for (unsigned i = 0; i < function->argc; i++) {
            // check if the size of memory allocation function is symbolic
            if (isSizeArgReg(func, i)) {
                klee::ref<klee::Expr> sizeExpr =
                        state->regs()->read(CPU_OFFSET(regs[i]), state->getPointerWidth());
                if (!isa<klee::ConstantExpr>(sizeExpr)) {
                    std::pair<uint64_t, uint64_t > range = checkRange(state, sizeExpr);
                    if (range.first != range.second) {
                        getWarningsStream(state) << "libc " << function->name
                                << " called with symbolic size range ("
                                <<  hexval(range.first) << "-" << hexval(range.second) <<"\n";
                    }
                }
            }

            // record the concrete arguments
            if (!state->regs()->read(CPU_OFFSET(regs[i]), &function->args[i], 4, klee::Expr::Int32)) {
                getWarningsStream(state) << "cannot read argument (r" << i << ")\n";
                return;
            }
            if (m_debugLevel > 1) {
                ss << hexval(function->args[i]);
                if (i < function->argc - 1)
                    ss << ", ";
            }
        }

        if (m_debugLevel > 1) {
            getWarningsStream(state) << hexval(pc)
                    << " libc " << function->name << "(" << ss.str() << ") called"
                    << " (" << m_pm->getFileName(pc) << ")"
                    << " thread " << hexval(pthread_self()) << "\n";
            m_sm->printCallStack(state);
        }

//        function->call_depth = function->call_depth_init;
        function->call_depth = m_sm->getCallStackDepth(state, 1, pthread_self());

        if (function->call_handler != NULL)
            (this->*function->call_handler)(state);
    }

    uint64_t offset;
    std::string file = m_pm->getFileName(target_pc, offset);
    if (offset == 0x1cdfc) {
        fprintf(stderr, "onAbortCall\n");
        onAbortCall(state);
    }

//    if (offset == 0x477ac)
//        onPthreadCondTimewaitCall(state);
}

void LibcMemoryChecker::onTranslateJumpStart(ExecutionSignal *signal, S2EExecutionState *state,
                                             TranslationBlock *tb, uint64_t pc, int jump_type)
{
    if (jump_type == JT_PLT) {
        signal->connect(sigc::mem_fun(*this, &LibcMemoryChecker::onIndirectPLTBranch));
        auto it = m_PLTMap.find(pc);
        if (it == m_PLTMap.end()) {
            m_PLTMap[pc] = (uint64_t)-1;
        }
    }
}

void LibcMemoryChecker::printConcreteInputs(llvm::raw_ostream &os, const ConcreteInputs &inputs) {
    std::stringstream ss;
    for (auto& it : inputs) {
        const VarValuePair &vp = it;
        ss << std::setw(20) << vp.first << " = {";

        for (unsigned i = 0; i < vp.second.size(); ++i) {
            if (i != 0)
                ss << ", ";
            ss << std::setw(2) << std::setfill('0') << "0x" << std::hex
                    << (unsigned) vp.second[i] << std::dec;
        }
        ss << "}" << std::setfill(' ') << "; ";

        if (vp.second.size() == sizeof(int32_t)) {
            int32_t valueAsInt = vp.second[0] | ((int32_t) vp.second[1] << 8) |
                    ((int32_t) vp.second[2] << 16) | ((int32_t) vp.second[3] << 24);
            ss << "(int32_t) " << valueAsInt << ", ";
        }

        if (vp.second.size() == sizeof(int64_t)) {
            int64_t valueAsInt = vp.second[0] | ((int64_t) vp.second[1] << 8) |
                    ((int64_t) vp.second[2] << 16) | ((int64_t) vp.second[3] << 24) |
                    ((int64_t) vp.second[4] << 32) | ((int64_t) vp.second[5] << 40) |
                    ((int64_t) vp.second[6] << 48) | ((int64_t) vp.second[7] << 56);
            ss << "(int64_t) " << valueAsInt << ", ";
        }

        ss << "(string) \"";
        for (unsigned i = 0; i < vp.second.size(); ++i) {
            ss << (char) (std::isprint(vp.second[i]) ? vp.second[i] : '.');
        }
        ss << "\"\n";
    }
    os << "concrete inputs:\n" << ss.str();
}

// Check if the experssion could have multiple feasible value under current constriants
std::pair<uint64_t, uint64_t> LibcMemoryChecker::checkRange(S2EExecutionState *state, klee::ref<klee::Expr> expr)
{
    std::pair<klee::ref<klee::Expr>, klee::ref<klee::Expr>> range;
    klee::Query query(state->constraints, expr);

    range = s2e()->getExecutor()->getSolver(*state)->getRange(query);

    uint64_t min = dyn_cast<klee::ConstantExpr>(range.first)->getZExtValue();
    uint64_t max = dyn_cast<klee::ConstantExpr>(range.second)->getZExtValue();

//    getWarningsStream(state) << "checkRange min = " << hexval(min) << " max = " << hexval(max) << "\n";

    return std::make_pair(min, max);
}

bool LibcMemoryChecker::assume(S2EExecutionState *state, klee::ref<klee::Expr> expr)
{
    getDebugStream(state) << "assume: " << expr <<"\n";
    klee::ref<klee::Expr> zero = klee::ConstantExpr::create(0, expr.get()->getWidth());
    klee::ref<klee::Expr> boolexpr = klee::NeExpr::create(expr, zero);

    bool isValid = true;
    // check if expr may be true under current path constraints
    bool truth;
    klee::Solver *solver = s2e()->getExecutor()->getSolver(*state);
    klee::Query query(state->constraints, boolexpr);
    bool res = solver->mustBeTrue(query.negateExpr(), truth);
    if (!res || truth) {
        isValid = false;
    }

    if (!isValid) {
        std::stringstream ss;
        ss << "LibcMemoryChecker: specified constraint cannot be satisfied "
           << expr;
    } else {
        std::vector<std::vector<unsigned char>> values;
        std::vector<const klee::Array *> objects;

        for (auto it : state->symbolics) {
            objects.push_back(it.second);
        }

        klee::ConstraintManager tmpConstraints = state->constraints;
        tmpConstraints.addConstraint(expr);
//        ConcreteInputs inputs;
        m_bugInputs.clear();
        isValid = solver->getInitialValues(
                klee::Query(tmpConstraints, klee::ConstantExpr::alloc(0, klee::Expr::Bool)), objects, values);
        assert(isValid && "should be solvable");

        for (unsigned i = 0; i != state->symbolics.size(); ++i) {
            m_bugInputs.push_back(
                    std::make_pair(state->symbolics[i].first->name, values[i]));
        }

        printConcreteInputs(getWarningsStream(state), m_bugInputs);
    }

    return isValid;
}

/*
bool LibcMemoryChecker::checkSymbolicUnallocatedHeapAccess(S2EExecutionState *state,
                                                          klee::ref<klee::Expr> addr)
{
    m_pm->updateProcessAddressMap("[anon:libc_malloc]", 0xffffffff);

    bool notAllocated = true;
    if (isAddressWithinFile(addr, "[anon:libc_malloc]")) {
        for (auto region : m_allocatedRegions) {
            if (addr >= region.first && addr + size < region.second) {
                notAllocated = false;
                break;
            }
        }
    }

    if (notAllocated) {
        err << "LibcMemoryChecker::checkMemoryAccess: "
                << "BUG: memory range at " << hexval(addr) << " of size " << hexval(size)
                << " can not be accessed by instruction " << getPrettyCodeLocation(state)
                << ": using not allocated region in heap" << '\n';
        emitOnBugDetected(state, BUG_C_LIBC_UNALLOCHEAP);
    }
    return notAllocated;
}*/

bool LibcMemoryChecker::checkUnallocatedHeapAccess(S2EExecutionState *state, uint64_t addr,
                                                  int size, llvm::raw_ostream &err)
{
    if (m_pm->isAddressUnknown(addr))
        m_pm->updateProcessAddressMap("[anon:libc_malloc]", addr + size);

    bool notAllocated = true;
    if (m_pm->isAddressWithinFile(addr, "[anon:libc_malloc]")) {
        for (auto region : m_allocatedRegions) {
            if (addr >= region.first && addr + size < region.second) {
                notAllocated = false;
                break;
            }
        }
    }

    if (notAllocated) {
        err << "LibcMemoryChecker::checkMemoryAccess: "
                << "BUG: memory range at " << hexval(addr) << " of size " << hexval(size)
                << " can not be accessed by instruction " << getPrettyCodeLocation(state)
                << ": using not allocated region in heap" << '\n';
        emitOnBugDetected(state, BUG_C_LIBC_UNALLOCHEAP);
    }
    return notAllocated;
}

std::string LibcMemoryChecker::getPrettyCodeLocation(S2EExecutionState *state)
{
    std::stringstream ss;
    uint64_t offset;
    uint64_t pc = state->regs()->getPc();
    uint32_t insn;
    std::string file = m_pm->getFileName(pc, offset);
    if (!state->mem()->read<uint32_t>(pc, &insn, VirtualAddress, false)) {
        getWarningsStream(state) << "cannot get instruction at " << hexval(pc);
    }
    ss << hexval(insn) << " @" << hexval(pc) << " (" << file << ":" << hexval(offset) << ")";
    return ss.str();
}

} // namespace plugins
} // namespace s2e
