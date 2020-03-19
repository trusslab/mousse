/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Hsin-Wei Hung<hsinweih@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "MemoryBugChecker.h"

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <cpu/se_libcpu.h>
#include <cpu/tb.h>
#include <cpu/exec.h>

#include <klee/Solver.h>
#include <klee/util/ExprTemplates.h>
#include <klee/Internal/ADT/ImmutableMap.h>
#include "klee/util/ExprPPrinter.h"

#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <sstream>

extern llvm::cl::opt<bool> ConcolicMode;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MemoryBugChecker, "MemoryBugChecker plugin", "MemoryBugChecker",
                  "ExecutionTracer");

namespace {
    struct MemoryRange {
        uint64_t start;
        uint64_t size;
    };

    //Used to track OS resources that are accessed
    //through a handle
    struct ResourceHandle {
        uint64_t allocPC;
        std::string type;
        uint64_t handle;
    };

    //XXX: Should also add per-module permissions
    struct MemoryRegion {
        MemoryRange range;
        uint64_t perms;
        uint64_t allocPC;
        std::string type;
        uint64_t id;
        bool permanent;
    };

    struct StoreAttribute {
        bool stack; //true: stack; false: heap
        bool local; //true: only access within stack frame, false: only access memory beyond current stack frame
        uint64_t framePC; // if the write is to stack and not local
    };

    struct MemoryRangeLT {
        bool operator()(const MemoryRange& a, const MemoryRange& b) const {
            return a.start + a.size <= b.start;
        }
    };

    typedef klee::ImmutableMap<MemoryRange, const MemoryRegion*,
                               MemoryRangeLT> MemoryMap;

    typedef std::map<uint64_t /*pc of the str*/, StoreAttribute> StoreMap;

} // namespace

inline bool is_aligned(uint64_t addr)
{
    return !(addr % TARGET_PAGE_SIZE); 
}

uint64_t align(uint64_t addr, bool floor)
{
    uint64_t add = floor? 0: is_aligned(addr)? 0: 1;
    return (addr/TARGET_PAGE_SIZE + add) * TARGET_PAGE_SIZE;
}

class MemoryBugCheckerState: public PluginState
{
public:
    uint64_t m_brkAddress;
    uint64_t m_brkPageAddress;

    MemoryBugChecker* m_plugin;
    MemoryMap m_memoryMap;
    StoreMap m_storeMap;

public:
    MemoryBugCheckerState() {}
    ~MemoryBugCheckerState() {}

    MemoryBugCheckerState *clone() const { return new MemoryBugCheckerState(*this); }
    static PluginState *factory(Plugin* p, S2EExecutionState* s) {
        MemoryBugCheckerState *ret = new MemoryBugCheckerState();
        ret->m_plugin = static_cast<MemoryBugChecker *>(p);
        return ret;
    }

    uint64_t &getBRKAddress() { return m_brkAddress; }

    uint64_t &getBRKPageAddress() { return m_brkPageAddress; }

    void setBRKAddress(uint64_t addr) { 
        m_brkAddress = addr; 
        m_brkPageAddress = align(addr, false); 
    }

    MemoryMap &getMemoryMap() {
        return m_memoryMap;
    }

    void setMemoryMap(const MemoryMap& memoryMap) {
        m_memoryMap = memoryMap;
    }

    StoreMap &getStoreMap() {
        return m_storeMap;
    }

    void setStoreMap(const StoreMap& storeMap) {
        m_storeMap = storeMap;
    }
};

void MemoryBugChecker::initialize()
{
    ConfigFile *cfg = s2e()->getConfig();

    m_debugLevel = cfg->getInt(getConfigKey() + ".debugLevel", 0);

    m_checkBugs = cfg->getBool(getConfigKey() + ".checkMemoryBugs", true);
    m_checkNullPtrDerefBug = cfg->getBool(getConfigKey() + ".checkNullPtrDereferenceBug", false);
    m_checkRetPtrOverrideBug = cfg->getBool(getConfigKey() + ".checkReturnPtrOverrideBug", false);
    m_checkOOBAccessBug =  cfg->getBool(getConfigKey() + ".checkOOBAccessBug", false);

    m_terminateOnBugs = cfg->getBool(getConfigKey() + ".terminateOnBugs", true);

    m_traceMemoryAccesses = cfg->getBool(getConfigKey() + ".traceMemoryAccesses", false);

    m_stackMonitor = s2e()->getPlugin<StackMonitor>();

    m_pm = s2e()->getPlugin<ProcessMonitor>();
    assert(m_pm);

    s2e()->getCorePlugin()->onBeforeSymbolicDataMemoryAccess.connect(
            sigc::mem_fun(*this, &MemoryBugChecker::onBeforeSymbolicDataMemoryAccess));

    s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(
            sigc::mem_fun(*this, &MemoryBugChecker::onConcreteDataMemoryAccess));

    s2e()->getCorePlugin()->onAlwaysConcreteMemoryAccess.connect(
            sigc::mem_fun(*this, &MemoryBugChecker::onAlwaysConcreteMemoryAccess));
}

void MemoryBugChecker::printImageInfo(S2EExecutionState *state, ImageInfo *info) 
{
    getDebugStream(state) << "\n"
            << "[Binary]\n"
            << "load_bias: " << hexval(info->load_bias) 
            << " load_addr: " << hexval(info->load_addr) << "\n"
            << "start_code: " << hexval(info->start_code) 
            << " end_code: " << hexval(info->end_code) << "\n"
            << "start_data: " << hexval(info->start_data) 
            << " end_data: " << hexval(info->end_data) << "\n"
            << "start_brk: " << hexval(info->start_brk) 
            << " brk: " << hexval(info->brk) << "\n"
            << "start_mmap: " << hexval(info->start_mmap) 
            << " mmap: " << hexval(info->mmap) << "\n"
            << "rss: " << hexval(info->rss) << "\n"
            << "start_stack: " << hexval(info->start_stack) 
            << " stack_limit: " << hexval(info->stack_limit) << "\n"
            << "entry: " << hexval(info->entry) << "\n"
            << "code_offset: " << hexval(info->code_offset) << "\n"
            << "data_offset: " << hexval(info->data_offset) << "\n"
            << "saved_auxv: " << hexval(info->saved_auxv) 
            << " auxv_len: " << hexval(info->auxv_len) << "\n"
            << "arg_start: " << hexval(info->arg_start) 
            << " arg_end: " << hexval(info->arg_end) << "\n"
            << "elf_flags: " << hexval(info->elf_flags) << "\n\n";

    if (info->interp_info) {
        ImageInfo* interp_info = info->interp_info;
        getDebugStream(state) << "\n"
                << "[ELF interpreter]\n"
                << "load_bias: " << hexval(interp_info->load_bias) 
                << " load_addr: " << hexval(interp_info->load_addr) << "\n"
                << "start_code: " << hexval(interp_info->start_code) 
                << " end_code: " << hexval(interp_info->end_code) << "\n"
                << "start_data: " << hexval(interp_info->start_data) 
                << " end_data: " << hexval(interp_info->end_data) << "\n"
                << "start_brk: " << hexval(interp_info->start_brk) 
                << " brk: " << hexval(interp_info->brk) << "\n"
                << "start_mmap: " << hexval(interp_info->start_mmap) 
                << " mmap: " << hexval(interp_info->mmap) << "\n"
                << "rss: " << hexval(interp_info->rss) << "\n"
                << "start_stack: " << hexval(interp_info->start_stack) 
                << " stack_limit: " << hexval(interp_info->stack_limit) << "\n"
                << "entry: " << hexval(interp_info->entry) << "\n"
                << "code_offset: " << hexval(interp_info->code_offset) << "\n"
                << "data_offset: " << hexval(interp_info->data_offset) << "\n"
                << "saved_auxv: " << hexval(interp_info->saved_auxv) 
                << " auxv_len: " << hexval(interp_info->auxv_len) << "\n"
                << "arg_start: " << hexval(interp_info->arg_start) 
                << " arg_end: " << hexval(interp_info->arg_end) << "\n"
                << "elf_flags: " << hexval(interp_info->elf_flags) << "\n\n";
    }
}

void MemoryBugChecker::emitOnBugDetected(S2EExecutionState *state, uint32_t bug, uint64_t pc)
{
    if (pc == 0)
        pc = state->regs()->getPc();
    std::string file = m_pm->getFileName(pc);
    uint32_t offset = m_pm->getOffsetWithinFile(file, pc);

    uint32_t insn;
    if (!state->mem()->read<uint32_t>(pc, &insn, VirtualAddress, false)) {
        getWarningsStream(state) << "cannot get instruction at " << hexval(pc);
        insn = 0xffffffff;
    }

    onBugDetected.emit(state, bug, offset, insn, file, m_bugInputs);
}

void MemoryBugChecker::printConcreteInputs(llvm::raw_ostream &os, const ConcreteInputs &inputs) {
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
bool MemoryBugChecker::checkRange(S2EExecutionState *state, klee::ref<klee::Expr> expr)
{
    std::pair<klee::ref<klee::Expr>, klee::ref<klee::Expr>> range;
    klee::Query query(state->constraints, expr);

    range = s2e()->getExecutor()->getSolver(*state)->getRange(query);

    uint64_t min = dyn_cast<klee::ConstantExpr>(range.first)->getZExtValue();
    uint64_t max = dyn_cast<klee::ConstantExpr>(range.second)->getZExtValue();

    getWarningsStream(state) << "checkRange min = " << hexval(min) << " max = " << hexval(max) << "fd = " << state->regs()->read<uint32_t>(CPU_OFFSET(regs[0])) <<"\n";

    return (min != max);
}

bool MemoryBugChecker::assume(S2EExecutionState *state, klee::ref<klee::Expr> expr)
{
    getDebugStream(state) << "Thread = " << hexval((unsigned long)pthread_self()) << " assume: " << expr << "\n";
    klee::ref<klee::Expr> zero = klee::ConstantExpr::create(0, expr.get()->getWidth());
    klee::ref<klee::Expr> boolexpr = klee::NeExpr::create(expr, zero);

    // check if expr may be true under current path constraints
    bool isValid = true;
    bool truth;
    klee::Solver *solver = s2e()->getExecutor()->getSolver(*state);
    klee::Query query(state->constraints, boolexpr);
    bool res = solver->mustBeTrue(query.negateExpr(), truth);
    if (!res || truth) {
        isValid = false;
    }

    if (!isValid) {
        std::stringstream ss;
        ss << "MemoryBugChecker: specified constraint cannot be satisfied "
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
//            inputs.push_back(
            m_bugInputs.push_back(
                    std::make_pair(state->symbolics[i].first->name, values[i]));
        }

        printConcreteInputs(getWarningsStream(state), m_bugInputs);
    }

    return isValid;
}

bool MemoryBugChecker::checkNullPtrDeref(S2EExecutionState *state, klee::ref<klee::Expr> addr) 
{
    klee::ref<klee::Expr> nullValue = E_CONST(0, state->getPointerWidth()); 
    klee::ref<klee::Expr> nullAddressRead = 
            klee::EqExpr::create(nullValue, addr);
    return assume(state, nullAddressRead);
}

bool MemoryBugChecker::checkAddressRange(S2EExecutionState *state, klee::ref<klee::Expr> addr,
                                         uint64_t lower, uint64_t upper)
{
    klee::ref<klee::Expr> lowerValue = E_CONST(lower, state->getPointerWidth());
    klee::ref<klee::Expr> upperValue = E_CONST(upper, state->getPointerWidth());
    klee::ref<klee::Expr> rangeConstraint =
            klee::AndExpr::create(klee::UgeExpr::create(addr, lowerValue),
                                  klee::UleExpr::create(addr, upperValue));

    bool ret = assume(state, rangeConstraint);
    getDebugStream(state) << "check if addr: " << addr << " can fall in the range("
            << hexval(lower) << "," << hexval(upper) << "):" << ret << "\n";
    return ret;
}

bool MemoryBugChecker::checkRetPtrOverride(S2EExecutionState *state, klee::ref<klee::Expr> addr) 
{
    bool isSeedState = false;
    bool hasBug = false;
//    if (m_seedSearcher) {
//        isSeedState = m_seedSearcher->isSeedState(state);
//    }

    /*
     * For every EIP stored on the stack, fork a state that will overwrite it.
     */

    StackMonitor::CallStack cs;
    if (!m_stackMonitor->getCallStack(state, 1, pthread_self(), cs)) {
        getWarningsStream(state) << "Failed to get call stack\n";
        return false;
    }

    std::vector<klee::ref<klee::Expr>> retAddrLocations;
    for (unsigned i = 1; i < cs.size(); i++) { // always skip first dummy frame
        retAddrLocations.push_back(E_CONST(cs[i].FrameTop, state->getPointerWidth()));
    }

    bool forkState = false;
    if (forkState) {
        std::vector<klee::ExecutionState *> states = 
                s2e()->getExecutor()->forkValues(state, isSeedState, addr, retAddrLocations);
        assert(states.size() == retAddrLocations.size());

        for (unsigned i = 0; i < states.size(); i++) {
            S2EExecutionState *valuableState = static_cast<S2EExecutionState *>(states[i]);
/*  
            if (valuableState) {
                // We've forked a state where symbolic address will be concretized to one exact value.
                // Put the state into separate CUPA group to distinguish it from other states that were
                // produced by fork and concretise at the same PC.
                m_keyValueStore->setProperty(valuableState, "group", CUPA_GROUP_SYMBOLIC_ADDRESS);
            }
*/
            std::ostringstream os;
            os << "Stack frame " << i << " retAddr @ " << retAddrLocations[i];
            if (valuableState) {
                os << " overriden in state " << valuableState->getID();
                getWarningsStream(state) << os.str() << "\n";
                hasBug = true;
            } else {
                os << " can not be overriden";
                getDebugStream(state) << os.str() << "\n";
            }
        }
    } else {
        for (unsigned i = 0; i < retAddrLocations.size(); i++) {
            std::ostringstream os;
            os << "Stack frame " << i << " retAddr @ " << retAddrLocations[i];
            klee::ref<klee::Expr> retAddrLocationWrite = 
                    klee::EqExpr::create(retAddrLocations.at(i), addr);
            if (assume(state, retAddrLocationWrite)) {
                os << " could be overridden";
                getWarningsStream(state) << os.str() << "\n";
                hasBug = true;
            } else {
            }
        }
    }
    return hasBug;
}
/*
bool MemoryBugChecker::checkSymbolicUnallocatedHeapAccess(S2EExecutionState *state,
                                                          klee::ref<klee::Expr> addr)
{
    m_pm->updateProcessAddressMap("[anon:libc_malloc]", 0xffffffff);

    bool notAllocated = true;
    if (isAddressWithinFile(addr, "[anon:libc_malloc]")) {
        for (auto region : m_libcMallocRegions) {
            if (addr >= region.first && addr + size < region.second) {
                notAllocated = false;
                break;
            }
        }
    }

    if (notAllocated) {
        err << "MemoryBugChecker::checkMemoryAccess: "
                << "BUG: memory range at " << hexval(addr) << " of size " << hexval(size)
                << " can not be accessed by instruction " << getPrettyCodeLocation(state)
                << ": using not allocated region in heap" << '\n';
        emitOnBugDetected(state, BUG_C_LIBC_UNALLOCHEAP);
    }
    return notAllocated;
}*/

bool MemoryBugChecker::checkSymbolicMemoryAccess(S2EExecutionState *state,
                                                 klee::ref<klee::Expr> start, 
                                                 klee::ref<klee::Expr> value,
                                                 bool isWrite,
                                                 llvm::raw_ostream &err)
{
    DECLARE_PLUGINSTATE(MemoryBugCheckerState, state);
    if (!m_checkBugs)
        return true;

    bool hasBug = false;

    if (checkRange(state, start)) {
        emitOnBugDetected(state, BUG_S_MEMACCESS);
        getWarningsStream(state) << "Symbolic memory access\n"
                << "    Instruction: " << getPrettyCodeLocation(state) << "\n"
                << "    Address: " << start << "\n";
       m_stackMonitor->printCallStack(state);
    }

    if (m_checkNullPtrDerefBug) {
        hasBug = checkNullPtrDeref(state, start);
        if (hasBug) {
            err << "BUG: potential null pointer dereference\n"
                << "    Instruction: " << getPrettyCodeLocation(state) << "\n"
                << "    Address: " << start << "\n";
            emitOnBugDetected(state, BUG_S_R_NULLPTR);
        }
    }

    if (isWrite) {
        if (m_checkRetPtrOverrideBug) {
            hasBug = checkRetPtrOverride(state, start);
            if (hasBug) {
                err << "BUG: potential return pointer override\n"
                    << "    Instruction: " << getPrettyCodeLocation(state) << "\n"
                    << "    Address: "<< start << "\n";
                emitOnBugDetected(state, BUG_S_W_RETPTR);
            }
        }
        if (m_checkOOBAccessBug) {
            StackMonitor::CallStack cs;
            if (m_stackMonitor->getCallStack(state, 1, pthread_self(), cs)) {
                ImageInfo* info = &m_binaryInfo;
                if (checkAddressRange(state, start, cs.back().FrameTop, info->start_stack)
                    && checkAddressRange(state, start, info->start_code, plgState->getBRKAddress())) {
                    err << "BUG: suspicious memory access (could access to both heap and stack)\n" 
                        << "    Instruction: " << getPrettyCodeLocation(state) << "\n"
                        << "    Address: "<< start << "\n";
                    hasBug = true;
                    emitOnBugDetected(state, BUG_S_W_STACKANDHEAP);
                }
            }
        }
        if (m_checkOOBAccessBug) {
            ImageInfo* info = &m_binaryInfo;
            if (checkAddressRange(state, start, info->start_code, info->end_code)) {
                err << "BUG: potential write to code section\n"
                    << "    Instruction: " << getPrettyCodeLocation(state) << "\n"
                    << "    Address: "<< start << "\n";
                hasBug = true;
                emitOnBugDetected(state, BUG_S_W_CODE);
            }
        }

    }

    return !hasBug;
}

void MemoryBugChecker::onBeforeSymbolicDataMemoryAccess(S2EExecutionState* state,
                                                        klee::ref<klee::Expr> virtualAddress,
                                                        klee::ref<klee::Expr> value,
                                                        bool isWrite)
{
    std::string errstr;
    llvm::raw_string_ostream err(errstr);
    bool result = checkSymbolicMemoryAccess(state, virtualAddress, value, isWrite, err);

    if (!result) {
        if (m_terminateOnBugs) {
            s2e()->getExecutor()->terminateStateEarly(*state, err.str());
        }
        else {
            s2e()->getWarningsStream(state) << err.str();
            m_stackMonitor->printCallStack(state);
        }
    }
}

bool MemoryBugChecker::checkConcreteOOBAccess(S2EExecutionState *state, uint64_t addr, int size,
                                              bool isWrite, llvm::raw_ostream &err)
{
 //   DECLARE_PLUGINSTATE(MemoryBugCheckerState, state);
//    StoreMap &storeMap = plgState->getStoreMap();

    if (!m_checkRetPtrOverrideBug)
        return false;

    bool hasError = false;

    if (isWrite) {
        StackMonitor::CallStack cs;
        if (!m_stackMonitor->getCallStack(state, 1, pthread_self(), cs)) {
            getWarningsStream(state) << "Failed to get call stack\n";
            return false;
        }

        bool stack = (addr <= m_binaryInfo.start_stack && addr > m_binaryInfo.stack_limit);
        uint64_t framePc = 0;
        uint64_t pc = state->regs()->getPc();
        int wordSize = state->getPointerWidth() / 8;

        //getDebugStream(state) <<'\n';
        if (stack) {
            for (unsigned i = 1; i < cs.size(); i++) { // always skip first dummy frame
                //getDebugStream(state) << " waddr: "<< hexval(addr) 
                //        << " frameTop: " << hexval(cs[i].FrameTop) << '\n';
                if ((addr < cs[i].FrameTop && addr >= cs[i].FrameTop + wordSize) ||
                    (addr + wordSize < cs[i].FrameTop && addr + wordSize >= cs[i].FrameTop + wordSize)) {
                    err << "MemoryBugChecker::checkMemoryAccess: "
                            << "BUG: memory range at " << hexval(addr) << " of size " << hexval(size)
                            << " can not be accessed by instruction " << getPrettyCodeLocation(state)
                            << ": the return pointer at " << hexval(cs[i].FrameTop)
                            << " should not be overriden" << "\n";
                    hasError = true;
                    emitOnBugDetected(state, BUG_C_W_RETPTR, pc);
                    break;
                }

                if (addr >= cs[i].FrameTop) {
                    framePc = cs[i].FramePc;
                }
            }
        }

//        //Check the access pattern
//        StoreAttribute *attr = new StoreAttribute();
//        attr->stack = stack;
//        attr->local = (framePc == cs.back().FramePc);
//        attr->framePC = framePc;
//
//        auto it = storeMap.find(pc);
//        if (it != storeMap.end()) {
//            storeMap.insert(std::pair<uint64_t, StoreAttribute>(pc, *attr));
//        } else {
//            if (it->second.stack != attr->stack ||
//                (attr->stack == true && it->second.local != attr->local)) {
//                err << "MemoryBugChecker::checkMemoryAccess: "
//                        << "BUG: memory range at " << hexval(addr) << " of size " << hexval(size)
//                        << " accessed by instruction " << getPrettyCodeLocation(state)
//                        << " : Access pattern mismatch. This could be an out-of-bound access. " << "\n";
//                hasError = true;
//                emitOnBugDetected(state, BUG_C_W_STACKANDHEAP, pc);
//            }
//        }
    }

    return hasError;
}
/*
bool MemoryBugChecker::checkUnallocatedHeapAccess(S2EExecutionState *state, uint64_t addr,
                                                  int size, llvm::raw_ostream &err)
{
    if (m_pm->isAddressUnknown(addr))
        m_pm->updateProcessAddressMap("[anon:libc_malloc]", addr + size);

    bool notAllocated = true;
    if (m_pm->isAddressWithinFile(addr, "[anon:libc_malloc]")) {
        for (auto region : m_libcMallocRegions) {
            if (addr >= region.first && addr + size < region.second) {
                notAllocated = false;
                break;
            }
        }
    }

    if (notAllocated) {
        err << "MemoryBugChecker::checkMemoryAccess: "
                << "BUG: memory range at " << hexval(addr) << " of size " << hexval(size)
                << " can not be accessed by instruction " << getPrettyCodeLocation(state)
                << ": using not allocated region in heap" << '\n';
        emitOnBugDetected(state, BUG_C_LIBC_UNALLOCHEAP);
    }
    return notAllocated;
}*/

bool MemoryBugChecker::checkMemoryAccess(S2EExecutionState *state,
                                         uint64_t start, uint64_t size, uint8_t perms,
                                         llvm::raw_ostream &err)
{
    if (!m_checkBugs)
        return true;

    bool hasError = false;

    //FIXME: should move the checking for concrete null pointer dereference to a handler 
    //connected to a signal emitted before concrete memory access. Otherwise, null 
    //pointer dereference will trigger qemu bad ram pointer error before the checking.
    if (m_checkNullPtrDerefBug && (start == 0)) {
        err << "MemoryBugChecker::checkMemoryAccess: "
                << "BUG: memory range at " << hexval(start) << " of size " << hexval(size)
                << " can not be accessed by instruction " << getPrettyCodeLocation(state)
                << ": reading memory @ 0x0, could be null pointer dereference" << '\n';
        hasError = true;
    }

    hasError |= checkConcreteOOBAccess(state, start, size, perms & WRITE, err);

//    hasError |= checkUnallocatedHeapAccess(state, start, size, err);

    return !hasError;
}

void MemoryBugChecker::onAlwaysConcreteMemoryAccess(S2EExecutionState *state,
                                                    klee::ref<klee::Expr> value,
                                                    bool isWrite)
{
    if (isWrite)
        getWarningsStream(state) << "write pc\n";
    else
        getWarningsStream(state) << "read pc\n";
}

void MemoryBugChecker::onConcreteDataMemoryAccess(S2EExecutionState *state,
                                                  uint64_t virtualAddress,
                                                  uint64_t value,
                                                  uint8_t size,
                                                  unsigned flags)
{
    bool isWrite = flags & MEM_TRACE_FLAG_WRITE;

    onPreCheck.emit(state, virtualAddress, size, isWrite);

    std::string errstr;
    llvm::raw_string_ostream err(errstr);
    bool result = checkMemoryAccess(state, virtualAddress, size, isWrite ? WRITE : READ, err);

    if (!result) {
        onPostCheck.emit(state, virtualAddress, size, isWrite, &result);
        if (result) {
            return;
        }

        if (m_terminateOnBugs)
            s2e()->getExecutor()->terminateStateEarly(*state, err.str());
        else
            s2e()->getWarningsStream(state) << err.str();
    }
}

std::string MemoryBugChecker::getPrettyCodeLocation(S2EExecutionState *state)
{
    std::stringstream ss;
    uint64_t pc = state->regs()->getPc();
    uint32_t insn;
    std::string binary = m_pm->getFileName(pc);
    if (!state->mem()->read<uint32_t>(pc, &insn, VirtualAddress, false)) {
        getWarningsStream(state) << "cannot get instruction at " << hexval(pc);
    }
    ss << hexval(insn) << " @" << hexval(pc) << " " << binary;
    return ss.str();
}

} // namespace plugins
} // namespace s2e
